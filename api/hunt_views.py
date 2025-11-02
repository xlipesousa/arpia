from __future__ import annotations

from time import perf_counter

from django.conf import settings
from django.db.models import Count, Q
from rest_framework import permissions, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import NotFound
from rest_framework.response import Response

from arpia_hunt.log_events import emit_hunt_log
from arpia_hunt.models import (
    AttackTechnique,
    CveAttackTechnique,
    HuntFinding,
    HuntRecommendation,
)
from arpia_hunt.serializers import (
    AttackTechniqueSerializer,
    HuntFindingProfileSerializer,
    HuntFindingSerializer,
    HuntRecommendationDetailSerializer,
    HuntRecommendationSerializer,
)

from .pagination import (
    HuntFindingPagination,
    HuntRecommendationPagination,
    HuntTechniquePagination,
)


def base_hunt_finding_queryset():
    return (
        HuntFinding.objects.select_related("project", "vulnerability")
        .prefetch_related(
            "enrichments",
            "recommendations__technique",
            "recommendations__technique__tactic",
        )
        .annotate(
            recommendation_total=Count("recommendations", distinct=True),
            recommendation_blue=Count(
                "recommendations",
                filter=Q(recommendations__recommendation_type=HuntRecommendation.Type.BLUE),
                distinct=True,
            ),
            recommendation_red=Count(
                "recommendations",
                filter=Q(recommendations__recommendation_type=HuntRecommendation.Type.RED),
                distinct=True,
            ),
        )
    )


def apply_hunt_finding_filters(
    queryset,
    *,
    project_ids: list[str] | None = None,
    technique_ids: list[str] | None = None,
    confidences: list[str] | None = None,
    recommendation_types: list[str] | None = None,
    search: str | None = None,
):
    if project_ids:
        if len(project_ids) == 1:
            queryset = queryset.filter(project_id=project_ids[0])
        else:
            queryset = queryset.filter(project_id__in=project_ids)

    if technique_ids:
        if len(technique_ids) == 1:
            queryset = queryset.filter(recommendations__technique_id=technique_ids[0])
        else:
            queryset = queryset.filter(recommendations__technique_id__in=technique_ids)

    if confidences:
        if len(confidences) == 1:
            queryset = queryset.filter(recommendations__confidence=confidences[0])
        else:
            queryset = queryset.filter(recommendations__confidence__in=confidences)

    if recommendation_types:
        if len(recommendation_types) == 1:
            queryset = queryset.filter(recommendations__recommendation_type=recommendation_types[0])
        else:
            queryset = queryset.filter(recommendations__recommendation_type__in=recommendation_types)

    if search:
        queryset = queryset.filter(
            Q(vulnerability__title__icontains=search)
            | Q(summary__icontains=search)
            | Q(cve__icontains=search)
        )

    return queryset


def finalize_hunt_finding_queryset(queryset):
    return queryset.order_by("-last_profiled_at", "-detected_at", "-created_at").distinct()


def base_hunt_recommendation_queryset():
    return HuntRecommendation.objects.select_related(
        "finding",
        "finding__project",
        "technique",
        "technique__tactic",
    )


def apply_hunt_recommendation_filters(
    queryset,
    *,
    project_ids: list[str] | None = None,
    technique_ids: list[str] | None = None,
    confidences: list[str] | None = None,
    recommendation_types: list[str] | None = None,
    generators: list[str] | None = None,
    finding_ids: list[str] | None = None,
    search: str | None = None,
):
    if project_ids:
        if len(project_ids) == 1:
            queryset = queryset.filter(finding__project_id=project_ids[0])
        else:
            queryset = queryset.filter(finding__project_id__in=project_ids)

    if technique_ids:
        if len(technique_ids) == 1:
            queryset = queryset.filter(technique_id=technique_ids[0])
        else:
            queryset = queryset.filter(technique_id__in=technique_ids)

    if confidences:
        if len(confidences) == 1:
            queryset = queryset.filter(confidence=confidences[0])
        else:
            queryset = queryset.filter(confidence__in=confidences)

    if recommendation_types:
        if len(recommendation_types) == 1:
            queryset = queryset.filter(recommendation_type=recommendation_types[0])
        else:
            queryset = queryset.filter(recommendation_type__in=recommendation_types)

    if generators:
        if len(generators) == 1:
            queryset = queryset.filter(generated_by=generators[0])
        else:
            queryset = queryset.filter(generated_by__in=generators)

    if finding_ids:
        if len(finding_ids) == 1:
            queryset = queryset.filter(finding_id=finding_ids[0])
        else:
            queryset = queryset.filter(finding_id__in=finding_ids)

    if search:
        queryset = queryset.filter(Q(title__icontains=search) | Q(summary__icontains=search))

    return queryset


def finalize_hunt_recommendation_queryset(queryset):
    return queryset.order_by("-updated_at", "-created_at")


class HuntBetaFeatureMixin:
    feature_flag_name = "ARPIA_HUNT_API_BETA"

    def initial(self, request, *args, **kwargs):  # type: ignore[override]
        if not getattr(settings, self.feature_flag_name, False):
            raise NotFound("API Hunt (beta) desabilitada.")
        self._hunt_api_started_at = perf_counter()
        return super().initial(request, *args, **kwargs)

    @staticmethod
    def _split_query_values(raw_value: str | None) -> list[str]:
        if not raw_value:
            return []
        return [part.strip() for part in raw_value.split(",") if part.strip()]

    def finalize_response(self, request, response, *args, **kwargs):  # type: ignore[override]
        response = super().finalize_response(request, response, *args, **kwargs)
        if getattr(settings, self.feature_flag_name, False) and hasattr(self, "_hunt_api_started_at"):
            duration_ms = int((perf_counter() - getattr(self, "_hunt_api_started_at", perf_counter())) * 1000)
            try:
                emit_hunt_log(
                    event_type="hunt.api.access",
                    message=f"{request.method} {request.path}",
                    component="hunt.api",
                    details={
                        "duration_ms": duration_ms,
                        "method": request.method,
                        "path": request.path,
                        "status_code": response.status_code,
                        "viewset": self.__class__.__name__,
                        "action": getattr(self, "action", None),
                    },
                    tags=[
                        "metric:hunt.api.latency",
                        f"status:{response.status_code}",
                        f"method:{request.method.lower()}",
                    ],
                )
            except Exception:
                # Evita que falhas de logging impeçam a resposta normal
                pass
        return response


class HuntFindingViewSet(HuntBetaFeatureMixin, viewsets.ReadOnlyModelViewSet):
    serializer_class = HuntFindingSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = HuntFindingPagination

    def get_queryset(self):  # type: ignore[override]
        queryset = base_hunt_finding_queryset()
        project_ids = self._split_query_values(self.request.query_params.get("project"))
        technique_ids = self._split_query_values(self.request.query_params.get("technique"))
        confidences = self._split_query_values(self.request.query_params.get("confidence"))
        recommendation_types = self._split_query_values(self.request.query_params.get("type"))
        search = self.request.query_params.get("search")

        queryset = apply_hunt_finding_filters(
            queryset,
            project_ids=project_ids,
            technique_ids=technique_ids,
            confidences=confidences,
            recommendation_types=recommendation_types,
            search=search,
        )
        return finalize_hunt_finding_queryset(queryset)

    def get_serializer_context(self):  # type: ignore[override]
        context = super().get_serializer_context()
        context.setdefault("heuristic_cache", {})
        return context

    @action(detail=True, methods=["get"], url_path="profiles")
    def profiles(self, request, *args, **kwargs):
        finding = self.get_object()
        heuristics = list(
            CveAttackTechnique.objects.filter(cve=finding.cve)
            .select_related("technique", "technique__tactic")
            .order_by("-updated_at")
        )
        recommendations = list(
            finding.recommendations.select_related("technique", "technique__tactic", "finding", "finding__project")
            .order_by("-updated_at")
        )
        serializer = HuntFindingProfileSerializer(
            {
                "finding": finding,
                "blue_profile": finding.blue_profile or {},
                "red_profile": finding.red_profile or {},
                "applied_heuristics": heuristics,
                "recommendations": recommendations,
            },
            context=self.get_serializer_context(),
        )
        return Response(serializer.data)


class HuntRecommendationViewSet(HuntBetaFeatureMixin, viewsets.ReadOnlyModelViewSet):
    serializer_class = HuntRecommendationSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = HuntRecommendationPagination

    def get_queryset(self):  # type: ignore[override]
        queryset = base_hunt_recommendation_queryset()
        project_ids = self._split_query_values(self.request.query_params.get("project"))
        technique_ids = self._split_query_values(self.request.query_params.get("technique"))
        confidences = self._split_query_values(self.request.query_params.get("confidence"))
        recommendation_types = self._split_query_values(self.request.query_params.get("type"))
        generators = self._split_query_values(self.request.query_params.get("generated_by"))
        finding_ids = self._split_query_values(self.request.query_params.get("finding"))
        search = self.request.query_params.get("search")

        queryset = apply_hunt_recommendation_filters(
            queryset,
            project_ids=project_ids,
            technique_ids=technique_ids,
            confidences=confidences,
            recommendation_types=recommendation_types,
            generators=generators,
            finding_ids=finding_ids,
            search=search,
        )
        return finalize_hunt_recommendation_queryset(queryset)

    def get_serializer_context(self):  # type: ignore[override]
        context = super().get_serializer_context()
        context.setdefault("heuristic_cache", {})
        return context

    def get_serializer_class(self):  # type: ignore[override]
        if getattr(self, "action", None) == "retrieve":
            return HuntRecommendationDetailSerializer
        return super().get_serializer_class()


class AttackTechniqueViewSet(HuntBetaFeatureMixin, viewsets.ReadOnlyModelViewSet):
    serializer_class = AttackTechniqueSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = HuntTechniquePagination
    queryset = AttackTechnique.objects.select_related("tactic")

    def get_queryset(self):  # type: ignore[override]
        queryset = super().get_queryset()

        matrix = self.request.query_params.get("matrix")
        if matrix:
            queryset = queryset.filter(tactic__matrix=matrix)

        tactic_id = self.request.query_params.get("tactic")
        if tactic_id:
            queryset = queryset.filter(tactic_id=tactic_id)

        search = self.request.query_params.get("search")
        if search:
            queryset = queryset.filter(
                Q(name__icontains=search)
                | Q(description__icontains=search)
                | Q(id__icontains=search)
            )
        return queryset.order_by("id")
