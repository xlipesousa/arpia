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
    HuntRecommendationSerializer,
)

from .pagination import (
    HuntFindingPagination,
    HuntRecommendationPagination,
    HuntTechniquePagination,
)


class HuntBetaFeatureMixin:
    feature_flag_name = "ARPIA_HUNT_API_BETA"

    def initial(self, request, *args, **kwargs):  # type: ignore[override]
        if not getattr(settings, self.feature_flag_name, False):
            raise NotFound("API Hunt (beta) desabilitada.")
        self._hunt_api_started_at = perf_counter()
        return super().initial(request, *args, **kwargs)

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
        queryset = (
            HuntFinding.objects.select_related("project", "vulnerability")
            .prefetch_related("enrichments", "recommendations__technique", "recommendations__technique__tactic")
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

        project_id = self.request.query_params.get("project")
        if project_id:
            queryset = queryset.filter(project_id=project_id)

        technique_id = self.request.query_params.get("technique")
        if technique_id:
            queryset = queryset.filter(recommendations__technique_id=technique_id)

        confidence = self.request.query_params.get("confidence")
        if confidence:
            queryset = queryset.filter(recommendations__confidence=confidence)

        recommendation_type = self.request.query_params.get("type")
        if recommendation_type:
            queryset = queryset.filter(recommendations__recommendation_type=recommendation_type)

        search = self.request.query_params.get("search")
        if search:
            queryset = queryset.filter(
                Q(vulnerability__title__icontains=search)
                | Q(summary__icontains=search)
                | Q(cve__icontains=search)
            )

        return queryset.order_by("-last_profiled_at", "-detected_at", "-created_at").distinct()

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
        queryset = HuntRecommendation.objects.select_related(
            "finding",
            "finding__project",
            "technique",
            "technique__tactic",
        )

        project_id = self.request.query_params.get("project")
        if project_id:
            queryset = queryset.filter(finding__project_id=project_id)

        technique_id = self.request.query_params.get("technique")
        if technique_id:
            queryset = queryset.filter(technique_id=technique_id)

        confidence = self.request.query_params.get("confidence")
        if confidence:
            queryset = queryset.filter(confidence=confidence)

        recommendation_type = self.request.query_params.get("type")
        if recommendation_type:
            queryset = queryset.filter(recommendation_type=recommendation_type)

        generator = self.request.query_params.get("generated_by")
        if generator:
            queryset = queryset.filter(generated_by=generator)

        search = self.request.query_params.get("search")
        if search:
            queryset = queryset.filter(Q(title__icontains=search) | Q(summary__icontains=search))

        return queryset.order_by("-updated_at", "-created_at")


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