from __future__ import annotations

from typing import Any

import graphene
from graphene.types.generic import GenericScalar

from arpia_hunt.serializers import HuntFindingSerializer, HuntRecommendationDetailSerializer

from .hunt_views import (
    apply_hunt_finding_filters,
    apply_hunt_recommendation_filters,
    base_hunt_finding_queryset,
    base_hunt_recommendation_queryset,
    finalize_hunt_finding_queryset,
    finalize_hunt_recommendation_queryset,
)


DEFAULT_LIMIT = 50
MAX_LIMIT = 500


def _ensure_cache(request) -> dict[str, Any]:
    cache = getattr(request, "_hunt_graphql_cache", None)
    if cache is None:
        cache = {"heuristic_cache": {}}
        setattr(request, "_hunt_graphql_cache", cache)
    return cache


class RecommendationCountsType(graphene.ObjectType):
    total = graphene.Int()
    blue = graphene.Int()
    red = graphene.Int()

    def resolve_total(parent, info):  # noqa: D401
        return parent.get("total", 0)

    def resolve_blue(parent, info):
        return parent.get("blue", 0)

    def resolve_red(parent, info):
        return parent.get("red", 0)


class TechniqueType(graphene.ObjectType):
    id = graphene.String()
    name = graphene.String()
    description = graphene.String()
    is_subtechnique = graphene.Boolean()
    parent_id = graphene.String()
    tactic_id = graphene.String()
    tactic_name = graphene.String()
    matrix = graphene.String()
    platforms = graphene.List(graphene.String)
    datasources = graphene.List(graphene.String)
    external_references = graphene.List(GenericScalar)
    version = graphene.String()
    updated_at = graphene.String()

    def resolve_platforms(parent, info):
        return parent.get("platforms") or []

    def resolve_datasources(parent, info):
        return parent.get("datasources") or []

    def resolve_external_references(parent, info):
        return parent.get("external_references") or []


class HeuristicType(graphene.ObjectType):
    id = graphene.UUID()
    cve = graphene.String()
    technique_id = graphene.String()
    technique = graphene.Field(TechniqueType)
    source = graphene.String()
    confidence = graphene.String()
    rationale = graphene.String()
    updated_at = graphene.String()

    def resolve_technique(parent, info):
        return parent.get("technique") or {}


class RecommendationFindingType(graphene.ObjectType):
    id = graphene.UUID()
    project_id = graphene.UUID()
    project_name = graphene.String()
    project_slug = graphene.String()
    vulnerability_id = graphene.UUID()
    cve = graphene.String()
    severity = graphene.String()
    summary = graphene.String()
    blue_profile = GenericScalar()
    red_profile = GenericScalar()
    profile_version = graphene.Int()

    def resolve_blue_profile(parent, info):
        return parent.get("blue_profile") or {}

    def resolve_red_profile(parent, info):
        return parent.get("red_profile") or {}


class HuntFindingType(graphene.ObjectType):
    id = graphene.UUID()
    project_id = graphene.UUID()
    project_name = graphene.String()
    project_slug = graphene.String()
    vulnerability_id = graphene.UUID()
    vulnerability_title = graphene.String()
    cve = graphene.String()
    severity = graphene.String()
    cvss_score = graphene.Float()
    cvss_vector = graphene.String()
    summary = graphene.String()
    blue_profile = GenericScalar()
    red_profile = GenericScalar()
    profile_version = graphene.Int()
    last_profiled_at = graphene.String()
    recommendation_counts = graphene.Field(RecommendationCountsType)
    applied_heuristics = graphene.List(HeuristicType)

    def resolve_project_id(parent, info):
        return parent.get("project")

    def resolve_vulnerability_id(parent, info):
        return parent.get("vulnerability")

    def resolve_blue_profile(parent, info):
        return parent.get("blue_profile") or {}

    def resolve_red_profile(parent, info):
        return parent.get("red_profile") or {}

    def resolve_recommendation_counts(parent, info):
        return parent.get("recommendation_counts") or {}

    def resolve_applied_heuristics(parent, info):
        return parent.get("applied_heuristics") or []


class HuntRecommendationType(graphene.ObjectType):
    id = graphene.UUID()
    finding_id = graphene.UUID()
    project_id = graphene.UUID()
    project_name = graphene.String()
    project_slug = graphene.String()
    technique_id = graphene.String()
    technique = graphene.Field(TechniqueType)
    recommendation_type = graphene.String()
    title = graphene.String()
    summary = graphene.String()
    confidence = graphene.String()
    confidence_note = graphene.String()
    evidence = GenericScalar()
    tags = graphene.List(graphene.String)
    generated_by = graphene.String()
    playbook_slug = graphene.String()
    source_enrichment_id = graphene.UUID()
    created_at = graphene.String()
    updated_at = graphene.String()
    finding = graphene.Field(RecommendationFindingType)
    heuristics = graphene.List(HeuristicType)

    def resolve_tags(parent, info):
        return parent.get("tags") or []

    def resolve_evidence(parent, info):
        return parent.get("evidence") or {}

    def resolve_technique(parent, info):
        return parent.get("technique") or {}

    def resolve_finding(parent, info):
        return parent.get("finding") or {}

    def resolve_heuristics(parent, info):
        return parent.get("heuristics") or []


class HuntFindingsConnection(graphene.ObjectType):
    total_count = graphene.Int()
    results = graphene.List(HuntFindingType)


class HuntRecommendationsConnection(graphene.ObjectType):
    total_count = graphene.Int()
    results = graphene.List(HuntRecommendationType)


class Query(graphene.ObjectType):
    hunt_findings = graphene.Field(
        HuntFindingsConnection,
        project_ids=graphene.List(graphene.UUID),
        technique_ids=graphene.List(graphene.String),
        confidences=graphene.List(graphene.String),
        recommendation_types=graphene.List(graphene.String),
        search=graphene.String(),
        limit=graphene.Int(),
        offset=graphene.Int(),
    )
    hunt_recommendations = graphene.Field(
        HuntRecommendationsConnection,
        project_ids=graphene.List(graphene.UUID),
        technique_ids=graphene.List(graphene.String),
        confidences=graphene.List(graphene.String),
        recommendation_types=graphene.List(graphene.String),
        generators=graphene.List(graphene.String),
        finding_ids=graphene.List(graphene.UUID),
        search=graphene.String(),
        limit=graphene.Int(),
        offset=graphene.Int(),
    )

    def resolve_hunt_findings(
        self,
        info,
        project_ids=None,
        technique_ids=None,
        confidences=None,
        recommendation_types=None,
        search=None,
        limit=None,
        offset=None,
    ):
        request = info.context
        cache_bundle = _ensure_cache(request)
        queryset = base_hunt_finding_queryset()
        queryset = apply_hunt_finding_filters(
            queryset,
            project_ids=[str(value) for value in project_ids] if project_ids else None,
            technique_ids=list(technique_ids) if technique_ids else None,
            confidences=list(confidences) if confidences else None,
            recommendation_types=list(recommendation_types) if recommendation_types else None,
            search=search,
        )
        queryset = finalize_hunt_finding_queryset(queryset)
        total_count = queryset.count()

        resolved_offset = max(offset or 0, 0)
        resolved_limit = limit if limit is not None else DEFAULT_LIMIT
        resolved_limit = max(1, min(resolved_limit, MAX_LIMIT))
        queryset = queryset[resolved_offset : resolved_offset + resolved_limit]

        context = {"request": request, **cache_bundle}
        serializer = HuntFindingSerializer(queryset, many=True, context=context)
        results = serializer.data
        return HuntFindingsConnection(total_count=total_count, results=results)

    def resolve_hunt_recommendations(
        self,
        info,
        project_ids=None,
        technique_ids=None,
        confidences=None,
        recommendation_types=None,
        generators=None,
        finding_ids=None,
        search=None,
        limit=None,
        offset=None,
    ):
        request = info.context
        cache_bundle = _ensure_cache(request)
        queryset = base_hunt_recommendation_queryset()
        queryset = apply_hunt_recommendation_filters(
            queryset,
            project_ids=[str(value) for value in project_ids] if project_ids else None,
            technique_ids=list(technique_ids) if technique_ids else None,
            confidences=list(confidences) if confidences else None,
            recommendation_types=list(recommendation_types) if recommendation_types else None,
            generators=list(generators) if generators else None,
            finding_ids=[str(value) for value in finding_ids] if finding_ids else None,
            search=search,
        )
        queryset = finalize_hunt_recommendation_queryset(queryset)
        total_count = queryset.count()

        resolved_offset = max(offset or 0, 0)
        resolved_limit = limit if limit is not None else DEFAULT_LIMIT
        resolved_limit = max(1, min(resolved_limit, MAX_LIMIT))
        queryset = queryset[resolved_offset : resolved_offset + resolved_limit]

        context = {"request": request, **cache_bundle}
        serializer = HuntRecommendationDetailSerializer(queryset, many=True, context=context)
        results = serializer.data
        return HuntRecommendationsConnection(total_count=total_count, results=results)


schema = graphene.Schema(query=Query)
