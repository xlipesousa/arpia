from __future__ import annotations

from rest_framework import serializers

from .models import (
    AttackTechnique,
    CveAttackTechnique,
    HuntEnrichment,
    HuntFinding,
    HuntFindingSnapshot,
    HuntFindingState,
    HuntRecommendation,
)


class AttackTechniqueSerializer(serializers.ModelSerializer):
    tactic_id = serializers.CharField(source="tactic.id")
    tactic_name = serializers.CharField(source="tactic.name")
    matrix = serializers.CharField(source="tactic.matrix")
    parent_id = serializers.CharField(allow_null=True, required=False, read_only=True)

    class Meta:
        model = AttackTechnique
        fields = (
            "id",
            "name",
            "description",
            "is_subtechnique",
            "parent_id",
            "tactic_id",
            "tactic_name",
            "matrix",
            "platforms",
            "datasources",
            "external_references",
            "version",
            "updated_at",
        )


class CveAttackTechniqueSerializer(serializers.ModelSerializer):
    technique = AttackTechniqueSerializer(read_only=True)
    technique_id = serializers.CharField(source="technique.id", read_only=True)

    class Meta:
        model = CveAttackTechnique
        fields = (
            "id",
            "cve",
            "technique_id",
            "technique",
            "source",
            "confidence",
            "rationale",
            "updated_at",
        )


class HuntEnrichmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = HuntEnrichment
        fields = (
            "id",
            "source",
            "status",
            "fetched_at",
            "expires_at",
            "error_message",
            "payload",
        )


class HuntFindingSnapshotSerializer(serializers.ModelSerializer):
    class Meta:
        model = HuntFindingSnapshot
        fields = (
            "version",
            "captured_at",
            "blue_profile",
            "red_profile",
            "enrichment_ids",
        )


class HuntFindingStateSerializer(serializers.ModelSerializer):
    class Meta:
        model = HuntFindingState
        fields = (
            "version",
            "captured_at",
            "source_hash",
            "payload",
        )


class HuntFindingSerializer(serializers.ModelSerializer):
    project_name = serializers.CharField(source="project.name")
    project_slug = serializers.CharField(source="project.slug")
    vulnerability_title = serializers.CharField(source="vulnerability.title")
    enrichments = HuntEnrichmentSerializer(many=True, read_only=True)
    snapshots = HuntFindingSnapshotSerializer(many=True, read_only=True)
    state_snapshots = HuntFindingStateSerializer(many=True, read_only=True)
    recommendation_counts = serializers.SerializerMethodField()
    applied_heuristics = serializers.SerializerMethodField()

    class Meta:
        model = HuntFinding
        fields = (
            "id",
            "project",
            "project_name",
            "project_slug",
            "vulnerability",
            "vulnerability_title",
            "cve",
            "severity",
            "cvss_score",
            "cvss_vector",
            "summary",
            "blue_profile",
            "red_profile",
            "profile_version",
            "last_profiled_at",
            "state_version",
            "last_state_snapshot_at",
            "detected_at",
            "enrichments",
            "snapshots",
            "state_snapshots",
            "recommendation_counts",
            "applied_heuristics",
        )

    def get_recommendation_counts(self, obj: HuntFinding) -> dict[str, int]:
        total = getattr(obj, "recommendation_total", None)
        blue = getattr(obj, "recommendation_blue", None)
        red = getattr(obj, "recommendation_red", None)

        if total is None:
            total = obj.recommendations.count()
        if blue is None:
            blue = obj.recommendations.filter(recommendation_type=HuntRecommendation.Type.BLUE).count()
        if red is None:
            red = obj.recommendations.filter(recommendation_type=HuntRecommendation.Type.RED).count()

        return {
            "total": int(total),
            "blue": int(blue),
            "red": int(red),
        }

    def get_applied_heuristics(self, obj: HuntFinding) -> list[dict[str, object]]:
        cve = (obj.cve or "").strip()
        if not cve:
            return []

        cache: dict[str, list[dict[str, object]]] = self.context.setdefault("heuristic_cache", {})
        if cve not in cache:
            mappings = list(
                CveAttackTechnique.objects.filter(cve=cve)
                .select_related("technique", "technique__tactic")
                .order_by("-updated_at")
            )
            cache[cve] = CveAttackTechniqueSerializer(mappings, many=True, context=self.context).data
        return cache[cve]


class HuntRecommendationSerializer(serializers.ModelSerializer):
    technique = AttackTechniqueSerializer(read_only=True)
    technique_id = serializers.CharField(read_only=True)
    finding_id = serializers.UUIDField(read_only=True)
    project_id = serializers.UUIDField(source="finding.project_id", read_only=True)
    project_name = serializers.CharField(source="finding.project.name", read_only=True)
    project_slug = serializers.CharField(source="finding.project.slug", read_only=True)
    tags = serializers.ListField(child=serializers.CharField(), allow_empty=True, read_only=True)
    source_enrichment_id = serializers.UUIDField(read_only=True, allow_null=True)

    class Meta:
        model = HuntRecommendation
        fields = (
            "id",
            "finding_id",
            "project_id",
            "project_name",
            "project_slug",
            "technique_id",
            "technique",
            "recommendation_type",
            "title",
            "summary",
            "confidence",
            "confidence_note",
            "evidence",
            "tags",
            "generated_by",
            "playbook_slug",
            "source_enrichment_id",
            "created_at",
            "updated_at",
        )


class HuntFindingProfileSerializer(serializers.Serializer):
    finding_id = serializers.UUIDField(source="finding.id")
    project_id = serializers.UUIDField(source="finding.project_id")
    project_name = serializers.CharField(source="finding.project.name")
    project_slug = serializers.CharField(source="finding.project.slug")
    profile_version = serializers.IntegerField(source="finding.profile_version")
    last_profiled_at = serializers.DateTimeField(source="finding.last_profiled_at", allow_null=True)
    blue_profile = serializers.JSONField()
    red_profile = serializers.JSONField()
    applied_heuristics = CveAttackTechniqueSerializer(many=True)
    recommendation_counts = serializers.SerializerMethodField()
    recommendations = HuntRecommendationSerializer(many=True)

    def get_recommendation_counts(self, obj: dict[str, object]) -> dict[str, int]:
        recommendations = obj.get("recommendations", [])
        if not recommendations:
            return {"total": 0, "blue": 0, "red": 0}

        blue = sum(1 for rec in recommendations if getattr(rec, "recommendation_type", None) == HuntRecommendation.Type.BLUE)
        red = sum(1 for rec in recommendations if getattr(rec, "recommendation_type", None) == HuntRecommendation.Type.RED)
        total = blue + red
        return {"total": total, "blue": blue, "red": red}


class HuntRecommendationDetailSerializer(HuntRecommendationSerializer):
    finding = serializers.SerializerMethodField()
    heuristics = serializers.SerializerMethodField()

    class Meta(HuntRecommendationSerializer.Meta):
        fields = HuntRecommendationSerializer.Meta.fields + (
            "finding",
            "heuristics",
        )

    def get_finding(self, obj: HuntRecommendation) -> dict[str, object] | None:
        if not obj.finding:
            return None
        finding = obj.finding
        return {
            "id": str(finding.pk),
            "project_id": str(finding.project_id) if finding.project_id else None,
            "project_name": finding.project.name if finding.project_id else None,
            "project_slug": finding.project.slug if finding.project_id else None,
            "vulnerability_id": str(finding.vulnerability_id) if finding.vulnerability_id else None,
            "cve": finding.cve,
            "severity": finding.severity,
            "summary": finding.summary,
            "blue_profile": finding.blue_profile or {},
            "red_profile": finding.red_profile or {},
            "profile_version": finding.profile_version,
        }

    def get_heuristics(self, obj: HuntRecommendation) -> list[dict[str, object]]:
        finding = obj.finding
        if not finding or not finding.cve:
            return []
        cache: dict[str, list[dict[str, object]]] = self.context.setdefault("heuristic_cache", {})
        if finding.cve not in cache:
            mappings = list(
                CveAttackTechnique.objects.filter(cve=finding.cve)
                .select_related("technique", "technique__tactic")
                .order_by("-updated_at")
            )
            cache[finding.cve] = CveAttackTechniqueSerializer(mappings, many=True, context=self.context).data
        return cache[finding.cve]
