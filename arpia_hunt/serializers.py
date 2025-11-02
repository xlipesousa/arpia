from __future__ import annotations

from rest_framework import serializers

from .models import HuntEnrichment, HuntFinding, HuntFindingSnapshot


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


class HuntFindingSerializer(serializers.ModelSerializer):
    project_name = serializers.CharField(source="project.name")
    vulnerability_title = serializers.CharField(source="vulnerability.title")
    enrichments = HuntEnrichmentSerializer(many=True, read_only=True)
    snapshots = HuntFindingSnapshotSerializer(many=True, read_only=True)

    class Meta:
        model = HuntFinding
        fields = (
            "id",
            "project",
            "project_name",
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
            "detected_at",
            "enrichments",
            "snapshots",
        )
