from __future__ import annotations

from rest_framework import serializers

from .models import HuntEnrichment, HuntFinding, HuntFindingSnapshot, HuntFindingState


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
    vulnerability_title = serializers.CharField(source="vulnerability.title")
    enrichments = HuntEnrichmentSerializer(many=True, read_only=True)
    snapshots = HuntFindingSnapshotSerializer(many=True, read_only=True)
    state_snapshots = HuntFindingStateSerializer(many=True, read_only=True)

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
            "state_version",
            "last_state_snapshot_at",
            "detected_at",
            "enrichments",
            "snapshots",
            "state_snapshots",
        )
