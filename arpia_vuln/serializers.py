from rest_framework import serializers

from .models import VulnScanSession, VulnTask, VulnerabilityFinding


class VulnTaskSerializer(serializers.ModelSerializer):
    tool_name = serializers.CharField(source="tool.name", read_only=True)
    script_slug = serializers.CharField(source="script.slug", read_only=True)

    class Meta:
        model = VulnTask
        fields = (
            "id",
            "session",
            "order",
            "kind",
            "status",
            "name",
            "tool",
            "tool_name",
            "script",
            "script_slug",
            "parameters",
            "progress",
            "stdout",
            "stderr",
            "started_at",
            "finished_at",
            "created_at",
            "updated_at",
        )
        read_only_fields = ("created_at", "updated_at", "stdout", "stderr")


class VulnerabilityFindingSerializer(serializers.ModelSerializer):
    session_reference = serializers.CharField(source="session.reference", read_only=True)
    source_task_name = serializers.CharField(source="source_task.name", read_only=True)

    class Meta:
        model = VulnerabilityFinding
        fields = (
            "id",
            "session",
            "session_reference",
            "source_task",
            "source_task_name",
            "cve",
            "title",
            "summary",
            "severity",
            "status",
            "host",
            "service",
            "port",
            "protocol",
            "cvss_score",
            "cvss_vector",
            "data",
            "detected_at",
            "created_at",
        )
        read_only_fields = ("created_at",)


class VulnScanSessionSerializer(serializers.ModelSerializer):
    project_name = serializers.CharField(source="project.name", read_only=True)
    owner_username = serializers.CharField(source="owner.get_username", read_only=True)
    tasks = VulnTaskSerializer(many=True, read_only=True)
    findings = VulnerabilityFindingSerializer(many=True, read_only=True)

    class Meta:
        model = VulnScanSession
        fields = (
            "id",
            "reference",
            "project",
            "project_name",
            "owner",
            "owner_username",
            "source_scan_session",
            "title",
            "status",
            "config_snapshot",
            "targets_snapshot",
            "report_snapshot",
            "started_at",
            "finished_at",
            "last_error",
            "notes",
            "created_at",
            "updated_at",
            "tasks",
            "findings",
        )
        read_only_fields = ("created_at", "updated_at")
