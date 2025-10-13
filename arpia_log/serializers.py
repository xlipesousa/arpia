from __future__ import annotations

from typing import Any, Dict, Iterable, List

from django.db import transaction
from django.utils import timezone
from rest_framework import serializers

from .models import LogEntry


def _coerce_optional_ref(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)) and value:
        return str(next(iter(value)))
    return str(value)


class TagsField(serializers.ListField):
    child = serializers.CharField(max_length=64)

    def to_internal_value(self, data: Iterable[Any]) -> List[str]:
        tags = super().to_internal_value(data)
        seen = set()
        ordered: List[str] = []
        for tag in tags:
            norm = tag.strip()
            if not norm:
                continue
            if norm.lower() in seen:
                continue
            seen.add(norm.lower())
            ordered.append(norm)
        return ordered


class LogEntrySerializer(serializers.ModelSerializer):
    tags = TagsField(required=False, allow_empty=True)

    class Meta:
        model = LogEntry
        fields = [
            "id",
            "version",
            "timestamp",
            "source_app",
            "component",
            "event_type",
            "severity",
            "message",
            "details",
            "context",
            "correlation",
            "tags",
            "project_ref",
            "asset_ref",
            "user_ref",
            "ingestion_channel",
            "ingested_at",
        ]
        read_only_fields = ["id", "ingested_at"]

    def validate_severity(self, value: str) -> str:
        value = (value or "").upper()
        if value not in LogEntry.Severity.values:
            raise serializers.ValidationError("Severidade inválida")
        return value

    def validate_ingestion_channel(self, value: str) -> str:
        value = (value or "").lower()
        if value not in LogEntry.Channel.values:
            raise serializers.ValidationError("Canal de ingestão inválido")
        return value

    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        attrs.setdefault("timestamp", timezone.now())
        attrs.setdefault("version", 1)
        attrs.setdefault("details", {})
        attrs.setdefault("context", {})
        attrs.setdefault("correlation", {})
        attrs.setdefault("tags", [])

        correlation = attrs.get("correlation") or {}
        context = attrs.get("context") or {}

        project_ref = attrs.get("project_ref") or correlation.get("project_id") or correlation.get("project")
        if project_ref:
            attrs["project_ref"] = _coerce_optional_ref(project_ref)

        asset_ref = attrs.get("asset_ref") or correlation.get("asset_id")
        if asset_ref:
            attrs["asset_ref"] = _coerce_optional_ref(asset_ref)

        user_ref = attrs.get("user_ref") or correlation.get("user_id")
        if not user_ref and isinstance(context.get("actor"), dict):
            user_ref = context["actor"].get("id")
        if user_ref:
            attrs["user_ref"] = _coerce_optional_ref(user_ref)

        if not attrs.get("message"):
            raise serializers.ValidationError({"message": "Mensagem é obrigatória."})

        return attrs

    @transaction.atomic
    def create(self, validated_data: Dict[str, Any]) -> LogEntry:
        tags = validated_data.pop("tags", [])
        entry = super().create(validated_data)
        entry.tags = tags
        entry.save(update_fields=["tags"])
        return entry


class LogBatchSerializer(serializers.Serializer):
    items = serializers.ListField(child=serializers.DictField(), allow_empty=False)

    def create(self, validated_data: Dict[str, Any]) -> List[LogEntry]:
        raise NotImplementedError

    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        if len(attrs["items"]) > 500:
            raise serializers.ValidationError("Limite máximo de 500 eventos por lote.")
        return attrs