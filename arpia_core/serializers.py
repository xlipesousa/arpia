from rest_framework import serializers

from .models import Asset, ObservedEndpoint, Project


class ObservedEndpointSerializer(serializers.ModelSerializer):
    project = serializers.UUIDField(source="asset.project_id", read_only=True)

    class Meta:
        model = ObservedEndpoint
        fields = [
            "id",
            "asset",
            "project",
            "ip",
            "port",
            "proto",
            "service",
            "path",
            "raw",
            "source",
            "first_seen",
            "last_seen",
        ]
        read_only_fields = ("id", "first_seen", "last_seen", "project")


class AssetSerializer(serializers.ModelSerializer):
    project = serializers.UUIDField(source="project_id", read_only=True)
    endpoints = ObservedEndpointSerializer(many=True, read_only=True)

    class Meta:
        model = Asset
        fields = [
            "id",
            "project",
            "identifier",
            "name",
            "hostnames",
            "ips",
            "category",
            "metadata",
            "created",
            "last_seen",
            "endpoints",
        ]
        read_only_fields = ("id", "created", "last_seen", "project", "endpoints")


class ProjectSerializer(serializers.ModelSerializer):
    owner = serializers.CharField(source="owner.username", read_only=True)
    members = serializers.SerializerMethodField()
    assets = AssetSerializer(many=True, read_only=True)

    class Meta:
        model = Project
        fields = [
            "id",
            "owner",
            "name",
            "slug",
            "description",
            "client_name",
            "status",
            "visibility",
            "start_at",
            "end_at",
            "timezone",
            "hosts",
            "protected_hosts",
            "networks",
            "ports",
            "credentials_json",
            "metadata",
            "created",
            "modified",
            "assets",
            "members",
        ]
        read_only_fields = ("id", "owner", "slug", "created", "modified", "assets", "members")

    def get_members(self, obj):
        memberships = obj.memberships.select_related("user")
        return [
            {
                "user": m.user.username,
                "role": m.role,
            }
            for m in memberships
        ]