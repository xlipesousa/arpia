from rest_framework import serializers
from .models import Project, Asset, ObservedEndpoint


class ObservedEndpointSerializer(serializers.ModelSerializer):
    # aceita project na criação para permitir reconciliação automática
    project = serializers.UUIDField(write_only=True, required=False)

    class Meta:
        model = ObservedEndpoint
        fields = "__all__"
        read_only_fields = ("id", "first_seen", "last_seen")

    def create(self, validated_data):
        project_id = validated_data.pop("project", None)
        asset = validated_data.get("asset", None)
        if asset is None and project_id:
            # import local para evitar circular imports
            from .services import reconcile_endpoint
            from .models import Project as ProjectModel

            project = ProjectModel.objects.get(id=project_id)
            hostnames = (validated_data.get("fingerprint") or {}).get("hostnames", [])
            asset_obj, oe = reconcile_endpoint(
                project=project,
                ip=validated_data.get("ip"),
                port=validated_data.get("port"),
                hostnames=hostnames,
                fingerprint=validated_data.get("fingerprint"),
                source=validated_data.get("source", "api"),
            )
            # associe o asset criado ao payload para criar ObservedEndpoint via super()
            validated_data["asset"] = asset_obj
            # ObservedEndpoint already created inside reconcile_endpoint -> return it
            return oe
        return super().create(validated_data)


class AssetSerializer(serializers.ModelSerializer):
    endpoints = ObservedEndpointSerializer(many=True, read_only=True)

    class Meta:
        model = Asset
        fields = [
            "id",
            "project",
            "logical_id",
            "display_name",
            "hostnames",
            "ip_addresses",
            "asset_type",
            "tags",
            "created_at",
            "last_seen",
            "endpoints",
        ]
        read_only_fields = ("id", "created_at", "last_seen")


class ProjectSerializer(serializers.ModelSerializer):
    assets = AssetSerializer(many=True, read_only=True)

    class Meta:
        model = Project
        fields = ["id", "name", "slug", "description", "created_at", "updated_at", "assets"]
        read_only_fields = ("id", "created_at", "updated_at")