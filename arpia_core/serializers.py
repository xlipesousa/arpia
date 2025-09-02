from rest_framework import serializers
from .models import Project, Asset, ObservedEndpoint


class ObservedEndpointSerializer(serializers.ModelSerializer):
    # permite enviar project UUID para acionar reconciliação automática
    project = serializers.UUIDField(write_only=True, required=False)

    class Meta:
        model = ObservedEndpoint
        fields = "__all__"
        read_only_fields = ("id", "first_seen", "last_seen")

    def create(self, validated_data):
        project_id = validated_data.pop("project", None)
        # se já veio asset, deixar o flow padrão
        if project_id and not validated_data.get("asset"):
            from .services import reconcile_endpoint
            from .models import Project as ProjectModel

            project = ProjectModel.objects.get(id=project_id)
            hostnames = (validated_data.get("raw") or {}).get("hostnames", [])
            asset_obj, endpoint_obj = reconcile_endpoint(
                project=project,
                ip=validated_data.get("ip"),
                port=validated_data.get("port"),
                hostnames=hostnames,
                raw=validated_data.get("raw"),
                source=validated_data.get("source", "api"),
            )
            # endpoint já criado por reconcile_endpoint
            return endpoint_obj
        return super().create(validated_data)


class AssetSerializer(serializers.ModelSerializer):
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
        read_only_fields = ("id", "created", "last_seen")


class ProjectSerializer(serializers.ModelSerializer):
    assets = AssetSerializer(many=True, read_only=True)

    class Meta:
        model = Project
        fields = ["id", "title", "slug", "summary", "created", "modified", "assets"]
        read_only_fields = ("id", "created", "modified")