from rest_framework import viewsets, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response

from arpia_core.models import Project, Asset, ObservedEndpoint
from arpia_core.serializers import ProjectSerializer, AssetSerializer, ObservedEndpointSerializer


class HealthCheck(APIView):
    permission_classes = ()
    authentication_classes = ()

    def get(self, request, *args, **kwargs):
        return Response({"status": "ok"}, status=status.HTTP_200_OK)


class ProjectViewSet(viewsets.ModelViewSet):
    queryset = Project.objects.all().order_by("-created")
    serializer_class = ProjectSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]


class AssetViewSet(viewsets.ModelViewSet):
    queryset = Asset.objects.select_related("project").all().order_by("-last_seen")
    serializer_class = AssetSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]


class ObservedEndpointViewSet(viewsets.ModelViewSet):
    queryset = ObservedEndpoint.objects.select_related("asset", "asset__project").all().order_by("-last_seen")
    serializer_class = ObservedEndpointSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]