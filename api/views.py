from rest_framework import viewsets, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response

from arpia_core.models import Project, Asset, ObservedEndpoint
from arpia_core.serializers import ProjectSerializer, AssetSerializer, ObservedEndpointSerializer
from arpia_core.services import reconcile_endpoint


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

    def create(self, request, *args, **kwargs):
        """
        Se request.data contiver 'project', aciona reconcile_endpoint diretamente
        (cria/atualiza Asset e ObservedEndpoint) e retorna o endpoint criado.
        Caso contrário, delega ao comportamento padrão do ModelViewSet.
        """
        project_id = request.data.get("project")
        if project_id:
            ip = request.data.get("ip")
            port = request.data.get("port")
            raw = request.data.get("raw", {}) or {}
            source = request.data.get("source", "api")
            hostnames = raw.get("hostnames", [])

            try:
                project = Project.objects.get(id=project_id)
            except Project.DoesNotExist:
                return Response({"project": "Projeto não encontrado."}, status=status.HTTP_400_BAD_REQUEST)

            asset, endpoint = reconcile_endpoint(
                project=project,
                ip=ip,
                port=port,
                hostnames=hostnames,
                raw=raw,
                source=source,
            )
            serializer = self.get_serializer(endpoint)
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return super().create(request, *args, **kwargs)