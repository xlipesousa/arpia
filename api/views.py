from django.db.models import Q

from rest_framework import permissions, status, viewsets
from rest_framework.response import Response
from rest_framework.views import APIView

from arpia_core.models import Asset, ObservedEndpoint, Project
from arpia_core.serializers import AssetSerializer, ObservedEndpointSerializer, ProjectSerializer
from arpia_core.services import reconcile_endpoint


class HealthCheck(APIView):
    permission_classes = ()
    authentication_classes = ()

    def get(self, request, *args, **kwargs):
        return Response({"status": "ok"}, status=status.HTTP_200_OK)


class ProjectViewSet(viewsets.ModelViewSet):
    serializer_class = ProjectSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if not user.is_authenticated:
            return Project.objects.none()
        return (
            Project.objects.filter(Q(owner=user) | Q(memberships__user=user))
            .select_related("owner")
            .distinct()
            .order_by("-created")
        )

    def perform_create(self, serializer):
        project = serializer.save(owner=self.request.user)
        project.memberships.get_or_create(
            user=self.request.user,
            defaults={"role": "owner", "invited_by": self.request.user},
        )


class AssetViewSet(viewsets.ModelViewSet):
    serializer_class = AssetSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if not user.is_authenticated:
            return Asset.objects.none()
        accessible_projects = Project.objects.filter(Q(owner=user) | Q(memberships__user=user)).values_list("id", flat=True)
        return (
            Asset.objects.select_related("project")
            .filter(project_id__in=accessible_projects)
            .order_by("-last_seen")
        )


class ObservedEndpointViewSet(viewsets.ModelViewSet):
    serializer_class = ObservedEndpointSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if not user.is_authenticated:
            return ObservedEndpoint.objects.none()
        accessible_projects = Project.objects.filter(Q(owner=user) | Q(memberships__user=user)).values_list("id", flat=True)
        return (
            ObservedEndpoint.objects.select_related("asset", "asset__project")
            .filter(asset__project_id__in=accessible_projects)
            .order_by("-last_seen")
        )

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
                target_project = Project.objects.get(id=project_id)
            except Project.DoesNotExist:
                return Response({"project": "Projeto não encontrado."}, status=status.HTTP_400_BAD_REQUEST)

            user = request.user
            if target_project.owner != user and not target_project.memberships.filter(user=user).exists():
                return Response({"project": "Sem permissão para atualizar este projeto."}, status=status.HTTP_403_FORBIDDEN)

            asset, endpoint = reconcile_endpoint(
                project=target_project,
                ip=ip,
                port=port,
                hostnames=hostnames,
                raw=raw,
                source=source,
            )
            serializer = self.get_serializer(endpoint)
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return super().create(request, *args, **kwargs)