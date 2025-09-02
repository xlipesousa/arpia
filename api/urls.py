from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import ProjectViewSet, AssetViewSet, ObservedEndpointViewSet, HealthCheck

router = DefaultRouter()
router.register(r"projects", ProjectViewSet, basename="project")
router.register(r"assets", AssetViewSet, basename="asset")
router.register(r"endpoints", ObservedEndpointViewSet, basename="endpoint")

urlpatterns = [
    path("", include(router.urls)),
    path("health/", HealthCheck.as_view(), name="health"),
]