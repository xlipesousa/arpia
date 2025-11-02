from django.conf import settings
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import ProjectViewSet, AssetViewSet, ObservedEndpointViewSet, HealthCheck
from .hunt_views import (
    AttackTechniqueViewSet,
    HuntFindingViewSet,
    HuntRecommendationViewSet,
)
from .graphql.views import HuntGraphQLView
from .schema import schema

router = DefaultRouter()
router.register(r"projects", ProjectViewSet, basename="project")
router.register(r"assets", AssetViewSet, basename="asset")
router.register(r"endpoints", ObservedEndpointViewSet, basename="endpoint")
router.register(r"hunt/findings", HuntFindingViewSet, basename="hunt-finding")
router.register(r"hunt/recommendations", HuntRecommendationViewSet, basename="hunt-recommendation")
router.register(r"hunt/catalog/techniques", AttackTechniqueViewSet, basename="hunt-technique")

urlpatterns = [
    path("", include(router.urls)),
    path("health/", HealthCheck.as_view(), name="health"),
    path(
        "hunt/graphql/",
        HuntGraphQLView.as_view(schema=schema, graphiql=settings.DEBUG),
        name="hunt-graphql",
    ),
]