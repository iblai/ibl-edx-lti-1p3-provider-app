from rest_framework.routers import DefaultRouter

from .views import LtiKeyViewSet, LtiToolViewSet

router = DefaultRouter()
router.register("lti-keys", LtiKeyViewSet, basename="lti-keys")
router.register("lti-tools", LtiToolViewSet, basename="lti-tools")
