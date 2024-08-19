from rest_framework.routers import DefaultRouter

from .views import LtiKeyViewSet

router = DefaultRouter()
router.register("lti-keys", LtiKeyViewSet, basename="lti-keys")
