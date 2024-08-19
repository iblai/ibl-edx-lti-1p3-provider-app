from django.utils.decorators import method_decorator
from pylti1p3.contrib.django.lti1p3_tool_config.models import LtiToolKey
from rest_framework.viewsets import ModelViewSet

from ..views import requires_lti_enabled
from .serializers import LtiKeySerializer


@method_decorator(requires_lti_enabled, name="dispatch")
class LtiKeyViewSet(ModelViewSet):
    queryset = LtiToolKey.objects.all()
    serializer_class = LtiKeySerializer
    # FIX: get correct authentication/permission classes
    authentication_classes = []
    permission_classes = []
