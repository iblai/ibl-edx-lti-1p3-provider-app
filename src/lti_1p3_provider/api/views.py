from django.utils.decorators import method_decorator
from pylti1p3.contrib.django.lti1p3_tool_config.models import LtiToolKey
from rest_framework.viewsets import ModelViewSet

from ..models import LtiKeyOrg
from ..views import requires_lti_enabled
from .serializers import LtiToolKeySerializer


@method_decorator(requires_lti_enabled, name="dispatch")
class LtiKeyViewSet(ModelViewSet):
    serializer_class = LtiToolKeySerializer
    # FIX: get correct authentication/permission classes
    authentication_classes = []
    permission_classes = []

    def get_queryset(self):
        return LtiToolKey.objects.select_related("key_org__key").filter(
            key_org__org__short_name=self.kwargs["org_short_name"]
        )
