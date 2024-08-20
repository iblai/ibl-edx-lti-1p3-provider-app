from django.utils.decorators import method_decorator
from openedx.core.lib.api.authentication import BearerAuthentication
from pylti1p3.contrib.django.lti1p3_tool_config.models import LtiTool, LtiToolKey
from rest_framework.permissions import IsAdminUser
from rest_framework.viewsets import ModelViewSet

from ..views import requires_lti_enabled
from .serializers import LtiToolKeySerializer, LtiToolSerializer


@method_decorator(requires_lti_enabled, name="dispatch")
class LtiKeyViewSet(ModelViewSet):
    serializer_class = LtiToolKeySerializer
    authentication_classes = [BearerAuthentication]
    permission_classes = [IsAdminUser]

    def get_queryset(self):
        return (
            LtiToolKey.objects.select_related("key_org__key")
            .filter(key_org__org__short_name=self.kwargs["org_short_name"])
            .order_by("name")
        )

    def get_serializer_context(self):
        ctx = super().get_serializer_context()
        ctx["org_short_name"] = self.kwargs["org_short_name"]
        return ctx


@method_decorator(requires_lti_enabled, name="dispatch")
class LtiToolViewSet(ModelViewSet):
    serializer_class = LtiToolSerializer
    authentication_classes = [BearerAuthentication]
    permission_classes = [IsAdminUser]

    def get_queryset(self):
        return (
            LtiTool.objects.select_related("tool_org__tool")
            .filter(tool_org__org__short_name=self.kwargs["org_short_name"])
            .order_by("title")
        )

    def get_serializer_context(self):
        ctx = super().get_serializer_context()
        ctx["org_short_name"] = self.kwargs["org_short_name"]
        return ctx
