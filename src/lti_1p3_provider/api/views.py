from django.utils.decorators import method_decorator
from openedx.core.lib.api.authentication import BearerAuthentication
from pylti1p3.contrib.django.lti1p3_tool_config.models import LtiTool, LtiToolKey
from rest_framework.exceptions import ValidationError
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

    def perform_destroy(self, instance):
        """Ensure that we delete the key only if it's not used by any tool."""
        existing_tools = LtiTool.objects.filter(tool_key=instance).values_list(
            "title", flat=True
        )
        if existing_tools:
            raise ValidationError(
                (
                    f"Key is currently used by the following tools: {', '.join(existing_tools)}. "
                    "Please assign a different key to these tools before deleting this one."
                )
            )
        super().perform_destroy(instance)


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
