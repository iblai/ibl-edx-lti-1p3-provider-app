from __future__ import annotations

from django.db import IntegrityError
from organizations.models import Organization
from pylti1p3.contrib.django.lti1p3_tool_config.models import LtiTool, LtiToolKey
from rest_framework import serializers

from ..models import LtiKeyOrg, LtiToolOrg
from . import ssl_services


class StringListField(serializers.ListField):
    child = serializers.CharField()


class LtiToolKeySerializer(serializers.ModelSerializer):
    class Meta:
        model = LtiToolKey
        fields = ["name", "public_key", "public_jwk", "id"]

    public_key = serializers.CharField(read_only=True)
    public_jwk = serializers.JSONField(read_only=True)

    def validate(self, attrs):
        short_name = self.context["org_short_name"]
        try:
            # Since we're validating it we may as well store it
            attrs["org"] = Organization.objects.get(short_name=short_name)
        except Organization.DoesNotExist:
            raise serializers.ValidationError(f"Org: '{short_name}' Does Not Exist")

        return super().validate(attrs)

    def to_representation(self, instance):
        """Remove the `{org.short_name}-` prefix for name field"""
        rep = super().to_representation(instance)
        org = instance.key_org.org.short_name
        rep["name"] = rep["name"].replace(f"{org}-", "", 1)
        return rep

    def update(self, instance, validated_data):
        name = validated_data["name"]
        validated_data["name"] = f"{self.context['org_short_name']}-{name}"
        return super().update(instance, validated_data)

    def create(self, validated_data):
        """Autogenerate private/public key pairs"""
        # Since name is unique, we'll prepend the org short code (Also unique) to
        # prevent collisions between clients
        name = validated_data["name"]
        validated_data["name"] = f"{self.context['org_short_name']}-{name}"

        private_key = ssl_services.generate_private_key_pem()
        validated_data["private_key"] = private_key
        validated_data["public_key"] = ssl_services.priv_to_public_key_pem(private_key)
        lti_org = validated_data.pop("org")

        try:
            tool_key = LtiToolKey.objects.create(**validated_data)
            LtiKeyOrg.objects.create(key=tool_key, org=lti_org)
        except IntegrityError:
            raise serializers.ValidationError(f"Tool name: '{name}' already exists")
        return tool_key


class LtiToolSerializer(serializers.ModelSerializer):
    class Meta:
        model = LtiTool
        fields = "__all__"

    deployment_ids = StringListField()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # NOTE: Restrict the tool_key querset to keys part of current org
        self.fields["tool_key"].queryset = LtiToolKey.objects.filter(
            key_org__org__short_name=self.context["org_short_name"]
        )

    def validate(self, attrs):
        short_name = self.context["org_short_name"]
        try:
            # Since we're validating it we may as well store it
            attrs["org"] = Organization.objects.get(short_name=short_name)
        # NOTE: This may not be possible since if org DNE, then primary related
        # field for tool_key fails first since all validate_<obj>'s are called first
        except Organization.DoesNotExist:
            raise serializers.ValidationError(f"Org: '{short_name}' Does Not Exist")

        if not (attrs.get("key_set_url", None) or attrs.get("key_set", None)):
            raise serializers.ValidationError(
                "Either key_set_url or key_set must be supplied"
            )

        return attrs

    def create(self, validated_data):
        lti_org = validated_data.pop("org")
        tool = super().create(validated_data)
        LtiToolOrg.objects.create(tool=tool, org=lti_org)
        return tool
