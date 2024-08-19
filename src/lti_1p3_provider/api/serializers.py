from __future__ import annotations

from typing import Any

from organizations.models import Organization
from organizations.serializers import OrganizationSerializer
from rest_framework import serializers

from ..models import LtiKeyOrg, LtiToolKey
from . import ssl_services


class LtiKeyOrgSerializer(serializers.ModelSerializer):
    class Meta:
        model = LtiKeyOrg
        fields = ["org"]

    org = serializers.SlugRelatedField(
        "short_name", queryset=Organization.objects.all()
    )


class LtiToolKeySerializer(serializers.ModelSerializer):
    class Meta:
        model = LtiToolKey
        fields = ["name", "private_key", "public_key", "public_jwk", "org_short_name"]

    private_key = serializers.JSONField(read_only=True)
    public_key = serializers.CharField(read_only=True)
    public_jwk = serializers.JSONField(read_only=True)
    org_short_name = serializers.SlugRelatedField(
        "short_name", source="key_org__org", queryset=Organization.objects.all()
    )

    def validate_pviate_key(self, value: str) -> str:
        """Check if the private key is valid"""
        if not ssl_services.is_valid_private_key(value):
            raise serializers.ValidationError("Invalid private key format")
        return value

    def create(self, validated_data):
        """Autogenerate private/public key pairs"""
        private_key = ssl_services.generate_private_key_pem()
        validated_data["private_key"] = private_key
        validated_data["public_key"] = ssl_services.priv_to_public_key_pem(private_key)
        lti_org = validated_data.pop("key_org__org")
        tool_key = LtiToolKey.objects.create(**validated_data)
        LtiKeyOrg.objects.create(key=tool_key, org=lti_org)
        return tool_key
