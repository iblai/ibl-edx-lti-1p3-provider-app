from __future__ import annotations

from django.db import IntegrityError
from organizations.models import Organization
from rest_framework import serializers

from ..models import LtiKeyOrg, LtiToolKey
from . import ssl_services


class LtiToolKeySerializer(serializers.ModelSerializer):
    class Meta:
        model = LtiToolKey
        fields = [
            "name",
            "public_key",
            "public_jwk",
        ]

    public_key = serializers.CharField(read_only=True)
    public_jwk = serializers.JSONField(read_only=True)

    def validate_private_key(self, value: str) -> str:
        """Check if the private key is valid"""
        if not ssl_services.is_valid_private_key(value):
            raise serializers.ValidationError("Invalid private key format")
        return value

    def validate(self, attrs):
        short_name = self.context["org_short_name"]
        try:
            # Since we're validating it we may as well store it
            attrs["org"] = Organization.objects.get(short_name=short_name)
        except Organization.DoesNotExist:
            raise serializers.ValidationError(f"Org {short_name} Does Not Exist")

        return super().validate(attrs)

    def create(self, validated_data):
        """Autogenerate private/public key pairs"""
        # Since name is unique, we'll prepend the org short code to prevent collisions
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
