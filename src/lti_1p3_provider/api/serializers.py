from __future__ import annotations

from typing import Any

from rest_framework import serializers

from ..models import LtiKey
from . import ssl_services


class LtiKeySerializer(serializers.ModelSerializer):
    class Meta:
        model = LtiKey
        fields = ["name", "private_key", "public_key", "public_jwk"]

    public_key = serializers.CharField(read_only=True)
    public_jwk = serializers.JSONField(read_only=True)

    def validate_pviate_key(self, value: str) -> str:
        """Check if the private key is valid"""
        if not ssl_services.is_valid_private_key(value):
            raise serializers.ValidationError("Invalid private key format")
        return value

    def validate(self, attrs):
        attrs["public_key"] = ssl_services.priv_to_public_key_pem(attrs["private_key"])
        return attrs
