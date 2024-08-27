from __future__ import annotations

import json

from django.db import IntegrityError
from opaque_keys import InvalidKeyError
from opaque_keys.edx.keys import CourseKey, UsageKey
from openedx.core.lib.api.serializers import CourseKeyField, UsageKeyField
from organizations.models import Organization
from pylti1p3.contrib.django.lti1p3_tool_config.models import LtiTool, LtiToolKey
from rest_framework import serializers

from ..models import LaunchGate, LtiKeyOrg, LtiToolOrg
from . import ssl_services


class StringListField(serializers.ListField):
    child = serializers.CharField()


class TextBackedListField(StringListField):
    """A ListField backed by a Char-Type field in the db

    - Writes as a JSON String
    - Reads object from a JSON string
    """

    def to_representation(self, data):
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except ValueError:
                data = []
        return super().to_representation(data)

    def to_internal_value(self, data):
        if data:
            return json.dumps(data)
        return "[]"


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
        try:
            return super().update(instance, validated_data)
        except IntegrityError:
            raise serializers.ValidationError(f"Key name: '{name}' already exists")

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
            raise serializers.ValidationError(f"Key name: '{name}' already exists")
        return tool_key


class LaunchGateSerializer(serializers.ModelSerializer):
    class Meta:
        model = LaunchGate
        fields = ["allowed_keys", "allowed_courses", "allow_all_within_org"]

    allowed_keys = StringListField(
        allow_empty=True,
        default=lambda: [],
    )
    allowed_courses = StringListField(
        allow_empty=True,
        default=lambda: [],
    )
    allow_all_within_org = serializers.BooleanField(
        default=False,
        help_text="If True, a target_link_uri will work with any content within this org",
    )

    def validate(self, attrs):
        """Ensure at least one of allow* is set"""
        if not (
            attrs["allowed_keys"]
            or attrs["allowed_courses"]
            or attrs["allow_all_within_org"]
        ):
            raise serializers.ValidationError(
                "Set either allow_all_within_org or one or more of allowed_courses/allowed_keys"
            )
        return attrs

    def to_representation(self, instance):
        rep = super().to_representation(instance)
        rep["allow_all_within_org"] = instance.allowed_orgs == [
            self.context["org_short_name"]
        ]
        return rep

    def validate_allowed_courses(self, value):
        for key in value:
            try:
                key = CourseKey.from_string(key)
                org_short_name = self.context["org_short_name"]
                if key.org != org_short_name:
                    raise serializers.ValidationError(
                        f"Course Key must be within org: {org_short_name}"
                    )
            except InvalidKeyError:
                raise serializers.ValidationError(
                    "Invalid Course Key. Format is: course-v1:<org>+<course>+<run>"
                )
        return value

    def validate_allowed_keys(self, value):
        for key in value:
            try:
                key = UsageKey.from_string(key)
                org_short_name = self.context["org_short_name"]
                if key.course_key.org != org_short_name:
                    raise serializers.ValidationError(
                        f"Usage Key must be within org: {org_short_name}"
                    )
            except InvalidKeyError:
                raise serializers.ValidationError(
                    "Invalid Usage Key. Format is: "
                    "block-v1:<org>+<course>+<run>+type@<block_type>+block@<hex_uuid>"
                )
        return value


class LtiToolSerializer(serializers.ModelSerializer):
    class Meta:
        model = LtiTool
        fields = [
            "id",
            "title",
            "issuer",
            "is_active",
            "client_id",
            "use_by_default",
            "auth_login_url",
            "auth_token_url",
            "auth_audience",
            "key_set_url",
            "key_set",
            "tool_key",
            "deployment_ids",
            "launch_gate",
        ]

    deployment_ids = TextBackedListField()
    launch_gate = LaunchGateSerializer()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # NOTE: Restrict the tool_key querset to keys part of current org
        self.fields["tool_key"].queryset = LtiToolKey.objects.filter(
            key_org__org__short_name=self.context["org_short_name"]
        )

    def validate(self, attrs):
        short_name = self.context["org_short_name"]
        # Since this endpoint is for an org, allowed_orgs must be [] or their org only
        allow_all_within_org = attrs["launch_gate"].pop("allow_all_within_org")
        attrs["launch_gate"]["allowed_orgs"] = (
            [short_name] if allow_all_within_org else []
        )

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

    def update(self, instance, validated_data):
        """Update object and launch gate, creating launch gate if necessary"""
        # Update LtiTool object
        launch_gate_data = validated_data.pop("launch_gate")
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        # Update LaunchGate
        launch_gate = instance.launch_gate
        for attr, value in launch_gate_data.items():
            setattr(launch_gate, attr, value)
        launch_gate.save()

        return instance

    def create(self, validated_data):
        lti_org = validated_data.pop("org")
        launch_gate_data = validated_data.pop("launch_gate")
        tool = LtiTool.objects.create(**validated_data)
        LtiToolOrg.objects.create(tool=tool, org=lti_org)
        LaunchGate.objects.create(tool=tool, **launch_gate_data)
        return tool
