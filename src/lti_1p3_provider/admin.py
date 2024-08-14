from __future__ import annotations

from django.contrib import admin

from . import models


@admin.register(models.LaunchGate)
class LaunchGateAdmin(admin.ModelAdmin):
    list_display = (
        "tool_name",
        "tool_issuer",
        "tool_client_id",
        "has_allowed_keys",
        "allowed_orgs",
    )

    def has_allowed_keys(self, obj) -> bool:
        return bool(obj.allowed_keys)

    def tool_name(self, obj) -> str:
        return f"{obj.tool.title}"

    def tool_issuer(self, obj) -> str:
        return obj.tool.issuer

    def tool_client_id(self, obj) -> str:
        return obj.tool.client_id

    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        """Shows human readable name for tool selection"""
        formfield = super().formfield_for_foreignkey(db_field, request, **kwargs)
        if db_field.name == "tool":
            formfield.label_from_instance = lambda obj: f"{obj.title} ({obj.client_id})"
        return formfield


@admin.register(models.LtiProfile)
class LtiProfileAdmin(admin.ModelAdmin):
    pass


@admin.register(models.LtiGradedResource)
class LtiGradedResourceAdmin(admin.ModelAdmin):
    pass


@admin.register(models.LtiToolOrg)
class LtiTooLOrgAdmin(admin.ModelAdmin):
    list_display = ("tool_name", "tool_issuer", "tool_client_id", "edx_org_name")

    def tool_name(self, obj) -> str:
        return f"{obj.tool.title}"

    def tool_issuer(self, obj) -> str:
        return obj.tool.issuer

    def tool_client_id(self, obj) -> str:
        return obj.tool.client_id

    def edx_org_name(self, obj) -> str:
        return obj.org.short_name

    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        """Shows human readable name for tool selection"""
        formfield = super().formfield_for_foreignkey(db_field, request, **kwargs)
        if db_field.name == "tool":
            formfield.label_from_instance = lambda obj: f"{obj.title} ({obj.client_id})"
        return formfield
