from __future__ import annotations

from django.contrib import admin

from . import models


@admin.register(models.LaunchGate)
class LaunchGateAdmin(admin.ModelAdmin):
    list_display = ("tool_name", "has_allowed_keys", "allowed_orgs")

    def has_allowed_keys(self, obj) -> bool:
        return bool(obj.allowed_keys)

    def tool_name(self, obj):
        return f"{obj.tool.title} ({obj.tool.client_id})"

    def formfield_for_foreignkey(self, db_field, request, **kwargs):
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
