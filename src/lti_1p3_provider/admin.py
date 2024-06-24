from django.contrib import admin

from . import models


@admin.register(models.LaunchGate)
class LaunchGateAdmin(admin.ModelAdmin):
    list_display = ("lti_tool__client_id",)


@admin.register(models.LtiProfile)
class LtiProfileAdmin(admin.ModelAdmin):
    pass


@admin.register(models.LtiGradedResource)
class LtiPGradedResourceAdmin(admin.ModelAdmin):
    pass
