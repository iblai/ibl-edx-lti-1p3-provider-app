from django.contrib import admin

from . import models

@admin.register(models.LtiProfile)
class LtiProfileAdmin(admin.ModelAdmin):
    pass

@admin.register(models.LtiGradedResource)
class LtiPGradedResourceAdmin(admin.ModelAdmin):
    pass
