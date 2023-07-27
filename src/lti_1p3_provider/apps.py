from django.apps import AppConfig


class Lti1p3ProviderConfig(AppConfig):
    """
    App Configuration for lti_1p3_provider
    """

    name = "lti_1p3_provider"
    verbose_name = "lti_1p3_provider"

    plugin_app = {
        "settings_config": {
            "lms.djangoapp": {
                "common": {
                    "relative_path": "settings.common",
                },
            },
            "cms.djangoapp": {
                "common": {
                    "relative_path": "settings.common",
                },
            },
        }
    }
