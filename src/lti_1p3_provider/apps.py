from django.apps import AppConfig
from edx_django_utils.plugins import PluginSettings, PluginURLs
from openedx.core.djangoapps.plugins.constants import ProjectType, SettingsType


class Lti1p3ProviderConfig(AppConfig):
    """
    App Configuration for lti_1p3_provider
    """

    name = "lti_1p3_provider"
    verbose_name = "lti_1p3_providers"

    plugin_app = {
        PluginSettings.CONFIG: {
            ProjectType.LMS: {
                SettingsType.COMMON: {
                    PluginSettings.RELATIVE_PATH: "settings.common",
                },
            },
        },
        PluginURLs.CONFIG: {
            ProjectType.LMS: {
                PluginURLs.NAMESPACE: "lti_1p3_provider",
                PluginURLs.REGEX: "^lti/1p3/",
                PluginURLs.RELATIVE_PATH: "urls",
            }
        },
    }
