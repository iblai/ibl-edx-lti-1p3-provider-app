"""
Tests for LTI views.
"""

from django.conf import settings
from django.test import TestCase, override_settings

from .base import URL_LIB_LTI_JWKS
import pytest


def override_features(**kwargs):
    """
    Wrapps ``override_settings`` to override ``settings.FEATURES``.
    """
    return override_settings(FEATURES={**settings.FEATURES, **kwargs})


class LtiToolJwksViewTest(TestCase):
    """
    Test JWKS view.
    """

    @pytest.mark.skip("webpack-stats.json missing ...")
    @override_features(ENABLE_LTI_1P3_PROVIDER=False)
    def test_when_lti_disabled_return_404(self):
        """
        Given LTI toggle is disabled
        When JWKS requested
        Then return 404

        Possible Solution:
        - https://discuss.overhang.io/t/missing-webpack-stats-json-when-pointing-to-local-discovery-platform/569
        - https://github.com/overhangio/tutor-discovery/blob/master/README.rst#debugging
        """
        response = self.client.get(URL_LIB_LTI_JWKS)
        self.assertEqual(response.status_code, 404)

    @override_features(ENABLE_LTI_1P3_PROVIDER=True)
    def test_when_no_keys_then_return_empty(self):
        """
        Given no LTI tool in the database.
        When JWKS requested.
        Then return empty
        """
        response = self.client.get(URL_LIB_LTI_JWKS)
        self.assertEqual(response.status_code, 200)
        self.assertJSONEqual(response.content, '{"keys": []}')
