"""
Tests for LTI views.
"""

from urllib import parse

import pytest
from django.conf import settings
from django.test import TestCase, override_settings
from django.urls import reverse

from . import factories
from .base import URL_LIB_LTI_JWKS


def override_features(**kwargs):
    """
    Wrapps ``override_settings`` to override ``settings.FEATURES``.
    """
    return override_settings(FEATURES={**settings.FEATURES, **kwargs})


@pytest.fixture
def enable_lti_provider():
    """Enables the Lti 1.3 Provider"""
    with override_features(ENABLE_LTI_1P3_PROVIDER=True):
        yield


@pytest.mark.django_db
@pytest.mark.usefixtures("enable_lti_provider")
class TestLtiToolLoginView:
    endpoint = reverse("lti_1p3_provider:lti-login")

    @pytest.mark.parametrize("method", ("get", "post"))
    def test_successful_login_init_returns_302(self, method, client):
        """Test successful login init returns 302 for GET or POST"""
        tool = factories.LtiToolFactory()
        qps_in = factories.OidcLoginFactory()

        resp = getattr(client, method)(self.endpoint, qps_in)

        parsed = parse.urlparse(resp.url)
        qps = parse.parse_qs(parsed.query)
        assert qps["scope"] == ["openid"]
        assert qps["response_type"] == ["id_token"]
        assert qps["response_mode"] == ["form_post"]
        assert qps["prompt"] == ["none"]
        assert qps["client_id"] == [tool.client_id]
        assert qps["login_hint"] == [qps_in["login_hint"]]
        assert qps["redirect_uri"] == [qps_in["target_link_uri"]]

        # Just make sure these aren't empty
        assert qps["state"]
        assert qps["nonce"]

        assert resp.status_code == 302

    def test_unknown_issuer_returns_400(self, client):
        """If issuer is unknown, returns a 400"""
        qps_in = factories.OidcLoginFactory()

        resp = client.get(self.endpoint, qps_in)

        assert resp.content == b"Invalid LTI login request."
        assert resp.status_code == 400

    def test_missing_issuer_returns_400(self, client):
        """If issuer is missing, returns a 400"""
        qps_in = factories.OidcLoginFactory()
        qps_in.pop("iss")

        resp = client.get(self.endpoint, qps_in)

        assert resp.content == b"Invalid LTI login request."
        assert resp.status_code == 400


@pytest.mark.django_db
class TestLtiToolJwksViewTest:
    """
    Test JWKS view.
    """

    @pytest.mark.skip("webpack-stats.json missing ...")
    @override_features(ENABLE_LTI_1P3_PROVIDER=False)
    def test_when_lti_disabled_return_404(self, client):
        """
        Given LTI toggle is disabled
        When JWKS requested
        Then return 404

        Possible Solution:
        - https://discuss.overhang.io/t/missing-webpack-stats-json-when-pointing-to-local-discovery-platform/569
        - https://github.com/overhangio/tutor-discovery/blob/master/README.rst#debugging
        """
        response = client.get(URL_LIB_LTI_JWKS)
        assert response.status_code == 404

    @override_features(ENABLE_LTI_1P3_PROVIDER=True)
    def test_when_no_keys_then_return_empty(self, client):
        """
        Given no LTI tool in the database.
        When JWKS requested.
        Then return empty
        """
        response = client.get(URL_LIB_LTI_JWKS)
        assert response.status_code == 200
        assert response.json() == {"keys": []}
