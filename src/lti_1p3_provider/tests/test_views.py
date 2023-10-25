"""
Tests for LTI views.
"""
from __future__ import annotations

from unittest import mock
from urllib import parse

import jwt
import pytest
from django.conf import settings
from django.http import HttpResponse
from django.test import override_settings
from django.urls import reverse

from lti_1p3_provider.models import LtiGradedResource, LtiProfile

from . import factories, fakes
from .base import URL_LIB_LTI_JWKS


def _get_target_link_uri(course_id, usage_id, domain="https://localhost") -> str:
    """Return tool launch url for course_id, usage_id"""
    endpoint = reverse(
        "lti_1p3_provider:lti-launch",
        kwargs={"course_id": course_id, "usage_id": usage_id},
    )
    return f"{domain}{endpoint}"


def _encode_platform_jwt(
    data: dict, kid: str, key=factories.PLATFORM_PRIVATE_KEY
) -> str:
    """Encode JWT"""
    return jwt.encode(data, key=key, algorithm="RS256", headers={"kid": kid})


def override_features(**kwargs):
    """
    Wrapps ``override_settings`` to override ``settings.FEATURES``.
    """
    return override_settings(FEATURES={**settings.FEATURES, **kwargs})


@pytest.fixture
def enable_lti_provider():
    """Enables the Lti 1.3 Provider"""
    backends = settings.AUTHENTICATION_BACKENDS
    backends.append("lti_1p3_provider.auth.Lti1p3AuthenticationBackend")

    with override_features(ENABLE_LTI_1P3_PROVIDER=True):
        with override_settings(AUTHENTICATION_BACKENDS=backends):
            yield


@pytest.mark.django_db
@pytest.mark.usefixtures("enable_lti_provider")
class TestLtiToolLoginView:
    endpoint = reverse("lti_1p3_provider:lti-login")

    def test_lti_provider_disabled_returns_404(self, client):
        """When ENABLE_LTI_1P3_PROVIDER is False, a 404 is returned"""
        factories.LtiToolFactory()
        qps_in = factories.OidcLoginFactory()
        with override_features(ENABLE_LTI_1P3_PROVIDER=False):
            resp = client.get(self.endpoint, qps_in)

        assert resp.status_code == 404

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
@pytest.mark.usefixtures("enable_lti_provider")
@mock.patch(
    "pylti1p3.contrib.django.message_launch.DjangoSessionService",
    new=fakes.FakeDjangoSessionService,
)
class TestLtiToolLaunchView:
    login_endpoint = reverse("lti_1p3_provider:lti-login")

    def setup_method(self):
        self.tool = factories.LtiToolFactory()
        self.kid = self.tool.to_dict()["key_set"]["keys"][0]["kid"]

    def _get_launch_endpoint(self, course_id: str, usage_id: str) -> str:
        return reverse(
            "lti_1p3_provider:lti-launch",
            kwargs={"course_id": course_id, "usage_id": usage_id},
        )

    def _get_payload(
        self,
        course_key,
        usage_key,
        key=factories.PLATFORM_PRIVATE_KEY,
        lineitem=None,
    ) -> dict:
        """Generate and return payload with encoded id_token"""
        target_link_uri = _get_target_link_uri(str(course_key), str(usage_key))
        id_token = factories.IdTokenFactory(
            aud=self.tool.client_id,
            nonce="nonce",
            target_link_uri=target_link_uri,
            lineitem=lineitem,
        )
        encoded = _encode_platform_jwt(id_token, self.kid, key=key)
        return {"state": "state", "id_token": encoded}

    def test_lti_provider_disabled_returns_404(self, client):
        """When ENABLE_LTI_1P3_PROVIDER is False, a 404 is returned"""
        factories.LtiToolFactory()
        endpoint = self._get_launch_endpoint(
            str(factories.COURSE_KEY), str(factories.USAGE_KEY)
        )
        payload = self._get_payload(factories.COURSE_KEY, factories.USAGE_KEY)
        with override_features(ENABLE_LTI_1P3_PROVIDER=False):
            resp = client.post(endpoint, payload)

        assert resp.status_code == 404

    @mock.patch("lti_1p3_provider.views.render_courseware")
    def test_successful_launch(self, mock_courseware, client):
        mock_courseware.return_value = HttpResponse(status=200)
        endpoint = self._get_launch_endpoint(
            str(factories.COURSE_KEY), str(factories.USAGE_KEY)
        )
        payload = self._get_payload(factories.COURSE_KEY, factories.USAGE_KEY)

        resp = client.post(endpoint, payload)

        assert resp.status_code == 200

    def test_unknown_course_key_returns_404(self, client):
        """If the course/usage_key is unknown, 404 is returned"""
        endpoint = self._get_launch_endpoint(
            str(factories.COURSE_KEY), str(factories.USAGE_KEY)
        )
        payload = self._get_payload(factories.COURSE_KEY, factories.USAGE_KEY)

        resp = client.post(endpoint, payload)

        assert resp.content == b"Course not found: course-v1:Org1+Course1+Run1."
        assert resp.status_code == 404

    def test_malformed_course_key_returns_400(self, client):
        """If course key is malformed, returns a 400"""
        endpoint = self._get_launch_endpoint(
            "course-v1:not+a+valid+course", str(factories.USAGE_KEY)
        )
        payload = self._get_payload(factories.COURSE_KEY, factories.USAGE_KEY)

        resp = client.post(endpoint, payload)

        assert resp.content.decode("utf-8").startswith("Invalid Course or Key:")
        assert resp.status_code == 400

    def test_malformed_usage_key_returns_400(self, client):
        """If usage key is malformed, returns a 400"""
        endpoint = self._get_launch_endpoint(
            str(factories.COURSE_KEY), "block-v1:not+the+right+type@something-format"
        )
        payload = self._get_payload(factories.COURSE_KEY, factories.USAGE_KEY)

        resp = client.post(endpoint, payload)

        assert resp.content.decode("utf-8").startswith("Invalid Course or Key:")
        assert resp.status_code == 400

    @pytest.mark.parametrize("key", ("iss", "aud", "sub"))
    def test_missing_iss_aud_sub_returns_400(self, key, client):
        endpoint = self._get_launch_endpoint(
            str(factories.COURSE_KEY), str(factories.USAGE_KEY)
        )
        target_link_uri = _get_target_link_uri(
            str(factories.COURSE_KEY), str(factories.USAGE_KEY)
        )
        id_token = factories.IdTokenFactory(
            aud=self.tool.client_id,
            nonce="nonce",
            target_link_uri=target_link_uri,
        )
        id_token.pop(key)
        encoded = _encode_platform_jwt(id_token, self.kid)
        payload = {"state": "state", "id_token": encoded}

        resp = client.post(endpoint, payload)

        assert resp.content == b"Invalid LTI tool launch."
        assert resp.status_code == 400

    def test_wrong_pub_key_returns_400(self, client):
        """Test unable to decode returns 400"""
        endpoint = self._get_launch_endpoint(
            str(factories.COURSE_KEY), str(factories.USAGE_KEY)
        )
        # Encoding w/ tool's private key but will try to decode w/ platforms pub key
        payload = self._get_payload(
            factories.COURSE_KEY, factories.USAGE_KEY, key=factories.TOOL_PRIVATE_KEY
        )

        resp = client.post(endpoint, payload)

        assert resp.content == b"Invalid LTI tool launch."
        assert resp.status_code == 400

    @mock.patch("lti_1p3_provider.views.authenticate")
    def test_when_authenticate_fails_returns_400(self, mock_auth, client):
        """If authenticate fails, a 400 is returns"""
        mock_auth.return_value = None
        endpoint = self._get_launch_endpoint(
            str(factories.COURSE_KEY), str(factories.USAGE_KEY)
        )
        payload = self._get_payload(factories.COURSE_KEY, factories.USAGE_KEY)

        resp = client.post(endpoint, payload)

        assert resp.content == b"Invalid LTI tool launch."
        assert resp.status_code == 400

    @pytest.mark.parametrize(
        "has_lineitem",
        (False, True),
    )
    @mock.patch("lti_1p3_provider.views.render_courseware")
    def test_handle_ags_missing_scopes_doesnt_created_graded_resource(
        self, mock_courseware, has_lineitem, client
    ):
        """If missing one of the required scopes, graded resource is not created

        Currently only score is required
        """
        mock_courseware.return_value = HttpResponse(status=200)
        endpoint = self._get_launch_endpoint(
            str(factories.COURSE_KEY), str(factories.USAGE_KEY)
        )
        ags = factories.LtiAgsFactory(
            has_score_scope=False,
            has_lineitem_scope=has_lineitem,
            has_result_scope=False,
        )
        payload = self._get_payload(
            factories.COURSE_KEY, factories.USAGE_KEY, lineitem=ags
        )

        resp = client.post(endpoint, payload)

        assert LtiGradedResource.objects.count() == 0
        assert resp.status_code == 200

    @mock.patch("lti_1p3_provider.views.render_courseware")
    def test_handle_ags_no_lineitem_doesnt_create_graded_resource(
        self, mock_courseware, client
    ):
        """If no lineitem claim exists , no graded resource is created"""
        mock_courseware.return_value = HttpResponse(status=200)
        endpoint = self._get_launch_endpoint(
            str(factories.COURSE_KEY), str(factories.USAGE_KEY)
        )
        ags = factories.LtiAgsFactory()
        ags.pop("lineitem")
        payload = self._get_payload(
            factories.COURSE_KEY, factories.USAGE_KEY, lineitem=ags
        )

        resp = client.post(endpoint, payload)

        assert LtiGradedResource.objects.count() == 0
        assert resp.status_code == 200

    @mock.patch("lti_1p3_provider.views.render_courseware")
    def test_handle_ags_graded_resource_created(self, mock_courseware, client):
        """If no lineitem claim exists , no graded resource is created"""
        mock_courseware.return_value = HttpResponse(status=200)
        endpoint = self._get_launch_endpoint(
            str(factories.COURSE_KEY), str(factories.USAGE_KEY)
        )
        ags = factories.LtiAgsFactory()
        payload = self._get_payload(
            factories.COURSE_KEY, factories.USAGE_KEY, lineitem=ags
        )

        resp = client.post(endpoint, payload)

        assert LtiGradedResource.objects.count() == 1
        resource = LtiGradedResource.objects.first()
        assert resource.profile == LtiProfile.objects.first()
        assert resource.course_key == factories.COURSE_KEY
        assert resource.usage_key == factories.USAGE_KEY
        assert resource.resource_id == "some-link-id"
        assert resource.resource_title == "Resource Title"
        assert resource.ags_lineitem == ags["lineitem"]
        assert resource.version_number == 0
        assert resp.status_code == 200

    def test_get_returns_405_with_error_template(self, client):
        """A GET to the launch endpoint returns a 405 with the error template"""
        endpoint = self._get_launch_endpoint(
            str(factories.COURSE_KEY), str(factories.USAGE_KEY)
        )

        resp = client.get(endpoint)

        assert (
            "Please relaunch your content from its original source to view it."
            in resp.text
        )
        assert resp.status_code == 405


@pytest.mark.django_db
class TestLtiToolJwksViewTest:
    """
    Test JWKS view.
    """

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
