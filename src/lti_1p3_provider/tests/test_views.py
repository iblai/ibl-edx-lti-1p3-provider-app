"""
Tests for LTI views.
"""
from __future__ import annotations

from datetime import timedelta
from unittest import mock
from urllib import parse

import jwt
import pytest
from bs4 import BeautifulSoup
from crum import CurrentRequestUserMiddleware
from django.conf import settings
from django.contrib.auth.models import AnonymousUser
from django.contrib.sessions.middleware import SessionMiddleware
from django.http import Http404, HttpResponse
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone

from lti_1p3_provider.models import LtiGradedResource, LtiProfile
from lti_1p3_provider.session_access import LTI_SESSION_KEY
from lti_1p3_provider.views import DisplayTargetResource

from . import factories, fakes
from .base import URL_LIB_LTI_JWKS


def _get_target_link_uri(
    course_id=str(factories.COURSE_KEY),
    usage_id=str(factories.USAGE_KEY),
    domain="http://localhost",
) -> str:
    """Return tool launch url for course_id, usage_id"""
    kwargs = {"course_id": course_id, "usage_id": usage_id}
    endpoint = reverse("lti_1p3_provider:lti-display", kwargs=kwargs)
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
        target_link_uri = _get_target_link_uri(
            str(factories.COURSE_KEY), str(factories.USAGE_KEY)
        )
        assert target_link_uri == qps_in["target_link_uri"]
        assert qps["redirect_uri"] == [
            f'http://testserver{reverse("lti_1p3_provider:lti-launch")}'
        ]

        # Just make sure these aren't empty
        assert qps["state"]
        assert qps["nonce"]

        assert resp.status_code == 302

    def test_get_unknown_issuer_returns_400(self, client):
        """If issuer is unknown, returns a 400"""
        qps_in = factories.OidcLoginFactory()

        resp = client.get(self.endpoint, qps_in)

        soup = BeautifulSoup(resp.content, "html.parser")
        assert soup.find("h1").text == "Invalid LTI Login Request"
        assert resp.status_code == 400

    def test_post_unknown_issuer_returns_400_post(self, client):
        """If issuer is unknown, returns a 400

        This tests the _get_launch_params POST path
        """
        qps_in = factories.OidcLoginFactory()

        resp = client.post(self.endpoint, data=qps_in)

        soup = BeautifulSoup(resp.content, "html.parser")
        assert soup.find("h1").text == "Invalid LTI Login Request"
        assert resp.status_code == 400

    def test_missing_issuer_returns_400(self, client):
        """If issuer is missing, returns a 400"""
        qps_in = factories.OidcLoginFactory()
        qps_in.pop("iss")

        resp = client.get(self.endpoint, qps_in)

        soup = BeautifulSoup(resp.content, "html.parser")
        assert soup.find("h1").text == "Invalid LTI Login Request"
        assert resp.status_code == 400


@pytest.mark.django_db
@pytest.mark.usefixtures("enable_lti_provider")
@mock.patch(
    "pylti1p3.contrib.django.message_launch.DjangoSessionService",
    new=fakes.FakeDjangoSessionService,
)
class TestLtiToolLaunchView:
    launch_endpoint = reverse("lti_1p3_provider:lti-launch")

    def setup_method(self):
        self.tool = factories.LtiToolFactory()
        self.kid = self.tool.to_dict()["key_set"]["keys"][0]["kid"]

    def _get_payload(
        self,
        course_key,
        usage_key,
        key=factories.PLATFORM_PRIVATE_KEY,
        lineitem=None,
        target_link_uri=None,
        return_url=None,
    ) -> dict:
        """Generate and return payload with encoded id_token"""
        if target_link_uri is None:
            target_link_uri = _get_target_link_uri(str(course_key), str(usage_key))
        id_token = factories.IdTokenFactory(
            aud=self.tool.client_id,
            nonce="nonce",
            target_link_uri=target_link_uri,
            lineitem=lineitem,
            return_url=return_url,
        )
        encoded = _encode_platform_jwt(id_token, self.kid, key=key)
        return {"state": "state", "id_token": encoded}

    def test_lti_provider_disabled_returns_404(self, client):
        """When ENABLE_LTI_1P3_PROVIDER is False, a 404 is returned"""
        factories.LtiToolFactory()
        payload = self._get_payload(factories.COURSE_KEY, factories.USAGE_KEY)
        with override_features(ENABLE_LTI_1P3_PROVIDER=False):
            resp = client.post(self.launch_endpoint, payload)

        assert resp.status_code == 404

    def test_successful_launch(self, client):
        payload = self._get_payload(factories.COURSE_KEY, factories.USAGE_KEY)

        resp = client.post(self.launch_endpoint, payload)

        assert resp.status_code == 302
        redirect_uri = reverse(
            "lti_1p3_provider:lti-display",
            kwargs={
                "course_id": str(factories.COURSE_KEY),
                "usage_id": str(factories.USAGE_KEY),
            },
        )
        assert resp.url == f"http://localhost{redirect_uri}"

    def test_missing_course_id_in_target_link_uri_returns_400(self, client):
        """If the course_id missing in target_link_uri, 400 is returned"""
        base = reverse("lti_1p3_provider:lti-launch")
        target_link_uri = f"{base}/{str(factories.USAGE_KEY)}"
        payload = self._get_payload("", "", target_link_uri=target_link_uri)

        resp = client.post(self.launch_endpoint, payload)

        soup = BeautifulSoup(resp.content, "html.parser")
        assert soup.find("h1").text == "Invalid LTI Tool Launch"
        assert resp.status_code == 400

    def test_missing_usage_id_in_target_link_uri_returns_400(self, client):
        """If the usage_id missing in target_link_uri, 400 is returned"""
        base = reverse("lti_1p3_provider:lti-launch")
        target_link_uri = f"{base}/{str(factories.COURSE_KEY)}"
        payload = self._get_payload("", "", target_link_uri=target_link_uri)

        resp = client.post(self.launch_endpoint, payload)

        soup = BeautifulSoup(resp.content, "html.parser")
        assert soup.find("h1").text == "Invalid LTI Tool Launch"
        assert resp.status_code == 400

    def test_get_at_launch_endpoint_returns_405(self, client):
        """If GET to launch endpoint, 405 is returned"""
        launch_endpoint = reverse("lti_1p3_provider:lti-launch")
        resp = client.get(launch_endpoint)

        soup = BeautifulSoup(resp.content, "html.parser")
        assert soup.find("h1").text == "This page cannot be accessed directly"
        assert resp.status_code == 405

    def test_wrong_target_link_uri_path_returns_400(self, client):
        """If the path in target_link_uri doesn't match launchurl, 400 is returned"""
        path = "/some/other/path/"
        qs = {
            "course_id": str(factories.COURSE_KEY),
            "usage_id": str(factories.USAGE_KEY),
        }
        target_link_uri = f"https://localhost{path}?{parse.urlencode(qs)}"
        payload = self._get_payload(
            factories.COURSE_KEY, factories.USAGE_KEY, target_link_uri=target_link_uri
        )

        resp = client.post(self.launch_endpoint, payload)

        soup = BeautifulSoup(resp.content, "html.parser")
        assert soup.find("h1").text == "Invalid LTI Tool Launch"
        assert resp.status_code == 400

    def test_malformed_course_key_returns_400(self, client):
        """If course key is malformed, returns a 400"""
        base = reverse("lti_1p3_provider:lti-launch")
        target_link_uri = f"{base}course-v1:course1/{str(factories.USAGE_KEY)}"
        payload = self._get_payload("", "", target_link_uri=target_link_uri)

        resp = client.post(self.launch_endpoint, payload)

        soup = BeautifulSoup(resp.content, "html.parser")
        assert soup.find("h1").text == "Invalid LTI Tool Launch"
        assert resp.status_code == 400

    def test_malformed_usage_key_returns_400(self, client):
        """If usage key is malformed, returns a 400"""
        base = reverse("lti_1p3_provider:lti-launch")
        target_link_uri = (
            f"{base}{str(factories.COURSE_KEY)}/block-v1:org1+course1+run1"
        )
        payload = self._get_payload("", "", target_link_uri=target_link_uri)

        resp = client.post(self.launch_endpoint, payload)

        soup = BeautifulSoup(resp.content, "html.parser")
        assert soup.find("h1").text == "Invalid LTI Tool Launch"
        assert resp.status_code == 400

    @pytest.mark.parametrize("key", ("iss", "aud", "sub"))
    def test_missing_iss_aud_sub_returns_400(self, key, client):
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

        resp = client.post(self.launch_endpoint, payload)

        soup = BeautifulSoup(resp.content, "html.parser")
        assert soup.find("h1").text == "Invalid LTI Tool Launch"
        assert resp.status_code == 400

    def test_wrong_pub_key_returns_400(self, client):
        """Test unable to decode returns 400"""
        # Encoding w/ tool's private key but will try to decode w/ platforms pub key
        payload = self._get_payload(
            factories.COURSE_KEY, factories.USAGE_KEY, key=factories.TOOL_PRIVATE_KEY
        )

        resp = client.post(self.launch_endpoint, payload)

        soup = BeautifulSoup(resp.content, "html.parser")
        assert soup.find("h1").text == "Invalid LTI Tool Launch"
        assert resp.status_code == 400

    @mock.patch("lti_1p3_provider.views.authenticate")
    def test_when_authenticate_fails_returns_400(self, mock_auth, client):
        """If authenticate fails, a 400 is returns"""
        mock_auth.return_value = None
        payload = self._get_payload(factories.COURSE_KEY, factories.USAGE_KEY)

        resp = client.post(self.launch_endpoint, payload)

        assert resp.content == b"Invalid LTI tool launch."
        assert resp.status_code == 400

    @pytest.mark.parametrize(
        "has_lineitem",
        (False, True),
    )
    def test_handle_ags_missing_scopes_doesnt_create_graded_resource(
        self, has_lineitem, client
    ):
        """If missing one of the required scopes, graded resource is not created

        Currently only score is required
        """
        ags = factories.LtiAgsFactory(
            has_score_scope=False,
            has_lineitem_scope=has_lineitem,
            has_result_scope=False,
        )
        payload = self._get_payload(
            factories.COURSE_KEY, factories.USAGE_KEY, lineitem=ags
        )

        resp = client.post(self.launch_endpoint, payload)

        assert LtiGradedResource.objects.count() == 0
        assert resp.status_code == 302
        redirect_uri = reverse(
            "lti_1p3_provider:lti-display",
            kwargs={
                "course_id": str(factories.COURSE_KEY),
                "usage_id": str(factories.USAGE_KEY),
            },
        )
        assert resp.url == f"http://localhost{redirect_uri}"

    def test_handle_ags_no_lineitem_doesnt_create_graded_resource(
        self, client
    ):
        """If no lineitem claim exists , no graded resource is created"""
        ags = factories.LtiAgsFactory()
        ags.pop("lineitem")
        payload = self._get_payload(
            factories.COURSE_KEY, factories.USAGE_KEY, lineitem=ags
        )

        resp = client.post(self.launch_endpoint, payload)

        assert LtiGradedResource.objects.count() == 0
        assert resp.status_code == 302
        redirect_uri = reverse(
            "lti_1p3_provider:lti-display",
            kwargs={
                "course_id": str(factories.COURSE_KEY),
                "usage_id": str(factories.USAGE_KEY),
            },
        )
        assert resp.url == f"http://localhost{redirect_uri}"

    def test_handle_ags_graded_resource_created(self, client):
        """If lineitem claim exists, graded resource is created"""
        ags = factories.LtiAgsFactory()
        payload = self._get_payload(
            factories.COURSE_KEY, factories.USAGE_KEY, lineitem=ags
        )

        resp = client.post(self.launch_endpoint, payload)

        assert LtiGradedResource.objects.count() == 1
        resource = LtiGradedResource.objects.first()
        assert resource.profile == LtiProfile.objects.first()
        assert resource.course_key == factories.COURSE_KEY
        assert resource.usage_key == factories.USAGE_KEY
        assert resource.resource_id == "some-link-id"
        assert resource.resource_title == "Resource Title"
        assert resource.ags_lineitem == ags["lineitem"]
        assert resource.version_number == 0
        assert resp.status_code == 302
        redirect_uri = reverse(
            "lti_1p3_provider:lti-display",
            kwargs={
                "course_id": str(factories.COURSE_KEY),
                "usage_id": str(factories.USAGE_KEY),
            },
        )
        assert resp.url == f"http://localhost{redirect_uri}"

    def test_get_returns_405_with_error_template(self, client):
        """A GET to the launch endpoint returns a 405 with the error template"""
        endpoint = reverse("lti_1p3_provider:lti-launch")

        resp = client.get(endpoint)

        soup = BeautifulSoup(resp.content, "html.parser")
        assert soup.find("h1").text == "This page cannot be accessed directly"
        assert resp.status_code == 405

    def test_error_returned_via_lti_return_url_with_error_log(self, client):
        """Error returned via return_url w/ errorlog (when specified)"""
        base = reverse("lti_1p3_provider:lti-launch")
        # Invalid usage key so it will return an error w/ errorlog
        target_link_uri = (
            f"{base}{str(factories.COURSE_KEY)}/block-v1:org1+course1+run1"
        )
        return_url = "https://endpoint.com/return_url?item=123"
        payload = self._get_payload(
            "", "", target_link_uri=target_link_uri, return_url=return_url
        )

        resp = client.post(self.launch_endpoint, payload)

        assert resp.status_code == 302
        url_parts = parse.urlparse(resp.url)
        assert url_parts.scheme == "https"
        assert url_parts.netloc == "endpoint.com"
        assert url_parts.path == "/return_url"
        query_parts = parse.parse_qs(url_parts.query)
        assert query_parts == {
            "item": ["123"],
            "lti_errormsg": [
                "Invalid LTI Tool Launch: Please contact your technical support for "
                "additional assistance"
            ],
            "lti_errorlog": ["Invalid course_id or usage_id in target link uri"],
        }


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


class

@pytest.mark.django_db
@pytest.mark.usefixtures("enable_lti_provider")
class TestDisplayTargetResourceView:
    endpoint = reverse(
        "lti_1p3_provider:lti-display",
        kwargs={
            "course_id": str(factories.COURSE_KEY),
            "usage_id": str(factories.USAGE_KEY),
        },
    )

    def _setup_session(self, request) -> None:
        """Setup the session for the request"""
        SessionMiddleware(lambda r: None).process_request(request)
        request.session.save()

    def _setup_user(self, request) -> None:
        """Create and add a user to the request"""
        profile = factories.LtiProfileFactory()
        request.user = profile.user

    def _get_expiration(self, is_expired: bool = False) -> str:
        """Return an expiration that may or may not be expired"""
        now = timezone.now()
        if is_expired:
            return (now - timedelta(minutes=1)).isoformat()
        return (now + timedelta(hours=1)).isoformat()

    def _setup_good_request(self, rf):
        """Return a properly setup request"""
        request = rf.get(
            self.endpoint,
            course_key=factories.COURSE_KEY,
            usage_key=factories.USAGE_KEY,
        )
        self._setup_user(request)
        self._setup_session(request)
        # NOTE: Required when b/c edx mako templates uses CRUM to get current request
        CurrentRequestUserMiddleware(lambda x: None).process_request(request)
        return request

    def test_successfully_renders_content(self, rf):
        """When user has proper, unexpired session access, content is rendered"""
        request = self._setup_good_request(rf)
        request.session[LTI_SESSION_KEY] = {self.endpoint: self._get_expiration()}
        request.session.save()

        resp = DisplayTargetResource.as_view()(
            request,
            course_id=str(factories.COURSE_KEY),
            usage_id=str(factories.USAGE_KEY),
        )

        assert resp.status_code == 200

    @mock.patch("lti_1p3_provider.views.render_courseware")
    def test_target_link_uri_content_dne_returns_404(self, mock_courseware, rf):
        """Courseware at target_link_uri cannot be found returns a 404"""
        mock_courseware.side_effect = Http404()
        request = self._setup_good_request(rf)
        request.session[LTI_SESSION_KEY] = {self.endpoint: self._get_expiration()}
        request.session.save()

        resp = DisplayTargetResource.as_view()(
            request,
            course_id=str(factories.COURSE_KEY),
            usage_id=str(factories.USAGE_KEY),
        )

        soup = BeautifulSoup(resp.content, "html.parser")
        assert soup.find("h1").text == "Content Not Found"
        assert resp.status_code == 404

    def test_no_lti_access_in_session_returns_401(self, rf):
        """If lti_access key not in session, returns a 401"""
        request = self._setup_good_request(rf)

        resp = DisplayTargetResource.as_view()(
            request,
            course_id=str(factories.COURSE_KEY),
            usage_id=str(factories.USAGE_KEY),
        )

        soup = BeautifulSoup(resp.content, "html.parser")
        assert soup.find("h1").text == "Invalid or Expired Session"
        assert resp.status_code == 401

    def test_missing_target_link_uri_in_lti_session_returns_401(self, rf):
        """If target_link_uri is missing from lti_session, 401 returned"""
        request = self._setup_good_request(rf)
        # lti session key exists, but target_link_uri does not
        request.session[LTI_SESSION_KEY] = {}

        resp = DisplayTargetResource.as_view()(
            request,
            course_id=str(factories.COURSE_KEY),
            usage_id=str(factories.USAGE_KEY),
        )

        soup = BeautifulSoup(resp.content, "html.parser")
        assert soup.find("h1").text == "Invalid or Expired Session"
        assert resp.status_code == 401

    def test_expired_session_returns_401(self, rf):
        """If target_link_uri exists and expiration is past due, 401 returned"""
        request = self._setup_good_request(rf)
        request.session[LTI_SESSION_KEY] = {
            self.endpoint: self._get_expiration(is_expired=True)
        }
        request.session.save()

        resp = DisplayTargetResource.as_view()(
            request,
            course_id=str(factories.COURSE_KEY),
            usage_id=str(factories.USAGE_KEY),
        )

        soup = BeautifulSoup(resp.content, "html.parser")
        assert soup.find("h1").text == "Session Expired"
        assert resp.status_code == 401

    def test_user_isnt_logged_in_returns_302(self, rf):
        """If user isn't logged in, a 302 is returned - user redirected to login"""
        request = self._setup_good_request(rf)
        # Override user w/ an anonymous one (not logged in)
        request.user = AnonymousUser()

        resp = DisplayTargetResource.as_view()(
            request,
            course_id=str(factories.COURSE_KEY),
            usage_id=str(factories.USAGE_KEY),
        )

        assert resp.status_code == 302
        url_parts = parse.urlparse(resp.url)
        assert url_parts.path == "/login"
