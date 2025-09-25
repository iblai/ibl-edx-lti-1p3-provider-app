"""
Tests for LTI views.
"""

from __future__ import annotations

import json
from datetime import timedelta
from unittest import mock
from urllib import parse

import jwt
import pytest
from bs4 import BeautifulSoup
from common.djangoapps.student.tests.factories import UserProfileFactory
from crum import CurrentRequestUserMiddleware
from django.conf import settings
from django.contrib.auth.models import AnonymousUser
from django.contrib.sessions.middleware import SessionMiddleware
from django.http import Http404, HttpResponse
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from organizations.tests.factories import OrganizationFactory
from pylti1p3.registration import Registration

from lti_1p3_provider.api.ssl_services import (
    generate_private_key_pem,
    priv_to_public_key_pem,
)
from lti_1p3_provider.error_response import (
    MISSING_SESSION_COOKIE_ERR_MSG,
    get_contact_support_msg,
)
from lti_1p3_provider.models import EDX_LTI_EMAIL_DOMAIN, LtiGradedResource, LtiProfile
from lti_1p3_provider.session_access import LTI_SESSION_KEY
from lti_1p3_provider.tests import factories, fakes
from lti_1p3_provider.tests.base import URL_LIB_LTI_JWKS
from lti_1p3_provider.views import (
    LTI_1P3_EMAIL_META_KEY,
    DisplayTargetResource,
    LtiToolLaunchView,
)


@pytest.fixture(autouse=True)
def override_lms_base():
    """Override LMS_BASE for the duration of the test"""
    with override_settings(LMS_BASE="localhost"):
        yield


def _get_session_middleware():
    """Get Initialized SessionMiddleware"""
    return SessionMiddleware(lambda r: None)


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


@pytest.fixture(autouse=True)
def enable_lti_provider():
    """Enables the Lti 1.3 Provider"""
    backends = settings.AUTHENTICATION_BACKENDS
    backends.append("lti_1p3_provider.auth.Lti1p3AuthenticationBackend")

    with override_features(ENABLE_LTI_1P3_PROVIDER=True):
        with override_settings(AUTHENTICATION_BACKENDS=backends):
            yield


@pytest.mark.django_db
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
            f"http://testserver{reverse('lti_1p3_provider:lti-launch')}"
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
@mock.patch(
    "pylti1p3.contrib.django.message_launch.DjangoSessionService",
    new=fakes.FakeDjangoSessionService,
)
class TestLtiBasicLaunch:
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

    def test_successful_launch_with_email_sets_email_in_profile(self, client):
        """If email claim provided, sets it in the LtiProfile and UserProfile

        User does not yet exist, so User, LtiProfile, and UserProfile are created
        """
        email = "test@example.com"
        target_link_uri = _get_target_link_uri(
            str(factories.COURSE_KEY), str(factories.USAGE_KEY)
        )
        id_token = factories.IdTokenFactory(
            aud=self.tool.client_id,
            nonce="nonce",
            target_link_uri=target_link_uri,
            email=email,
        )
        encoded = _encode_platform_jwt(id_token, self.kid)
        payload = {"state": "state", "id_token": encoded}

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
        lti_profile = LtiProfile.objects.get_from_claims(
            iss=id_token["iss"], aud=id_token["aud"], sub=id_token["sub"]
        )
        assert lti_profile.email == email
        assert lti_profile.user.profile.get_meta()[LTI_1P3_EMAIL_META_KEY] == email

    def test_successful_launch_with_email_null_is_allowed(self, client):
        """If email claim is null, it is allowed and the user gets a default email"""
        email = None
        target_link_uri = _get_target_link_uri(
            str(factories.COURSE_KEY), str(factories.USAGE_KEY)
        )
        id_token = factories.IdTokenFactory(
            aud=self.tool.client_id,
            nonce="nonce",
            target_link_uri=target_link_uri,
            email=email,
        )
        encoded = _encode_platform_jwt(id_token, self.kid)
        payload = {"state": "state", "id_token": encoded}

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
        lti_profile = LtiProfile.objects.get_from_claims(
            iss=id_token["iss"], aud=id_token["aud"], sub=id_token["sub"]
        )
        assert lti_profile.email == ""
        assert lti_profile.user.email.endswith(f"@{EDX_LTI_EMAIL_DOMAIN}")

    def test_existing_user_profile_with_no_email_gets_updated(self, client):
        """If email claim provided, updates the existing LtiProfile and UserProfile"""
        email = "test@example.com"
        payload = self._get_payload(factories.COURSE_KEY, factories.USAGE_KEY)
        target_link_uri = _get_target_link_uri(
            str(factories.COURSE_KEY), str(factories.USAGE_KEY)
        )
        # This id token has an email
        id_token = factories.IdTokenFactory(
            aud=self.tool.client_id,
            nonce="nonce",
            target_link_uri=target_link_uri,
            email="test@example.com",
        )
        encoded = _encode_platform_jwt(id_token, self.kid)
        payload = {"state": "state", "id_token": encoded}
        # Create a profile with no email
        lti_profile = LtiProfile.objects.get_or_create_from_claims(
            iss=id_token["iss"], aud=id_token["aud"], sub=id_token["sub"], email=""
        )
        # UserProfile exists, but has no email
        UserProfileFactory(user=lti_profile.user)

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
        fetched_profile = LtiProfile.objects.get_from_claims(
            iss=id_token["iss"], aud=id_token["aud"], sub=id_token["sub"]
        )
        assert fetched_profile == lti_profile
        assert fetched_profile.email == email
        assert fetched_profile.user.profile.get_meta()[LTI_1P3_EMAIL_META_KEY] == email

    def test_existing_user_profile_with_email_gets_updated(self, client):
        """If email claim provided, updates the existing LtiProfile and UserProfile

        User, LtiProfile, and UserProfile exist, and UserProfile has email set
        """
        email = "test@example.com"
        payload = self._get_payload(factories.COURSE_KEY, factories.USAGE_KEY)
        target_link_uri = _get_target_link_uri(
            str(factories.COURSE_KEY), str(factories.USAGE_KEY)
        )
        # This id token has an email
        id_token = factories.IdTokenFactory(
            aud=self.tool.client_id,
            nonce="nonce",
            target_link_uri=target_link_uri,
            email="test@example.com",
        )
        encoded = _encode_platform_jwt(id_token, self.kid)
        payload = {"state": "state", "id_token": encoded}
        # Create a profile with email already set
        lti_profile = LtiProfile.objects.get_or_create_from_claims(
            iss=id_token["iss"],
            aud=id_token["aud"],
            sub=id_token["sub"],
            email="already@set.com",
        )
        # UserProfile exists, and has email set
        user_profile = UserProfileFactory(
            user=lti_profile.user,
            meta=f'{{"{LTI_1P3_EMAIL_META_KEY}": "already@set.com"}}',
        )
        assert user_profile.get_meta()[LTI_1P3_EMAIL_META_KEY] == "already@set.com"

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
        fetched_profile = LtiProfile.objects.get_from_claims(
            iss=id_token["iss"], aud=id_token["aud"], sub=id_token["sub"]
        )
        assert fetched_profile == lti_profile
        assert fetched_profile.email == email
        assert fetched_profile.user.profile.get_meta()[LTI_1P3_EMAIL_META_KEY] == email

    def test_successful_launch_with_first_and_last_name_sets_them_on_user(self, client):
        """If first and last name claims provided, sets them on the User"""
        target_link_uri = _get_target_link_uri(
            str(factories.COURSE_KEY), str(factories.USAGE_KEY)
        )
        id_token = factories.IdTokenFactory(
            aud=self.tool.client_id,
            nonce="nonce",
            target_link_uri=target_link_uri,
            given_name="First",
            family_name="Last",
        )
        encoded = _encode_platform_jwt(id_token, self.kid)
        payload = {"state": "state", "id_token": encoded}

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
        lti_profile = LtiProfile.objects.get_from_claims(
            iss=id_token["iss"], aud=id_token["aud"], sub=id_token["sub"]
        )
        assert lti_profile.email == ""
        assert lti_profile.user.first_name == "First"
        assert lti_profile.user.last_name == "Last"
        assert lti_profile.user.profile.name == "First Last"

    def test_successful_launch_with_first_and_last_name_updates_when_exists(
        self, client
    ):
        """If first and last name claims provided, updates the existing User"""
        payload = self._get_payload(factories.COURSE_KEY, factories.USAGE_KEY)
        target_link_uri = _get_target_link_uri(
            str(factories.COURSE_KEY), str(factories.USAGE_KEY)
        )
        # This id token has an email
        id_token = factories.IdTokenFactory(
            aud=self.tool.client_id,
            nonce="nonce",
            target_link_uri=target_link_uri,
            given_name="First-new",
            family_name="Last-new",
        )
        encoded = _encode_platform_jwt(id_token, self.kid)
        payload = {"state": "state", "id_token": encoded}
        # Create a profile with email/first/last name already set
        lti_profile = LtiProfile.objects.get_or_create_from_claims(
            iss=id_token["iss"],
            aud=id_token["aud"],
            sub=id_token["sub"],
            email="already@set.com",
            first_name="First-old",
            last_name="Last-old",
        )
        user_profile = UserProfileFactory(user=lti_profile.user)
        assert user_profile.user.first_name == "First-old"
        assert user_profile.user.last_name == "Last-old"
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
        fetched_profile = LtiProfile.objects.get_from_claims(
            iss=id_token["iss"], aud=id_token["aud"], sub=id_token["sub"]
        )
        assert fetched_profile == lti_profile
        assert fetched_profile.user.first_name == "First-new"
        assert fetched_profile.user.last_name == "Last-new"
        assert fetched_profile.user.profile.name == "First-new Last-new"

    def test_successful_launch_no_gate(self, client):
        """Test successsful launch with no gate in place"""
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
        # Since no email in id_token, the profile should have no email
        fetched_profile = LtiProfile.objects.first()
        assert fetched_profile.email == ""
        assert LTI_1P3_EMAIL_META_KEY not in fetched_profile.user.profile.get_meta()

    def test_successful_launch_with_gate(self, client):
        """Test successful launch where target_link_uri is allowed by gate"""
        factories.LaunchGateFactory(
            tool=self.tool, allowed_orgs=[factories.USAGE_KEY.course_key.org]
        )
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

    def test_gated_content_returns_403(self, client):
        """If tool cannot access content due to a gate, 403 is returned"""
        factories.LaunchGateFactory(tool=self.tool)
        payload = self._get_payload(factories.COURSE_KEY, factories.USAGE_KEY)

        resp = client.post(self.launch_endpoint, payload)

        soup = BeautifulSoup(resp.content, "html.parser")
        assert soup.find("h1").text == "LTI Launch Gate Error"
        assert resp.status_code == 403

    @override_settings(
        CACHES={
            "default": {
                "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
                "LOCATION": "test-cache",
            }
        },
        CONTACT_EMAIL="test@override.com",
    )
    def test_missing_cookie_displays_custom_error(self, client):
        """If missing cookie, displays custom error"""
        # Enable an in memory cache
        payload = self._get_payload(factories.COURSE_KEY, factories.USAGE_KEY)

        resp = client.post(self.launch_endpoint, payload, secure=True)

        expected = (
            f"{MISSING_SESSION_COOKIE_ERR_MSG.strip('.')}. {get_contact_support_msg()}"
        )
        soup = BeautifulSoup(resp.content, "html.parser")
        assert soup.find("p").text == expected

        assert resp.status_code == 400

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

    def test_invalid_platform_pub_key_format_returns_500(self, client):
        """If pub key has an invalid format, a 500 is returned"""
        payload = self._get_payload(factories.COURSE_KEY, factories.USAGE_KEY)
        jwt = Registration.get_jwk(factories.PLATFORM_PUBLIC_KEY)
        # Make the key_set malformed
        jwt["n"] = jwt["n"][5:]
        self.tool.key_set = json.dumps({"keys": [jwt]})
        self.tool.save()

        resp = client.post(self.launch_endpoint, payload)

        soup = BeautifulSoup(resp.content, "html.parser")
        assert soup.find("h1").text == "Invalid LTI Tool Launch"
        assert soup.find("p").text.startswith("Invalid Platform Public Key")
        assert resp.status_code == 500

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

    def test_handle_ags_no_lineitem_doesnt_create_graded_resource(self, client):
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

    def test_error_returned_via_lti_return_url_with_error_msg(self, client):
        """Error returned via return_url w/ errormsg (when specified)"""
        base = reverse("lti_1p3_provider:lti-launch")
        # Invalid usage key so it will return an error w/ errormsg
        target_link_uri = f"https://localhost{base}{str(factories.COURSE_KEY)}/block-v1:org1+course1+run1"
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
                (
                    "Invalid LTI Tool Launch: Invalid course_id or usage_id in target "
                    f"link uri: {target_link_uri}"
                )
            ],
        }

    def test_session_exp_set_to_none(self, rf):
        """Session expiration is set to None by default"""
        target_link_uri = _get_target_link_uri()
        target_link_path = parse.urlparse(target_link_uri).path
        id_token = factories.IdTokenFactory(
            aud=self.tool.client_id,
            nonce="nonce",
            target_link_uri=target_link_uri,
        )
        encoded = _encode_platform_jwt(id_token, self.kid)
        payload = {"state": "state", "id_token": encoded}
        request = rf.post(self.launch_endpoint, data=payload)
        _get_session_middleware().process_request(request)
        request.session.save()

        LtiToolLaunchView.as_view()(request)

        assert request.session[LTI_SESSION_KEY][target_link_path] is None

    @override_settings(LTI_1P3_PROVIDER_ACCESS_LENGTH_SEC=100)
    def test_session_exp_set_to_settings_value(self, rf):
        """Session expiration is set to the override value when present"""
        target_link_uri = _get_target_link_uri()
        target_link_path = parse.urlparse(target_link_uri).path
        id_token = factories.IdTokenFactory(
            aud=self.tool.client_id,
            nonce="nonce",
            target_link_uri=target_link_uri,
        )
        encoded = _encode_platform_jwt(id_token, self.kid)
        payload = {"state": "state", "id_token": encoded}
        request = rf.post(self.launch_endpoint, data=payload)
        _get_session_middleware().process_request(request)
        request.session.save()
        now = timezone.now()

        # NOTE: Need to mock here b/c otherwise it gets overridden everywhere and
        # you can't save the session. Maybe a better way to do this?
        with mock.patch("lti_1p3_provider.views.timezone.now") as mock_now:
            mock_now.return_value = now
            LtiToolLaunchView.as_view()(request)

        expected = {target_link_path: (now + timedelta(seconds=100)).isoformat()}
        assert request.session[LTI_SESSION_KEY] == expected

    def test_user_can_have_multiple_active_lti_access_sessions(self, rf):
        """Multiple Sessions can be added to user's existing login"""
        course2 = "course-v1:Org+Course2+Run"
        target_link_uri_1 = _get_target_link_uri()
        target_link_path_1 = parse.urlparse(target_link_uri_1).path
        target_link_uri_2 = _get_target_link_uri(course_id=course2)
        target_link_path_2 = parse.urlparse(target_link_uri_2).path
        payload = self._get_payload(course2, factories.USAGE_KEY)
        request = rf.post(self.launch_endpoint, data=payload)
        _get_session_middleware().process_request(request)
        link_1_exp = timezone.now()
        request.session[LTI_SESSION_KEY] = {target_link_path_1: link_1_exp.isoformat()}
        request.session.save()

        LtiToolLaunchView.as_view()(request)

        assert request.session[LTI_SESSION_KEY].keys() == {
            target_link_path_1,
            target_link_path_2,
        }
        assert (
            request.session[LTI_SESSION_KEY][target_link_path_1]
            == link_1_exp.isoformat()
        )

    def test_target_link_uri_does_not_match_lms_domain_returns_400(self, client):
        """If target_link_uri domain doesn't match LMS_BASE, 400 is returned"""
        # Create a target_link_uri with a different domain
        target_link_uri = _get_target_link_uri(
            str(factories.COURSE_KEY),
            str(factories.USAGE_KEY),
            domain="https://different-domain.com",
        )
        payload = self._get_payload(
            factories.COURSE_KEY, factories.USAGE_KEY, target_link_uri=target_link_uri
        )

        resp = client.post(self.launch_endpoint, payload)

        soup = BeautifulSoup(resp.content, "html.parser")
        assert soup.find("h1").text == "Invalid LTI Tool Launch"
        assert soup.find("p").text.startswith(
            f"Invalid target_link_uri domain: {target_link_uri}"
        )
        assert resp.status_code == 400

    @override_settings(LMS_BASE="lms.local")
    @pytest.mark.parametrize(
        "endpoint_name,expected_error",
        [
            (
                "deep-link-launch",
                "Deep Linking Launch endpoint is not a valid target_link_uri for basic launches.",
            ),
            (
                "lti-launch",
                "LTI Launch endpoint is not a valid target_link_uri for basic launches.",
            ),
            (
                "lti-login",
                "Invalid target_link_uri: ",
            ),
        ],
    )
    def test_target_link_uri_does_not_match_lti_display_endpoint_returns_400(
        self, client, endpoint_name, expected_error
    ):
        """If target_link_uri points to wrong endpoint, 400 is returned with specific error"""
        # Create target_link_uri pointing to the wrong endpoint
        wrong_endpoint = reverse(f"lti_1p3_provider:{endpoint_name}")
        target_link_uri = f"http://lms.local{wrong_endpoint}"
        payload = self._get_payload(
            factories.COURSE_KEY, factories.USAGE_KEY, target_link_uri=target_link_uri
        )

        resp = client.post(self.launch_endpoint, payload)

        soup = BeautifulSoup(resp.content, "html.parser")
        assert soup.find("h1").text == "Invalid LTI Tool Launch"
        assert expected_error in soup.find("p").text
        assert resp.status_code == 400


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


@pytest.mark.django_db
class TestLtiOrgToolJwksViewTest:
    """
    Test JWKS view for specific Org only
    """

    @override_features(ENABLE_LTI_1P3_PROVIDER=True)
    def test_keys_returned_for_specified_org_only(self, client):
        """Returns keys only for specified org"""
        priv1 = generate_private_key_pem()
        pub1 = priv_to_public_key_pem(priv1)
        priv2 = generate_private_key_pem()
        pub2 = priv_to_public_key_pem(priv2)

        org1 = OrganizationFactory()
        org2 = OrganizationFactory()
        key1_org1 = factories.LtiKeyOrgFactory(
            org=org1, key__private_key=priv1, key__public_key=pub1
        )
        key2_org1 = factories.LtiKeyOrgFactory(
            org=org1, key__private_key=priv2, key__public_key=pub2
        )
        # This key will not be in the output
        key1_org2 = factories.LtiKeyOrgFactory(org=org2)
        endpoint = reverse(
            "lti_1p3_provider:lti-pub-org-jwks",
            kwargs={"org_short_name": org1.short_name},
        )

        response = client.get(endpoint)

        assert response.status_code == 200
        keys = response.json()["keys"]
        assert json.loads(key1_org1.key.public_jwk) in keys
        assert json.loads(key2_org1.key.public_jwk) in keys
        assert len(keys) == 2

    @override_features(ENABLE_LTI_1P3_PROVIDER=True)
    def test_no_keys_for_org_returns_empty_list(self, client):
        """Returns keys only for specified org"""

        org1 = OrganizationFactory()
        endpoint = reverse(
            "lti_1p3_provider:lti-pub-org-jwks",
            kwargs={"org_short_name": org1.short_name},
        )

        response = client.get(endpoint)

        assert response.status_code == 200
        keys = response.json()["keys"] == []


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
        _get_session_middleware().process_request(request)
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

    @mock.patch("lti_1p3_provider.views.render_courseware")
    def test_successfully_renders_content_with_exp_set(self, mock_courseware, rf):
        """When user has unexpired session access, content is rendered"""
        mock_courseware.return_value = HttpResponse(status=200)
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
    def test_successfully_renders_content_with_exp_as_none(self, mock_courseware, rf):
        """When user's expiration is None, allows access"""
        mock_courseware.return_value = HttpResponse(status=200)
        request = self._setup_good_request(rf)
        request.session[LTI_SESSION_KEY] = {self.endpoint: None}
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

    def test_user_isnt_logged_in_returns_401(self, rf):
        """If user isn't logged in, a 401 is returned"""
        request = self._setup_good_request(rf)
        # Override user w/ an anonymous one (not logged in)
        request.user = AnonymousUser()

        resp = DisplayTargetResource.as_view()(
            request,
            course_id=str(factories.COURSE_KEY),
            usage_id=str(factories.USAGE_KEY),
        )

        soup = BeautifulSoup(resp.content, "html.parser")
        assert soup.find("h1").text == "Unauthorized"
        assert resp.status_code == 401
