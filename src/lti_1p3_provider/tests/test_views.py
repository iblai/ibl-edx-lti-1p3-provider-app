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
from django.test import Client, RequestFactory, override_settings
from django.urls import reverse
from django.utils import timezone
from organizations.tests.factories import OrganizationFactory
from pylti1p3.contrib.django import DjangoCacheDataStorage
from pylti1p3.registration import Registration
from pylti1p3.session import SessionService
from xmodule.modulestore.tests.django_utils import ModuleStoreTestCase
from xmodule.modulestore.tests.factories import BlockFactory, CourseFactory

from lti_1p3_provider.api.ssl_services import (
    generate_private_key_pem,
    priv_to_public_key_pem,
)
from lti_1p3_provider.dl_content_selection import Content
from lti_1p3_provider.error_response import (
    MISSING_SESSION_COOKIE_ERR_MSG,
    get_contact_support_msg,
)
from lti_1p3_provider.models import EDX_LTI_EMAIL_DOMAIN, LtiGradedResource, LtiProfile
from lti_1p3_provider.session_access import (
    LTI_DEEP_LINKING_SESSION_PREFIX,
    LTI_SESSION_KEY,
)
from lti_1p3_provider.views import (
    DEFAULT_LTI_DEEP_LINKING_ACCEPT_ROLES,
    LTI_1P3_EMAIL_META_KEY,
    DisplayTargetResource,
    LtiToolLaunchView,
)

from . import factories, fakes
from .base import URL_LIB_LTI_JWKS


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


@pytest.mark.django_db
@mock.patch(
    "pylti1p3.contrib.django.message_launch.DjangoSessionService",
    new=fakes.FakeDjangoSessionService,
)
class TestLtiDeepLinkLaunch:
    """Tests for LTI Deep Linking launch functionality"""

    deep_link_launch_endpoint = reverse("lti_1p3_provider:deep-link-launch")

    def setup_method(self):
        self.tool = factories.LtiToolFactory()
        self.kid = self.tool.to_dict()["key_set"]["keys"][0]["kid"]

    def _get_deep_link_payload(self, key=factories.PLATFORM_PRIVATE_KEY) -> dict:
        """Generate and return payload with encoded deep linking id_token"""
        id_token = factories.DeepLinkIdTokenFactory(
            aud=self.tool.client_id, nonce="nonce"
        )
        encoded = _encode_platform_jwt(id_token, self.kid, key=key)
        return {"state": "state", "id_token": encoded}

    def test_successful_deep_linking_launch_creates_session_and_redirects(self, client):
        """Test successful deep linking launch creates session and redirects to content selection"""
        # Setup LaunchGate to allow access for this tool/org
        factories.LaunchGateFactory(
            tool=self.tool, allowed_orgs=[factories.COURSE_KEY.org]
        )
        payload = self._get_deep_link_payload()
        # Nothing in the session before launch
        assert not client.session.keys()

        resp = client.post(self.deep_link_launch_endpoint, payload)

        assert resp.status_code == 302
        # Should redirect to content selection with a token
        assert resp.url.startswith("/lti/1p3/deep-linking/select-content/")
        # Extract token from redirect URL
        token = resp.url.split("/")[-2]
        assert len(token) == 36  # UUID4 length

        # Validate deep link session data
        dl_session_key = [
            k
            for k in client.session.keys()
            if k.startswith(LTI_DEEP_LINKING_SESSION_PREFIX)
        ]
        assert len(dl_session_key) == 1
        ctx = client.session[dl_session_key[0]]
        assert ctx["token"] == token
        assert ctx["launch_id"] is not None
        assert ctx["created_at"] is not None
        assert ctx["expires_at"] is not None
        assert ctx["expires_at"] >= ctx["created_at"]

    def test_no_launch_gate_for_tool_returns_403(self, client):
        """Test deep linking launch fails when LaunchGate does not exist"""
        payload = self._get_deep_link_payload()

        resp = client.post(self.deep_link_launch_endpoint, payload)

        soup = BeautifulSoup(resp.content, "html.parser")
        assert soup.find("h1").text == "No Accessible Content"
        assert "tool does not have access to any content" in soup.find("p").text.lower()
        assert resp.status_code == 403

    def test_empty_launch_gate_for_tool_returns_403(self, client):
        """Test deep linking launch fails when LaunchGate is empty"""
        # Create a gate for this tool that doesn't have any accessible content
        factories.LaunchGateFactory(tool=self.tool)
        payload = self._get_deep_link_payload()

        resp = client.post(self.deep_link_launch_endpoint, payload)

        soup = BeautifulSoup(resp.content, "html.parser")
        assert soup.find("h1").text == "No Accessible Content"
        assert "tool does not have access to any content" in soup.find("p").text.lower()
        assert resp.status_code == 403

    def test_deep_linking_launch_with_learner_role_returns_403(self, client):
        """Test deep linking launch fails for non-instructor roles"""
        # Setup LaunchGate to allow access
        factories.LaunchGateFactory(
            tool=self.tool, allowed_orgs=[factories.COURSE_KEY.org]
        )
        # Create token with learner role (default in factory)
        id_token = factories.DeepLinkIdTokenFactory(
            aud=self.tool.client_id,
            nonce="nonce",
            roles=["http://purl.imsglobal.org/vocab/lis/v2/membership#Learner"],
        )
        encoded = _encode_platform_jwt(id_token, self.kid)
        payload = {"state": "state", "id_token": encoded}

        resp = client.post(self.deep_link_launch_endpoint, payload)

        soup = BeautifulSoup(resp.content, "html.parser")
        assert soup.find("h1").text == "Insufficient Permissions"
        assert "required role to access" in soup.find("p").text.lower()
        assert resp.status_code == 403

    @pytest.mark.parametrize("role", DEFAULT_LTI_DEEP_LINKING_ACCEPT_ROLES)
    def test_deep_linking_launch_with_default_allowed_roles_succeeds(
        self, client, role
    ):
        """Test deep linking launch succeeds with default allowed roles"""
        # Setup LaunchGate to allow access
        factories.LaunchGateFactory(
            tool=self.tool, allowed_orgs=[factories.COURSE_KEY.org]
        )
        # Create token with instructor role
        id_token = factories.DeepLinkIdTokenFactory(
            aud=self.tool.client_id,
            nonce="nonce",
            roles=[role],
        )
        encoded = _encode_platform_jwt(id_token, self.kid)
        payload = {"state": "state", "id_token": encoded}

        resp = client.post(self.deep_link_launch_endpoint, payload)

        assert resp.status_code == 302
        assert resp.url.startswith("/lti/1p3/deep-linking/select-content/")

    def test_deep_linking_launch_with_at_least_one_allowed_role_succeeds(self, client):
        """Test deep linking launch succeeds with at least one allowed role"""
        # Setup LaunchGate to allow access
        factories.LaunchGateFactory(
            tool=self.tool, allowed_orgs=[factories.COURSE_KEY.org]
        )
        # Create token with instructor role
        id_token = factories.DeepLinkIdTokenFactory(
            aud=self.tool.client_id,
            nonce="nonce",
            roles=[
                "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Instructor",  # allowed
                "http://purl.imsglobal.org/vocab/lis/v2/membership#Learner",  # not allowed
            ],
        )
        encoded = _encode_platform_jwt(id_token, self.kid)
        payload = {"state": "state", "id_token": encoded}

        resp = client.post(self.deep_link_launch_endpoint, payload)

        assert resp.status_code == 302
        assert resp.url.startswith("/lti/1p3/deep-linking/select-content/")


@pytest.fixture
def enable_cache(settings):
    settings.CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "test-cache",
        }
    }


class DeepLinkingContentSelectionBaseTest:
    SIMPLE_CONTENT = {
        "test-org": [
            Content(
                title="Test Course",
                block_type="course",
                usage_key="block-v1:test-org+test-course+type@course+block@course",
                description="Test Course Description",
                children=[
                    Content(
                        title="Test Item",
                        block_type="problem",
                        usage_key="block-v1:test-org+test-course+test-item+type@problem+block@htmlid",
                        description="Test Problem Description",
                        children=[],
                    )
                ],
            )
        ]
    }

    def setup_method(self):
        self.tool = factories.LtiToolFactory()
        self.token = "test-token-123"
        # Need to use a password and client.login due to safesessions
        # It's Client.login is automatically patched to support safe sessions but
        # force_login is not supported
        self.user = factories.UserFactory()
        self.password = "password"
        self.user.set_password(self.password)
        self.user.save()

        # Default session data that can be modified per test
        self.dl_session_data = {
            "token": self.token,
            "launch_id": "test-launch-id",
            "created_at": timezone.now().timestamp(),
            "expires_at": (timezone.now() + timedelta(minutes=30)).timestamp(),
        }

    def _setup_session(self, client, authenticated=True):
        """Setup client session with deep linking context and cache entry"""
        if authenticated:
            client.login(username=self.user.username, password=self.password)

        # Create the ID token that will be stored in cache
        id_token = factories.DeepLinkIdTokenFactory(
            aud=self.tool.client_id, nonce="nonce"
        )

        # Need to establish an existing session with pylti1p3
        # Create a mock request object for the SessionService
        rf = RequestFactory()
        mock_request = rf.get("/")
        mock_request.session = client.session

        # Set up the cache storage and session service
        storage = DjangoCacheDataStorage()
        storage.set_request(mock_request)
        sess_service = SessionService(mock_request)
        sess_service.set_data_storage(storage)

        # Save the launch data to cache - this is what from_cache will retrieve
        sess_service.save_launch_data(self.dl_session_data["launch_id"], id_token)

        # Set up the deep linking session data
        session_key = f"{LTI_DEEP_LINKING_SESSION_PREFIX}{self.token}"
        session = client.session
        session[session_key] = self.dl_session_data
        session.save()


@pytest.mark.django_db
class TestDeepLinkingContentSelectionViewGET(DeepLinkingContentSelectionBaseTest):
    """Tests for Deep Linking Content Selection View GET"""

    @mock.patch("lti_1p3_provider.views.get_selectable_dl_content")
    def test_get_content_selection_with_no_content_renders_page(
        self, mock_get_content, client, enable_cache
    ):
        """Test GET request with no content renders content selection page"""
        gate = factories.LaunchGateFactory(
            tool=self.tool,
            allowed_orgs=["test-org"],
            allowed_courses=["course1", "course2"],
        )
        mock_get_content.return_value = {}

        self._setup_session(client)

        url = reverse(
            "lti_1p3_provider:deep-linking-select-content", kwargs={"token": self.token}
        )
        resp = client.get(url)

        assert resp.status_code == 200
        mock_get_content.assert_called_once_with(gate)
        soup = BeautifulSoup(resp.content, "html.parser")
        no_content_div = soup.find("div", class_="no-content-message")
        assert no_content_div.find("h3").text == "No Content Available"

    @mock.patch("lti_1p3_provider.views.get_selectable_dl_content")
    def test_get_content_selection_with_content_renders_page(
        self, mock_get_content, client, enable_cache
    ):
        """Test GET request with valid session renders content selection page"""
        gate = factories.LaunchGateFactory(
            tool=self.tool,
            allowed_orgs=["test-org"],
            allowed_courses=["course1", "course2"],
        )
        mock_get_content.return_value = self.SIMPLE_CONTENT

        self._setup_session(client)

        url = reverse(
            "lti_1p3_provider:deep-linking-select-content", kwargs={"token": self.token}
        )
        resp = client.get(url)

        assert resp.status_code == 200
        mock_get_content.assert_called_once_with(gate)
        soup = BeautifulSoup(resp.content, "html.parser")
        form = soup.find("form")

    @mock.patch("lti_1p3_provider.views.get_selectable_dl_content")
    def test_get_content_selection_with_invalid_token_returns_404(
        self, mock_get_content, client, enable_cache
    ):
        """Test GET request with invalid token returns 404"""
        self._setup_session(client)
        mock_get_content.return_value = self.SIMPLE_CONTENT

        invalid_token = "invalid-token-456"
        url = reverse(
            "lti_1p3_provider:deep-linking-select-content",
            kwargs={"token": invalid_token},
        )
        resp = client.get(url)

        assert resp.status_code == 404
        soup = BeautifulSoup(resp.content, "html.parser")
        assert soup.find("h1").text == "Invalid Access Link"

    def test_get_content_selection_with_unauthenticated_user_returns_401(self, client):
        """Test GET request with unauthenticated user returns 401"""
        self._setup_session(client, authenticated=False)

        url = reverse(
            "lti_1p3_provider:deep-linking-select-content", kwargs={"token": self.token}
        )
        resp = client.get(url)

        assert resp.status_code == 401
        soup = BeautifulSoup(resp.content, "html.parser")
        assert soup.find("h1").text == "Authentication Required"

    def test_get_content_selection_with_expired_session_returns_403(self, client):
        """Test GET request with expired session returns 403"""
        # Modify session data to be expired
        self.dl_session_data["expires_at"] = (
            timezone.now() - timedelta(minutes=1)
        ).timestamp()
        self._setup_session(client)

        url = reverse(
            "lti_1p3_provider:deep-linking-select-content", kwargs={"token": self.token}
        )
        resp = client.get(url)

        assert resp.status_code == 403
        soup = BeautifulSoup(resp.content, "html.parser")
        assert soup.find("h1").text == "Deep Linking Session Expired"

    def test_get_content_selection_with_token_mismatch_returns_400(self, client):
        """Test GET request with token mismatch in session returns 400"""
        # Modify session data to have mismatched token
        self.dl_session_data["token"] = "different-token"
        self._setup_session(client)

        url = reverse(
            "lti_1p3_provider:deep-linking-select-content", kwargs={"token": self.token}
        )
        resp = client.get(url)

        assert resp.status_code == 400
        soup = BeautifulSoup(resp.content, "html.parser")
        assert soup.find("h1").text == "Invalid Access Link"

    def test_get_content_selection_with_no_launch_gate_returns_403(
        self, client, enable_cache
    ):
        """Test GET request when tool has no LaunchGate returns 403"""
        self._setup_session(client)

        url = reverse(
            "lti_1p3_provider:deep-linking-select-content", kwargs={"token": self.token}
        )
        resp = client.get(url)

        assert resp.status_code == 403
        soup = BeautifulSoup(resp.content, "html.parser")
        assert soup.find("h1").text == "No Accessible Content"

    @mock.patch("lti_1p3_provider.views.get_selectable_dl_content")
    def test_get_content_selection_with_empty_content_renders_page(
        self, mock_get_content, client, enable_cache
    ):
        """Test GET request with empty content list still renders page"""
        # Setup LaunchGate
        factories.LaunchGateFactory(tool=self.tool)

        # Mock empty content
        mock_get_content.return_value = {}

        self._setup_session(client)

        url = reverse(
            "lti_1p3_provider:deep-linking-select-content", kwargs={"token": self.token}
        )
        resp = client.get(url)

        assert resp.status_code == 200
        assert "Select Content to Return" in resp.content.decode()

    def test_get_content_selection_with_missing_session_expiration_returns_500(
        self, client
    ):
        """Test GET request with missing session expiration returns 500"""
        # Remove expires_at from session data
        del self.dl_session_data["expires_at"]
        self._setup_session(client)

        url = reverse(
            "lti_1p3_provider:deep-linking-select-content", kwargs={"token": self.token}
        )
        resp = client.get(url)

        assert resp.status_code == 500
        soup = BeautifulSoup(resp.content, "html.parser")
        assert soup.find("h1").text == "Invalid Session"


@pytest.mark.django_db
@pytest.mark.usefixtures("enable_cache")
class TestDeepLinkingContentSelectionViewPOST(DeepLinkingContentSelectionBaseTest):
    """Tests for Deep Linking Content Selection View POST"""

    @mock.patch("lti_1p3_provider.views.get_xblock_display_name")
    def test_successful_post_with_valid_content_selection(
        self, mock_get_display_name, client
    ):
        """Test successful POST request with valid content selection returns deep link response"""
        # Setup LaunchGate with allowed content
        mock_get_display_name.return_value = "Sample LTI Content"
        gate = factories.LaunchGateFactory(
            tool=self.tool,
            allowed_orgs=[factories.COURSE_KEY.org],
            allowed_courses=[str(factories.COURSE_KEY)],
        )

        self._setup_session(client)

        # Valid usage key that should be allowed by the gate
        target_usage_key = str(factories.USAGE_KEY)

        url = reverse(
            "lti_1p3_provider:deep-linking-select-content", kwargs={"token": self.token}
        )

        resp = client.post(url, {"deep_link_content": target_usage_key})

        assert resp.status_code == 200
        assert resp["Content-Type"] == "text/html"

        # Check that the response is an auto-submitted HTML form with JWT
        soup = BeautifulSoup(resp.content, "html.parser")
        form = soup.find("form")
        assert form is not None, "Response should contain an HTML form"

        # Check for JWT form field
        jwt_input = form.find("input", {"name": "JWT"})
        assert jwt_input is not None, "Form should contain JWT input field"
        assert jwt_input.get("value") is not None, "JWT input should have a value"

        # Verify that the deep linking session was cleared
        session_key = f"{LTI_DEEP_LINKING_SESSION_PREFIX}{self.token}"
        assert session_key not in client.session

    @pytest.mark.parametrize(
        "post_data",
        [
            {},
            {"deep_link_content": ""},
        ],
    )
    @mock.patch("lti_1p3_provider.views.get_selectable_dl_content")
    def test_post_with_missing_or_empty_deep_link_content_returns_400(
        self, mock_get_content, post_data, client
    ):
        """Test POST request with missing or empty deep_link_content returns 400"""
        # Setup LaunchGate
        factories.LaunchGateFactory(tool=self.tool)
        mock_get_content.return_value = self.SIMPLE_CONTENT

        self._setup_session(client)

        url = reverse(
            "lti_1p3_provider:deep-linking-select-content", kwargs={"token": self.token}
        )

        resp = client.post(url, post_data)

        assert resp.status_code == 400
        soup = BeautifulSoup(resp.content, "html.parser")
        assert soup.find("h3").text == "No Content Selected"

    @mock.patch("lti_1p3_provider.views.get_selectable_dl_content")
    def test_post_with_unauthorized_content_returns_403(self, mock_get_content, client):
        """Test POST request with content not allowed by launch gate returns 403"""
        # Setup LaunchGate that doesn't allow the target content
        gate = factories.LaunchGateFactory(
            tool=self.tool,
            allowed_orgs=["different-org"],  # Different org than COURSE_KEY.org
        )
        mock_get_content.return_value = {}

        self._setup_session(client)

        # Usage key that should NOT be allowed by the gate
        target_usage_key = str(factories.USAGE_KEY)

        url = reverse(
            "lti_1p3_provider:deep-linking-select-content", kwargs={"token": self.token}
        )

        resp = client.post(url, {"deep_link_content": target_usage_key})

        assert resp.status_code == 403
        soup = BeautifulSoup(resp.content, "html.parser")
        assert soup.find("h3").text == "Permission Denied"
        div = soup.find("div", class_="error-display")
        div_text = div.find("p").text
        assert div_text.startswith(
            "You do not have permission to access the selected content."
        )

    @mock.patch("lti_1p3_provider.views.get_selectable_dl_content")
    def test_post_with_malformed_usage_key_returns_400(self, mock_get_content, client):
        """Test POST request with malformed usage key returns 400"""
        # Setup LaunchGate
        factories.LaunchGateFactory(tool=self.tool)
        mock_get_content.return_value = self.SIMPLE_CONTENT

        self._setup_session(client)

        # Malformed usage key
        malformed_usage_key = "invalid-usage-key-format"

        url = reverse(
            "lti_1p3_provider:deep-linking-select-content", kwargs={"token": self.token}
        )

        resp = client.post(url, {"deep_link_content": malformed_usage_key})

        assert resp.status_code == 400
        soup = BeautifulSoup(resp.content, "html.parser")
        assert soup.find("h3").text == "Invalid Usage Key"

    @mock.patch("lti_1p3_provider.views.get_xblock_display_name")
    @mock.patch("lti_1p3_provider.views.get_selectable_dl_content")
    def test_post_clears_deep_linking_session_after_success(
        self, mock_get_content, mock_get_display_name, client
    ):
        """Test that successful POST request clears the deep linking session"""
        # Setup LaunchGate
        mock_get_display_name.return_value = "Test Title"
        gate = factories.LaunchGateFactory(
            tool=self.tool,
            allowed_orgs=[factories.COURSE_KEY.org],
        )
        mock_get_content.return_value = self.SIMPLE_CONTENT

        self._setup_session(client)

        # Verify session exists before POST
        session_key = f"{LTI_DEEP_LINKING_SESSION_PREFIX}{self.token}"
        assert session_key in client.session

        url = reverse(
            "lti_1p3_provider:deep-linking-select-content", kwargs={"token": self.token}
        )

        resp = client.post(url, {"deep_link_content": str(factories.USAGE_KEY)})

        assert resp.status_code == 200

        # Verify session was cleared after successful POST
        assert session_key not in client.session

    @mock.patch("lti_1p3_provider.views.get_xblock_display_name")
    def test_post_generates_correct_target_link_uri(
        self, mock_get_display_name, client
    ):
        """Test that POST request generates correct target_link_uri in response"""
        # Setup LaunchGate
        mock_get_display_name.return_value = "Test Title"
        gate = factories.LaunchGateFactory(
            tool=self.tool,
            allowed_orgs=[factories.COURSE_KEY.org],
        )

        self._setup_session(client)

        target_usage_key = str(factories.USAGE_KEY)

        url = reverse(
            "lti_1p3_provider:deep-linking-select-content", kwargs={"token": self.token}
        )

        resp = client.post(url, {"deep_link_content": target_usage_key})

        assert resp.status_code == 200

        # Check that the response is a valid auto-submitted HTML form
        soup = BeautifulSoup(resp.content, "html.parser")
        form = soup.find("form")
        assert form is not None, "Response should contain an HTML form"

        # Check for JWT form field
        jwt_input = form.find("input", {"name": "JWT"})
        assert jwt_input is not None, "Form should contain JWT input field"
        assert jwt_input.get("value") is not None, "JWT input should have a value"

    @mock.patch("lti_1p3_provider.views.get_xblock_display_name")
    def test_post_with_different_usage_key_still_works(
        self, mock_get_display_name, client
    ):
        """Test POST request with a different valid usage key works correctly"""
        # Create a different course and usage key
        mock_get_display_name.return_value = "Test Title"
        different_course = factories.COURSE_KEY.replace(course="Course2")
        different_usage = different_course.make_usage_key(
            "vertical", "different-html-id"
        )

        # Setup LaunchGate that allows both courses
        gate = factories.LaunchGateFactory(
            tool=self.tool,
            allowed_orgs=[factories.COURSE_KEY.org],
            allowed_courses=[str(factories.COURSE_KEY), str(different_course)],
        )

        self._setup_session(client)

        url = reverse(
            "lti_1p3_provider:deep-linking-select-content", kwargs={"token": self.token}
        )

        resp = client.post(url, {"deep_link_content": str(different_usage)})

        assert resp.status_code == 200
        assert resp["Content-Type"] == "text/html"

        # Check that the response is a valid auto-submitted HTML form
        soup = BeautifulSoup(resp.content, "html.parser")
        form = soup.find("form")
        assert form is not None, "Response should contain an HTML form"

        # Check for JWT form field
        jwt_input = form.find("input", {"name": "JWT"})
        assert jwt_input is not None, "Form should contain JWT input field"
        assert jwt_input.get("value") is not None, "JWT input should have a value"

    def test_post_with_invalid_token_returns_404(self, client):
        """Test POST request with invalid token returns 404"""
        # Setup LaunchGate
        factories.LaunchGateFactory(tool=self.tool)

        self._setup_session(client)

        invalid_token = "invalid-token-456"
        url = reverse(
            "lti_1p3_provider:deep-linking-select-content",
            kwargs={"token": invalid_token},
        )

        resp = client.post(url, {"deep_link_content": str(factories.USAGE_KEY)})

        assert resp.status_code == 404
        soup = BeautifulSoup(resp.content, "html.parser")
        assert soup.find("h1").text == "Invalid Access Link"

    def test_post_with_unauthenticated_user_returns_401(self, client):
        """Test POST request with unauthenticated user returns 401"""
        # Setup LaunchGate
        factories.LaunchGateFactory(tool=self.tool)

        self._setup_session(client, authenticated=False)

        url = reverse(
            "lti_1p3_provider:deep-linking-select-content", kwargs={"token": self.token}
        )

        resp = client.post(url, {"deep_link_content": str(factories.USAGE_KEY)})

        assert resp.status_code == 401
        soup = BeautifulSoup(resp.content, "html.parser")
        assert soup.find("h1").text == "Authentication Required"

    def test_post_with_expired_session_returns_403(self, client):
        """Test POST request with expired session returns 403"""
        # Setup LaunchGate
        factories.LaunchGateFactory(tool=self.tool)

        # Modify session data to be expired
        self.dl_session_data["expires_at"] = (
            timezone.now() - timedelta(minutes=1)
        ).timestamp()
        self._setup_session(client)

        url = reverse(
            "lti_1p3_provider:deep-linking-select-content", kwargs={"token": self.token}
        )

        resp = client.post(url, {"deep_link_content": str(factories.USAGE_KEY)})

        assert resp.status_code == 403
        soup = BeautifulSoup(resp.content, "html.parser")
        assert soup.find("h1").text == "Deep Linking Session Expired"

    def test_post_with_no_launch_gate_returns_403(self, client):
        """Test POST request when tool has no LaunchGate returns 403"""
        # Don't create a LaunchGate for the tool
        self._setup_session(client)

        url = reverse(
            "lti_1p3_provider:deep-linking-select-content", kwargs={"token": self.token}
        )

        resp = client.post(url, {"deep_link_content": str(factories.USAGE_KEY)})

        assert resp.status_code == 403
        soup = BeautifulSoup(resp.content, "html.parser")
        assert soup.find("h1").text == "No Accessible Content"


@pytest.mark.django_db
class TestDeepLinkingContentSelectionWithModulestore(ModuleStoreTestCase):
    """Tests for Deep Linking Content Selection View with real ModuleStore content"""

    def setUp(self):
        super().setUp()

        # Create organization
        self.org = OrganizationFactory(short_name="test-org")

        # Create a course with various content types
        self.course = CourseFactory.create(
            org=self.org.short_name, display_name="Test Course for LTI"
        )

        # Create course structure: Chapter -> Sequential -> Vertical -> Problems/Videos
        self.chapter = BlockFactory.create(
            parent_location=self.course.location,
            category="chapter",
            display_name="Test Chapter",
        )

        self.sequential = BlockFactory.create(
            parent_location=self.chapter.location,
            category="sequential",
            display_name="Test Sequential",
        )

        self.vertical = BlockFactory.create(
            parent_location=self.sequential.location,
            category="vertical",
            display_name="Test Vertical",
        )

        # Create problems (these should be returned by block_filter)
        self.problem1 = BlockFactory.create(
            parent_location=self.vertical.location,
            category="problem",
            display_name="Test Problem 1",
        )

        self.problem2 = BlockFactory.create(
            parent_location=self.vertical.location,
            category="problem",
            display_name="Test Problem 2",
        )

        # Create videos (these should NOT be returned by block_filter)
        self.video1 = BlockFactory.create(
            parent_location=self.vertical.location,
            category="video",
            display_name="Test Video 1",
        )

        # Create another vertical with more content
        self.vertical2 = BlockFactory.create(
            parent_location=self.sequential.location,
            category="vertical",
            display_name="Test Vertical 2",
        )

        self.problem3 = BlockFactory.create(
            parent_location=self.vertical2.location,
            category="problem",
            display_name="Test Problem 3",
        )

        # Setup LTI tool and user
        self.tool = factories.LtiToolFactory()
        self.token = "test-token-123"
        self.user = factories.UserFactory()
        self.password = "password"
        self.user.set_password(self.password)
        self.user.save()

        # Create LaunchGate with allowed_orgs filter and block_filter for problems only
        self.launch_gate = factories.LaunchGateFactory(
            tool=self.tool, allowed_orgs=[self.org.short_name], block_filter=["problem"]
        )

        # Default session data
        self.dl_session_data = {
            "token": self.token,
            "launch_id": "test-launch-id",
            "created_at": timezone.now().timestamp(),
            "expires_at": (timezone.now() + timedelta(minutes=30)).timestamp(),
        }

    def _setup_session(self, client, authenticated=True):
        """Setup client session with deep linking context and cache entry"""
        if authenticated:
            client.login(username=self.user.username, password=self.password)

        # Create the ID token that will be stored in cache
        id_token = factories.DeepLinkIdTokenFactory(
            aud=self.tool.client_id, nonce="nonce"
        )

        # Need to establish an existing session with pylti1p3
        # Create a mock request object for the SessionService
        rf = RequestFactory()
        mock_request = rf.get("/")
        mock_request.session = client.session

        # Set up the cache storage and session service
        storage = DjangoCacheDataStorage()
        storage.set_request(mock_request)
        sess_service = SessionService(mock_request)
        sess_service.set_data_storage(storage)

        # Save the launch data to cache - this is what from_cache will retrieve
        sess_service.save_launch_data(self.dl_session_data["launch_id"], id_token)

        # Set up the deep linking session data
        session_key = f"{LTI_DEEP_LINKING_SESSION_PREFIX}{self.token}"
        session = client.session
        session[session_key] = self.dl_session_data
        session.save()

    @override_settings(
        CACHES={
            "default": {
                "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
                "LOCATION": "test-cache",
            }
        }
    )
    def test_get_content_selection_with_real_content_renders_correct_problems(self):
        """Test GET request with real ModuleStore content renders only problem blocks"""
        client = Client()
        self._setup_session(client)

        url = reverse(
            "lti_1p3_provider:deep-linking-select-content", kwargs={"token": self.token}
        )
        resp = client.get(url)

        assert resp.status_code == 200

        # Parse the response with BeautifulSoup
        soup = BeautifulSoup(resp.content, "html.parser")

        # Check that the page title is correct
        assert soup.find("h1").text == "Select Content to Return"

        # Check that the organization section exists
        org_section = soup.find("h2", class_="organization-title")
        assert org_section is not None
        assert org_section.text == self.org.short_name

        # Check that the course section exists
        course_section = soup.find("h3", class_="course-title")
        assert course_section is not None
        assert course_section.text == "Test Course for LTI"

        # Find all radio button inputs for content selection
        content_inputs = soup.find_all("input", {"name": "deep_link_content"})

        # Should have exactly 3 problem blocks (problem1, problem2, problem3)
        assert len(content_inputs) == 3

        # Extract the usage keys from the form inputs
        found_usage_keys = set()
        for input_elem in content_inputs:
            usage_key = input_elem.get("value")
            found_usage_keys.add(usage_key)

        # Verify that we have exactly the three problems we expect
        expected_problem_keys = {
            str(self.problem1.location),
            str(self.problem2.location),
            str(self.problem3.location),
        }

        assert found_usage_keys == expected_problem_keys, (
            f"Expected exactly {expected_problem_keys}, but found {found_usage_keys}. "
            f"Missing: {expected_problem_keys - found_usage_keys}, "
            f"Extra: {found_usage_keys - expected_problem_keys}"
        )

        # Check that each problem has the correct display name and block type
        for input_elem in content_inputs:
            # Find the parent label element
            label = input_elem.find_parent("label")
            assert label is not None

            # Check the title
            title_elem = label.find("div", class_="content-option-title")
            assert title_elem is not None

            # Check the block type
            type_elem = label.find("div", class_="content-option-type")
            assert type_elem is not None
            assert type_elem.text == "problem"

            # Verify the title matches one of our expected problems
            title = title_elem.text
            expected_titles = ["Test Problem 1", "Test Problem 2", "Test Problem 3"]
            assert title in expected_titles, f"Unexpected title: {title}"

        # Verify the form structure
        form = soup.find("form", {"id": "content-selection-form"})
        assert form is not None
        assert form.get("method") == "post"

        # Check that submit button exists and is initially disabled
        submit_button = soup.find("button", class_="submit-button")
        assert submit_button is not None
        assert submit_button.get("disabled") is not None
        assert submit_button.text.strip() == "Select Content"
