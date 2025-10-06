"""
Tests for LTI views.
"""

from __future__ import annotations

from datetime import timedelta
from unittest import mock

import jwt
import pytest
from bs4 import BeautifulSoup
from django.conf import settings
from django.test import Client, RequestFactory, override_settings
from django.urls import reverse
from django.utils import timezone
from organizations.tests.factories import OrganizationFactory
from pylti1p3.contrib.django import DjangoCacheDataStorage
from pylti1p3.session import SessionService
from xmodule.modulestore.tests.django_utils import ModuleStoreTestCase
from xmodule.modulestore.tests.factories import BlockFactory, CourseFactory

from lti_1p3_provider.dl_content_selection import Content
from lti_1p3_provider.models import import_from_string
from lti_1p3_provider.session_access import LTI_DEEP_LINKING_SESSION_PREFIX
from lti_1p3_provider.tests import factories, fakes
from lti_1p3_provider.views import DEFAULT_LTI_DEEP_LINKING_ACCEPT_ROLES


def dl_block_filter(msg_launch, platform_org):
    """Block filter for testing"""

    def _filter(block) -> bool:
        return block.location.block_type != "html"

    return _filter


@pytest.fixture
def enable_cache(settings):
    settings.CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "test-cache",
        }
    }


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
        self.tool_org = factories.LtiToolOrgFactory(tool=self.tool)
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
        mock_get_content.assert_called_once_with(gate, None)
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
        mock_get_content.assert_called_once_with(gate, None)
        soup = BeautifulSoup(resp.content, "html.parser")
        assert soup.find("form")

    @mock.patch("lti_1p3_provider.views.get_selectable_dl_content")
    def test_get_content_with_dl_content_selection_path_with_content_renders_page(
        self, mock_get_content, client, enable_cache
    ):
        """Test GET request with dl_content_filter_path set passes filter to mock_get_content"""
        gate = factories.LaunchGateFactory(
            tool=self.tool,
            allowed_orgs=["test-org"],
            allowed_courses=["course1", "course2"],
            dl_content_filter_path="lti_1p3_provider.tests.test_views.test_deep_linking_views.dl_block_filter",
        )
        mock_get_content.return_value = self.SIMPLE_CONTENT

        self._setup_session(client)

        url = reverse(
            "lti_1p3_provider:deep-linking-select-content",
            kwargs={"token": self.token},
        )
        resp = client.get(url)

        assert resp.status_code == 200

        mock_get_content.assert_called_once()
        args = mock_get_content.call_args.args
        assert args[0] == gate
        assert (
            args[1].__name__ == "_filter"
        )  # can't check the exact function bc it's a closure
        soup = BeautifulSoup(resp.content, "html.parser")
        assert soup.find("form")

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

    @mock.patch("lti_1p3_provider.views.get_selectable_dl_content")
    @mock.patch("lti_1p3_provider.views.get_xblock_display_name")
    def test_successful_post_with_valid_content_selection(
        self, mock_get_display_name, mock_get_content
    ):
        """Test successful POST request with valid content selection returns deep link response"""
        # Setup LaunchGate with allowed content
        client = Client(enforce_csrf_checks=True)
        mock_get_content.return_value = self.SIMPLE_CONTENT
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

        # First GET request to get CSRF cookie
        get_resp = client.get(url)
        assert get_resp.status_code == 200

        # Extract CSRF token from the form
        soup = BeautifulSoup(get_resp.content, "html.parser")
        csrf_input = soup.find("input", {"name": "csrfmiddlewaretoken"})
        csrf_token = csrf_input.get("value") if csrf_input else None
        assert csrf_token is not None, "CSRF token should be present in the form"

        # POST request with CSRF token
        resp = client.post(
            url,
            {"deep_link_content": target_usage_key, "csrfmiddlewaretoken": csrf_token},
        )

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
