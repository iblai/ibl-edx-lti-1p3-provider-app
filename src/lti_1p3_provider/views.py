"""LTI 1.3 Provider Views"""

from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import datetime, timedelta
from urllib import parse

from common.djangoapps.student.models import UserProfile
from django.conf import settings
from django.contrib.auth import authenticate, get_user_model, login
from django.http import (
    Http404,
    HttpResponse,
    HttpResponseBadRequest,
    JsonResponse,
)
from django.shortcuts import redirect
from django.urls import Resolver404, resolve, reverse
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.decorators.clickjacking import xframe_options_exempt
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.base import View
from jwcrypto.common import JWException
from opaque_keys import InvalidKeyError
from opaque_keys.edx.keys import CourseKey, UsageKey
from openedx.core.djangoapps.safe_sessions.middleware import (
    mark_user_change_as_expected,
)
from openedx.core.lib.url_utils import unquote_slashes
from pylti1p3.contrib.django import (
    DjangoCacheDataStorage,
    DjangoDbToolConf,
    DjangoMessageLaunch,
    DjangoOIDCLogin,
)
from pylti1p3.exception import LtiException, OIDCException

from .error_formatter import reformat_error
from .error_response import (
    MISSING_SESSION_COOKIE_ERR_MSG,
    get_contact_support_msg,
    get_lti_error_response,
    render_edx_error,
)
from .exceptions import DeepLinkingError, MissingSessionError
from .jwks import get_jwks_for_org
from .models import LaunchGate, LtiGradedResource, LtiProfile
from .session_access import has_lti_session_access, set_lti_session_access

log = logging.getLogger(__name__)
User = get_user_model()

LTI_1P3_EMAIL_META_KEY = "lti_1p3_email"
DEFAULT_DEEP_LINKING_SESSION_DURATION_SEC = 1800  # 30 minutes
DEFAULT_LTI_DEEP_LINKING_ACCEPT_ROLES = [
    "http://purl.imsglobal.org/vocab/lis/v2/institution/person#Instructor",
    "http://purl.imsglobal.org/vocab/lis/v2/membership#ContentDeveloper",
    "http://purl.imsglobal.org/vocab/lis/v2/membership#Manager",
]


def requires_lti_enabled(view_func):
    """
    Modify the view function to raise 404 if LTI 1p3 Provider is not enabled
    """

    def wrapped_view(*args, **kwargs):
        lti_enabled = settings.FEATURES.get("ENABLE_LTI_1P3_PROVIDER")
        if not lti_enabled:
            raise Http404()
        return view_func(*args, **kwargs)

    return wrapped_view


@method_decorator(requires_lti_enabled, name="dispatch")
class LtiToolView(View):
    """
    Base LTI View initializing common attributes.
    """

    # pylint: disable=attribute-defined-outside-init
    def setup(self, request, *args, **kwds):
        """
        Initialize attributes shared by all LTI views.
        """
        super().setup(request, *args, **kwds)
        self.lti_tool_config = DjangoDbToolConf()
        self.lti_tool_storage = DjangoCacheDataStorage(cache_name="default")


@method_decorator(csrf_exempt, name="dispatch")
class LtiToolLoginView(LtiToolView):
    """
    Third-party Initiated Login view.

    The LTI platform will start the OpenID Connect flow by redirecting the User
    Agent (UA) to this view. The redirect may be a form POST or a GET.  On
    success the view should redirect the UA to the LTI platform's authentication
    URL.
    """

    # TODO: Remove this class var; unused
    LAUNCH_URI_PARAMETER = "target_link_uri"

    def get(self, request):
        return self.post(request)

    def post(self, request):
        """Initialize 3rd-party login requests to redirect."""
        oidc_login = DjangoOIDCLogin(
            self.request,
            self.lti_tool_config,
            launch_data_storage=self.lti_tool_storage,
        )
        try:
            return oidc_login.redirect(
                self.request.build_absolute_uri(reverse("lti_1p3_provider:lti-launch"))
            )
        except (OIDCException, LtiException) as exc:
            log.error(
                "LTI OIDC login failed.\nError: %s\nMethod: %s\nParams: %s",
                exc,
                self.request.method,
                self._get_launch_params(),
            )
            return render_edx_error(
                request,
                title="Invalid LTI Login Request",
                error=f"{exc}. {get_contact_support_msg()}",
                status=400,
            )

    def _get_launch_params(self) -> dict[str, str]:
        """Return launch params based on launch type"""
        if self.request.method == "GET":
            return self.request.GET
        return self.request.POST


@method_decorator(csrf_exempt, name="dispatch")
@method_decorator(xframe_options_exempt, name="dispatch")
class LtiToolLaunchView(LtiToolView):
    """
    LTI platform tool launch view.

    The launch view supports resource link launches and AGS, when enabled by the
    LTI platform.  Other features and resouces are ignored.
    """

    template_name = "content_libraries/xblock_iframe.html"

    @property
    def launch_data(self):
        if getattr(self, "launch_message", None):
            return self.launch_message.get_launch_data()
        return {}

    def _authenticate_and_login(self):
        """
        Authenticate and authorize the user for this LTI message launch.

        We automatically create LTI profile for every valid launch, and
        authenticate the LTI user associated with it.
        """

        email_claim = self.launch_data.get("email", "") or ""  # can't allow null email
        first_name = self.launch_data.get("given_name", "")
        last_name = self.launch_data.get("family_name", "")
        lti_profile = LtiProfile.objects.get_or_create_from_claims(
            iss=self.launch_data["iss"],
            aud=self.launch_data["aud"],
            sub=self.launch_data["sub"],
            email=email_claim,
            first_name=first_name,
            last_name=last_name,
        )
        # Make sure email is updated in LtiProfile and UserProfile
        if email_claim:
            if lti_profile.email != email_claim:
                lti_profile.email = email_claim
                lti_profile.save()

        # Ensure UserProfile is updated w/ email and full name
        self._update_or_create_user_profile(
            lti_profile, email_claim, first_name, last_name
        )

        # Ensure user's first/last name is updated if passed
        self._update_user_first_last_name(lti_profile.user, first_name, last_name)

        edx_user = authenticate(
            self.request,
            iss=self.launch_data["iss"],
            aud=self.launch_data["aud"],
            sub=self.launch_data["sub"],
        )

        if edx_user is not None:
            login(self.request, edx_user)
            mark_user_change_as_expected(edx_user.id)
        else:
            log.warning(
                "Unable to login user %s from iss %s with aud %s",
                self.launch_data["sub"],
                self.launch_data["iss"],
                self.launch_data["aud"],
            )

        return edx_user

    def _update_or_create_user_profile(
        self, lti_profile: LtiProfile, email_claim: str, first_name: str, last_name: str
    ) -> None:
        """Update/create the User's edx UserProfile data"""
        full_name = self._create_user_name(first_name, last_name)
        try:
            user_profile = lti_profile.user.profile
        except UserProfile.DoesNotExist:
            if email_claim:
                meta = json.dumps({LTI_1P3_EMAIL_META_KEY: email_claim})
            else:
                meta = json.dumps({})
            user_profile = UserProfile.objects.create(
                user=lti_profile.user, meta=meta, name=full_name
            )
            log.info(
                "Created UserProfile for LTI profile %s (id=%s)",
                lti_profile,
                lti_profile.id,
            )
            return

        changed = False
        meta = user_profile.get_meta()
        if meta.get(LTI_1P3_EMAIL_META_KEY, "") != email_claim:
            meta[LTI_1P3_EMAIL_META_KEY] = email_claim
            user_profile.set_meta(meta)
            log.info(
                "Updated email for LTI user %s (id=%s)", lti_profile, lti_profile.id
            )
            changed = True

        if user_profile.name != full_name:
            user_profile.name = full_name
            log.info(
                "Updated Profile name for LTI user %s (id=%s)",
                lti_profile,
                lti_profile.id,
            )
            changed = True

        if changed:
            user_profile.save()

    def _create_user_name(self, first_name: str, last_name: str) -> str:
        """Create a user name based on first and last name"""
        return f"{first_name} {last_name}" if first_name or last_name else ""

    def _update_user_first_last_name(
        self, user: User, first_name: str, last_name: str
    ) -> None:
        """Update user's first and last name if they are different than stored"""

        # Ensure user's first/last name is updated if passed
        changed = False
        if user.first_name != first_name:
            user.first_name = first_name
            log.info("Updated first name for LTI user %s", user.username)
            changed = True

        if user.last_name != last_name:
            user.last_name = last_name
            log.info("Updated last name for LTI user %s", user.username)
            changed = True

        if changed:
            user.save()

    def _bad_request_response(self):
        """
        A default response for bad requests.
        """
        return HttpResponseBadRequest("Invalid LTI tool launch.")

    def get_launch_message(self):
        """
        Return the LTI 1.3 launch message object for the current request.
        """
        launch_message = DjangoMessageLaunch(
            self.request,
            self.lti_tool_config,
            launch_data_storage=self.lti_tool_storage,
        )
        # This will force the LTI launch validation steps.
        launch_message.get_launch_data()
        return launch_message

    def get(self, request):
        """
        Show a nicer error since we don't support GET here
        """
        title = "This page cannot be accessed directly"
        error = "Please relaunch your content from its original source to view it."
        return render_edx_error(request, title, error, status=405)

    # pylint: disable=attribute-defined-outside-init
    def post(self, request):
        """
        Process LTI platform launch requests.
        """

        try:
            self.launch_message = self.get_launch_message()
            log.info("LTI 1.3: Launch message body: %s", json.dumps(self.launch_data))

            if self.launch_message.is_deep_link_launch():
                return self._handle_deep_linking_launch()

            # Regular resource link launch
            return self._handle_basic_tool_launch()

        except InvalidKeyError as e:
            log.error("Invalid Launch Course or UsageKey - %s", e)
            errormsg = (
                "Invalid course_id or usage_id in target link uri: "
                f"{self._get_target_link_uri()}"
            )
            return get_lti_error_response(
                request, self.launch_data, errormsg=errormsg, status=400
            )

        except LtiException as exc:
            log.error("LTI 1.3: Tool launch failed: %s", exc)
            title = "Invalid LTI Tool Launch"
            errormsg = reformat_error(str(exc))
            # Handle missing cookie error raised by pylti1p3
            # Actual string is "Missing %s cookie session-id"
            if re.match(r"Missing .* cookie session-id", errormsg):
                title = "Oops, this didn't work! Invalid LTI tool launch."
                errormsg = MISSING_SESSION_COOKIE_ERR_MSG
            errormsg = f"{errormsg.strip('.')}. {get_contact_support_msg()}"
            return get_lti_error_response(
                request, self.launch_data, title=title, errormsg=errormsg, status=400
            )

        except JWException as exc:
            log.error("LTI 1.3: JwkError: %s", exc)
            errormsg = (
                "Invalid Platform Public Key. Please contact your technical support "
                "for additional assistance."
            )
            return get_lti_error_response(
                request, self.launch_data, errormsg=errormsg, status=500
            )

    def _get_course_and_usage_id(self) -> tuple[str, str]:
        """Return course_id and usage_id from target_link_uri string"""
        target_link_uri = self._get_target_link_uri()
        path = parse.urlparse(target_link_uri)[2]
        try:
            log.debug("Target link uri: %s", path)
            match = resolve(path)
        except Resolver404:
            log.error("target link uri: %s is invalid", path)
            raise LtiException("Invalid target_link_uri path: %s", path)

        return match.kwargs["course_id"], match.kwargs["usage_id"]

    def _get_target_link_uri(self) -> str | None:
        """Return target link URI from payload"""
        return self.launch_data.get(
            "https://purl.imsglobal.org/spec/lti/claim/target_link_uri"
        )

    def handle_ags(self, course_key: CourseKey, usage_key: UsageKey) -> None:
        """
        Handle AGS-enabled launches for block in the request.
        """
        if not self.launch_message.has_ags():
            log.debug("Not an AGS launch")
            return

        endpoint_claim = "https://purl.imsglobal.org/spec/lti-ags/claim/endpoint"
        endpoint = self.launch_data[endpoint_claim]
        required_scopes = [
            "https://purl.imsglobal.org/spec/lti-ags/scope/score",
        ]

        for scope in required_scopes:
            if scope not in endpoint["scope"]:
                log.info(
                    "LTI 1.3: AGS: LTI platform does not support a required scope: %s",
                    scope,
                )
                return

        lineitem = endpoint.get("lineitem")
        if not lineitem:
            log.info(
                "LTI 1.3: AGS: LTI platform didn't pass lineitem, ignoring "
                "request: %s. Code doesn't exist to create one yet, no grade passback.",
                endpoint,
            )
            return

        # Create graded resource in the database for the current launch.
        resource_claim = "https://purl.imsglobal.org/spec/lti/claim/resource_link"
        resource_link = self.launch_data.get(resource_claim)
        resource = LtiGradedResource.objects.upsert_from_ags_launch(
            self.request.user, course_key, usage_key, endpoint, resource_link
        )

        log.info("LTI 1.3: AGS: Upserted LTI graded resource from launch: %s", resource)

    def _set_session_access(self) -> None:
        """Setup session to grant lti access to target link uri"""
        target_link_uri = self._get_target_link_uri()
        target_link_uri_path = parse.urlparse(target_link_uri).path
        expiration = self._get_lti_session_expiration()
        set_lti_session_access(self.request.session, target_link_uri_path, expiration)

    def _get_lti_session_expiration(self) -> datetime | None:
        """Return expiration for LTI Session for this path"""
        override_exp_sec = getattr(settings, "LTI_1P3_PROVIDER_ACCESS_LENGTH_SEC", None)
        if override_exp_sec:
            log.debug(
                "Using LTI_1P3_PROVIDER_ACCESS_LENGTH_SEC as lti access length: %s",
                override_exp_sec,
            )
            return timezone.now() + timedelta(seconds=override_exp_sec)

        log.debug(
            "LTI_1P3_PROVIDER_ACCESS_LENGTH_SEC is None; "
            "Access allowed as long as logged in"
        )
        return None

    def _check_launch_gate(
        self, message: DjangoMessageLaunch, target_usage_key: UsageKey
    ) -> bool:
        """Return True if launching tool can access target_usage_key"""
        tool = self.lti_tool_config.get_lti_tool(
            iss=message.get_iss(),
            client_id=message.get_client_id(),
        )
        try:
            return tool.launch_gate.can_access_key(target_usage_key)
        except LaunchGate.DoesNotExist:
            log.info(
                "Tool (iss=%s, client_id=%s) has no launch gate; proceeding",
                tool.issuer,
                tool.client_id,
            )

        return True

    def _handle_basic_tool_launch(self):
        """
        Handle regular LTI resource link launch requests.
        """
        # Regular resource link launch - parse course and usage keys
        course_id, usage_id = self._get_course_and_usage_id()
        course_key, usage_key = parse_course_and_usage_keys(course_id, usage_id)
        log.info(
            "LTI 1.3: issuer=%s, client_id=%s, Launch course=%s, block: id=%s",
            self.launch_message.get_iss(),
            self.launch_message.get_client_id(),
            course_key,
            usage_key,
        )

        # Validate tool can access the requested usage key
        if not self._check_launch_gate(self.launch_message, usage_key):
            log.warning(
                "Tool (iss=%s, client_id=%s) cannot launch usage key: %s",
                self.launch_message.get_iss(),
                self.launch_message.get_client_id(),
                usage_key,
            )
            errormsg = (
                "You do not have permission to access this content. Please "
                "contact your technical support for additional assistance."
            )
            return get_lti_error_response(
                self.request,
                self.launch_data,
                title="LTI Launch Gate Error",
                errormsg=errormsg,
                status=403,
            )

        # Authenticate and log in the user
        edx_user = self._authenticate_and_login()
        if not edx_user:
            return self._bad_request_response()

        # Handle AGS (Assignment and Grade Services) if available
        self.handle_ags(course_key, usage_key)

        # Set session access for the target resource
        self._set_session_access()

        # Redirect to the target content
        return redirect(self._get_target_link_uri())

    def _validate_deep_linking_roles(self) -> bool:
        """
        Validate user has appropriate roles for deep linking.

        Checks LTI roles claim against configured acceptable roles for deep linking.

        Returns:
            bool: True if user has valid roles, False otherwise
        """
        roles_claim = "https://purl.imsglobal.org/spec/lti/claim/roles"
        user_roles = self.launch_data.get(roles_claim, [])
        accepted_roles = getattr(
            settings,
            "LTI_DEEP_LINKING_ACCEPT_ROLES",
            DEFAULT_LTI_DEEP_LINKING_ACCEPT_ROLES,
        )

        has_valid_role = any(role in accepted_roles for role in user_roles)

        if not has_valid_role:
            log.warning(
                "Deep linking access denied: user roles %s not in accepted roles %s",
                user_roles,
                accepted_roles,
            )

        return has_valid_role

    def _validate_has_accessible_content(self) -> bool:
        """Return True if tool has entries in its launch date

        Returns:
            bool: True if tool has entries in the launch gate, False otherwise
        """
        tool = self.lti_tool_config.get_lti_tool(
            iss=self.launch_message.get_iss(),
            client_id=self.launch_message.get_client_id(),
        )

        try:
            gate = tool.launch_gate
            if not any(gate.allowed_keys, gate.allowed_courses, gate.allowed_orgs):
                log.error(
                    "Tool (iss=%s, client_id=%s) has empty LaunchGate; denying access",
                    tool.issuer,
                    tool.client_id,
                )
                return False

        except LaunchGate.DoesNotExist:
            log.error(
                "Tool (iss=%s, client_id=%s) has no LaunchGate; denying access",
                tool.issuer,
                tool.client_id,
            )
            return False

        return True

    def _store_deep_linking_context(self) -> str:
        """
        Store deep linking context in the user's session with a unique token.

        This context includes tool information, launch data, and expiration time
        to control access to the content selection page.

        Returns:
            str: The unique token for this deep linking session
        """
        token = self.get_deep_linking_token()

        session_duration_sec = getattr(
            settings,
            "LTI_DEEP_LINKING_SESSION_DURATION_SEC",
            DEFAULT_DEEP_LINKING_SESSION_DURATION_SEC,
        )
        now = timezone.now()
        expires_at = now + timedelta(seconds=session_duration_sec)

        tool = self.lti_tool_config.get_lti_tool(
            iss=self.launch_message.get_iss(),
            client_id=self.launch_message.get_client_id(),
        )

        # Store context in session with token-specific key
        session_key = f"lti_deep_link_context_{token}"
        self.request.session[session_key] = {
            "token": token,
            "tool_info": {
                "issuer": tool.issuer,
                "client_id": tool.client_id,
            },
            "launch_data": self.launch_data.copy(),  # Store relevant launch data
            "created_at": now.timestamp(),
            "expires_at": expires_at.timestamp(),
        }

        log.info(
            "Stored deep linking context in session for Tool (issuer=%s, client_id=%s) with token %s (expires at %s)",
            tool.issuer,
            tool.client_id,
            token[:8] + "...",
            expires_at.isoformat(),
        )

        return token

    def get_deep_linking_token(self) -> str:
        """Return a new unique token for deep linking session"""
        return str(uuid.uuid4())

    def _handle_deep_linking_launch(self):
        """Handle LTI Deep Linking launch requests."""
        iss = self.launch_message.get_iss()
        client_id = self.launch_message.get_client_id()
        log.info(
            "LTI 1.3: Deep linking launch for Tool (issuer=%s, client_id=%s)",
            iss,
            client_id,
        )

        if not self._validate_deep_linking_roles():
            # TODO: Add accepted roles to error message
            return get_lti_error_response(
                self.request,
                self.launch_data,
                title="Insufficient Permissions",
                errormsg="You do not have the required role to access deep linking. Contact your administrator.",
                status=403,
            )

        if not self._validate_has_accessible_content():
            log.warning(
                "Tool (issuer=%s, client_id=%s) has no accessible content in its launch gate",
                iss,
                client_id,
            )
            return get_lti_error_response(
                self.request,
                self.launch_data,
                title="No Accessible Content",
                errormsg="Tool does not have access to any content. Please contact your administrator.",
                status=403,
            )

        edx_user = self._authenticate_and_login()
        if not edx_user:
            return self._bad_request_response()

        # Store context and get unique token
        token = self._store_deep_linking_context()

        # Redirect to content selection with token
        return redirect(
            reverse(
                "lti_1p3_provider:deep-linking-select-content", kwargs={"token": token}
            )
        )


class DisplayTargetResource(LtiToolView):
    """Displays content to user if they have appropriate permissions"""

    default_error = "Please relaunch your content from its source to renew your session"

    def get(self, request, course_id: str, usage_id: str) -> HttpResponse:
        if not request.user.is_authenticated:
            log.warning("Anonymous user tried to access %s", self.request.path)
            return self._render_unathorized()

        try:
            has_access = has_lti_session_access(request.session, request.path)
        except MissingSessionError as e:
            log.warning("LTI Session Error: %s @ path: %s", e, self.request.path)
            return self._render_invalid_or_expired_error(e)

        if not has_access:
            log.info("LTI access expired at: %s", self.request.path)
            return self._render_expired_session_error()

        _, usage_key = parse_course_and_usage_keys(course_id, usage_id)
        try:
            return render_courseware(request, usage_key)

        except Http404 as e:
            log.warning("LTI Content DNE: %s. Is it published?", self.request.path)
            return self._render_content_not_found_error()

    def _render_unathorized(self):
        """Return an authorized response"""
        title = "Unauthorized"
        error = (
            "Please relaunch this LTI resource from its original source to access it"
        )
        return render_edx_error(self.request, title, error, status=401)

    def _render_invalid_or_expired_error(self, exc: MissingSessionError):
        """Return an Invalid or Expired Session response"""
        title = "Invalid or Expired Session"
        return render_edx_error(self.request, title, self.default_error, status=401)

    def _render_expired_session_error(self):
        """Render an Expired Session response"""
        title = "Session Expired"
        return render_edx_error(self.request, title, self.default_error, status=401)

    def _render_content_not_found_error(self):
        """Return a Content Not Found response"""
        title = "Content Not Found"
        error = (
            "Sorry, but this content cannot be found. Please contact your "
            "technical support for additional assistance."
        )
        return render_edx_error(self.request, title, error, status=404)


class LtiToolJwksView(LtiToolView):
    """
    JSON Web Key Sets view.
    """

    def get(self, request):
        """
        Return the JWKS.
        """
        return JsonResponse(self.lti_tool_config.get_jwks(), safe=False)


class LtiOrgToolJwksView(LtiToolView):
    """
    JSON Web Key Sets view for a specific org
    """

    def get(self, request, org_short_name: str):
        """
        Return the JWKS.
        """

        return JsonResponse(get_jwks_for_org(org_short_name), safe=False)


@method_decorator(requires_lti_enabled, name="dispatch")
class DeepLinkingContentSelectionView(View):
    """
    Content selection view for LTI Deep Linking.

    Allows users to select content to return to the platform after
    a deep linking launch. Access is controlled by session-based validation.
    """

    def get(self, request, token: str):
        """
        Display content selection interface for deep linking.

        Args:
            token: Unique token for this deep linking session
        """
        try:
            # Validate session has deep linking access for this token
            deep_link_context = self._validate_deep_linking_session(token)
        except DeepLinkingError as e:
            return render_edx_error(request, e.title, e.message, status=e.status_code)

        # TODO: Implement content selection UI
        # For now, return a simple page with hardcoded content selection
        tool_info = deep_link_context.get("tool_info", {})
        return HttpResponse(
            "<h1>Content Selection</h1>"
            "<p>Deep linking content selection interface will be implemented here.</p>"
            f"<p>Tool: {tool_info.get('issuer', 'Unknown')}</p>"
            f"<p>Token: {token[:8]}...</p>"
            "<p>This is a stub implementation.</p>",
            content_type="text/html",
        )

    def post(self, request, token: str):
        """
        Process content selection and return deep linking response.

        Args:
            token: Unique token for this deep linking session
        """
        try:
            # Validate session has deep linking access for this token
            dl_context = self._validate_deep_linking_session(token)
        except DeepLinkingError as e:
            return render_edx_error(request, e.title, e.message, status=e.status_code)

        tool_info = dl_context["tool_info"]
        del self.request.session[token]
        log.info(
            "Removed deep linking session for Tool (issuer=%s, client_id=%s), token %s",
            tool_info["issuer"],
            tool_info["client_id"],
            token[:8] + "...",
        )

        # TODO: Process selected content and generate deep linking response
        # For now, return a stub response

        return HttpResponse(
            "<h1>Content Selected</h1>"
            "<p>Deep linking response generation will be implemented here.</p>"
            f"<p>Token: {token[:8]}...</p>",
            content_type="text/html",
        )

    def _validate_deep_linking_session(self, token: str) -> dict:
        """
        Validate user has valid deep linking session access for the given token.

        Args:
            token: The unique token for this deep linking session

        Returns:
            dict: Deep linking context if valid

        Raises:
            DeepLinkingError: If validation fails with user-friendly message
        """

        # Check if user is authenticated
        if not self.request.user.is_authenticated:
            log.warning("Deep linking access denied: user not authenticated")
            raise DeepLinkingError(
                title="Authentication Required",
                message="Please log in to access this content selection page.",
                status_code=401,
            )

        # Check if session has deep linking context for this token
        session_key = f"lti_deep_link_context_{token}"
        dl_context = self.request.session.get(session_key)
        if not dl_context:
            log.warning(
                "Deep linking access denied: no context for token %s...", token[:8]
            )
            raise DeepLinkingError(
                title="Invalid Access Link",
                message="This content selection link is invalid or expired. Please launch again from your learning platform.",
                status_code=400,
            )

        # Validate token matches (extra security check)
        if dl_context.get("token") != token:
            log.warning(
                "Deep linking access denied: token mismatch for %s...", token[:8]
            )
            # Clear potentially corrupted session
            del self.request.session[session_key]
            raise DeepLinkingError(
                title="Invalid Access Link",
                message="This content selection link is invalid. Please launch again from your learning platform.",
                status_code=400,
            )

        # Check if session hasn't expired
        expires_at = dl_context.get("expires_at")
        if not expires_at:
            log.warning(
                "Deep linking access denied: no expiration in context for token %s...",
                token[:8],
            )
            # Clear potentially corrupted session
            del self.request.session[session_key]
            raise DeepLinkingError(
                title="Invalid Session",
                message="Your content selection session is invalid. Please launch again from your learning platform.",
                status_code=400,
            )

        tool = dl_context["tool_info"]
        if timezone.now().timestamp() > expires_at:
            log.info(
                "Deep linking session expired for Tool (issuer=%s, client_id=%s), token %s...",
                tool["issuer"],
                tool["client_id"],
                token[:8],
            )
            # Clear expired session
            del self.request.session[session_key]
            raise DeepLinkingError(
                title="Session Expired",
                message="Your content selection session has expired. Please launch again from your learning platform to select new content.",
                status_code=403,
            )

        return dl_context


# This was taken from lms/djangoapps/lti_provider
def render_courseware(request, usage_key):
    """
    Render the content requested for the LTI launch.
    TODO: This method depends on the current refactoring work on the
    courseware/courseware.html template. It's signature may change depending on
    the requirements for that template once the refactoring is complete.

    Return an HttpResponse object that contains the template and necessary
    context to render the courseware.

    NOTE: Taken from lms.djangoapps.lti_provider.views. We could use their version
    but then would have to enable LTI 1.1 provider for it to be in installed apps.
    """
    # return an HttpResponse object that contains the template and necessary context to render the courseware.
    from lms.djangoapps.courseware.views.views import render_xblock

    return render_xblock(request, str(usage_key), check_if_enrolled=False)


def parse_course_and_usage_keys(course_id, usage_id):
    """
    Convert course and usage ID strings into key objects. Return a tuple of
    (course_key, usage_key), or throw an InvalidKeyError if the translation
    fails.

    NOTE: Taken from lms.djangoapps.lti_provider.views. We could use their version
    but then would have to enable LTI 1.1 provider for it to be in installed apps.
    """
    course_key = CourseKey.from_string(course_id)
    usage_id = unquote_slashes(usage_id)
    usage_key = UsageKey.from_string(usage_id).map_into_course(course_key)
    return course_key, usage_key
