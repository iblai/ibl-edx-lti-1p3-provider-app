"""
=======================
Content Libraries Views
=======================

This module contains the REST APIs for blockstore-based content libraries, and
LTI 1.3 views.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta
from urllib import parse

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
from django.utils.translation import gettext as _
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

from .error_response import get_lti_error_response, render_edx_error
from .exceptions import MissingSessionError
from .models import LtiGradedResource, LtiProfile
from .session_access import has_lti_session_access, set_lti_session_access

log = logging.getLogger(__name__)
User = get_user_model()


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
                error=(
                    f"{exc}. Please contact your technical support for additional "
                    "assistance."
                ),
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

        LtiProfile.objects.get_or_create_from_claims(
            iss=self.launch_data["iss"],
            aud=self.launch_data["aud"],
            sub=self.launch_data["sub"],
        )
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
        # TODO: Add an optional gate for permissions/purchasing checks of some kind

        try:
            self.launch_message = self.get_launch_message()
            course_id, usage_id = self._get_course_and_usage_id()
            course_key, usage_key = parse_course_and_usage_keys(course_id, usage_id)
            # TODO: Add client
            log.info("LTI 1.3: Launch course=%s, block: id=%s", course_key, usage_key)

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
            errormsg = (
                f"{exc}. Please contact your technical support for additional "
                "assistance."
            )
            return get_lti_error_response(
                request, self.launch_data, errormsg=errormsg, status=400
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

        log.info("LTI 1.3: Launch message body: %s", json.dumps(self.launch_data))

        edx_user = self._authenticate_and_login()
        if not edx_user:
            return self._bad_request_response()

        self.handle_ags(course_key, usage_key)
        self._set_session_access()
        return redirect(self._get_target_link_uri())

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

    def _get_target_link_uri(self) -> str:
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
                    "LTI 1.3: AGS: LTI platform does not support a required "
                    "scope: %s",
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
