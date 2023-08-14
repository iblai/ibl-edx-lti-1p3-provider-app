"""
=======================
Content Libraries Views
=======================

This module contains the REST APIs for blockstore-based content libraries, and
LTI 1.3 views.
"""

from __future__ import annotations

import itertools
import json
import logging

import openedx.core.djangoapps.site_configuration.helpers as configuration_helpers
from django.conf import settings
from django.contrib.auth import authenticate, get_user_model, login
from django.http import Http404, HttpResponseBadRequest, JsonResponse
from django.utils.decorators import method_decorator
from django.utils.translation import gettext as _
from django.views.decorators.clickjacking import xframe_options_exempt
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.base import View
from opaque_keys.edx.keys import UsageKey, CourseKey
from opaque_keys import InvalidKeyError
from openedx.core.djangoapps.content_libraries import api
from openedx.core.djangoapps.safe_sessions.middleware import (
    mark_user_change_as_expected,
)
from openedx.core.djangoapps.xblock import api as xblock_api
from pylti1p3.contrib.django import (
    DjangoCacheDataStorage,
    DjangoDbToolConf,
    DjangoMessageLaunch,
    DjangoOIDCLogin,
)
from pylti1p3.exception import LtiException, OIDCException

from .models import LtiGradedResource, LtiProfile

User = get_user_model()
log = logging.getLogger(__name__)


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
        launch_url = self.request.POST.get(
            self.LAUNCH_URI_PARAMETER
        ) or self.request.GET.get(self.LAUNCH_URI_PARAMETER)
        try:
            return oidc_login.redirect(launch_url)
        except OIDCException as exc:
            # Relying on downstream error messages, attempt to sanitize it up
            # for customer facing errors.
            log.error("LTI OIDC login failed: %s", exc)
            return HttpResponseBadRequest("Invalid LTI login request.")


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
        return self.launch_message.get_launch_data()

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
        # TODO: See if this could conflict with the content_libraries.auth imp
        edx_user = authenticate(
            self.request,
            iss=self.launch_data["iss"],
            aud=self.launch_data["aud"],
            sub=self.launch_data["sub"],
        )

        if edx_user is not None:
            login(self.request, edx_user)
            log.info("Logged in user: %s", edx_user)
        else:
            log.warning(
                "Unable to login user %s from iss %s with aud %s)",
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

    # pylint: disable=attribute-defined-outside-init
    def post(self, request, course_id: str, usage_id: str):
        """
        Process LTI platform launch requests.
        """

        # Parse LTI launch message.

        try:
            course_key, usage_key = self._parse_course_and_usage_keys(
                course_id, usage_id
            )
            log.info("LTI 1.3: Launch course=%s, block: id=%s", course_key, usage_key)
            self.launch_message = self.get_launch_message()

        except InvalidKeyError as e:
            log.error("Invalid Launch Course or UsageKey - %s")
            # TODO: Improve this to be more specific
            return HttpResponseBadRequest(f"Invalid Course or Key: {e}")

        except LtiException as exc:
            log.exception("LTI 1.3: Tool launch failed: %s", exc)
            return self._bad_request_response()

        log.info("LTI 1.3: Launch message body: %s", json.dumps(self.launch_data))

        edx_user = self._authenticate_and_login()
        if not edx_user:
            return self._bad_request_response()

        # TODO: Evaluate if we need to update this?
        self.handle_ags()

        # Render context and response.
        # TODO: Probably use the same rendering from lti 1.1 here for simplicity
        response = render_courseware(request, usage_key)
        mark_user_change_as_expected(edx_user.id)
        return response

    def _parse_course_and_usage_keys(
        self, course_id: str, usage_id: str
    ) -> tuple[CourseKey, UsageKey]:
        """Return CourseKey and UsageKey from course_id and usage_id"""
        course_key = CourseKey.formatter(course_id)
        usage_key = UsageKey.from_string(usage_id).map_into_course(course_key)
        return course_key, usage_key

    def handle_ags(self):
        """
        Handle AGS-enabled launches for block in the request.
        # NOTE: No test coverage here
        """
        if not self.launch_message.has_ags():
            return

        endpoint_claim = "https://purl.imsglobal.org/spec/lti-ags/claim/endpoint"
        endpoint = self.launch_data[endpoint_claim]
        required_scopes = [
            "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem",
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
                "request: %s",
                endpoint,
            )
            return

        # Create graded resource in the database for the current launch.

        resource_claim = "https://purl.imsglobal.org/spec/lti/claim/resource_link"
        resource_link = self.launch_data.get(resource_claim)

        # TODO: Check exactly what upsert is doing and if we need to modify it
        resource = LtiGradedResource.objects.upsert_from_ags_launch(
            self.request.user, self.block, endpoint, resource_link
        )

        log.info("LTI 1.3: AGS: Upserted LTI graded resource from launch: %s", resource)


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
    """
    # return an HttpResponse object that contains the template and necessary context to render the courseware.
    from lms.djangoapps.courseware.views.views import render_xblock

    return render_xblock(request, str(usage_key), check_if_enrolled=False)
