"""
=======================
Content Libraries Views
=======================

This module contains the REST APIs for blockstore-based content libraries, and
LTI 1.3 views.
"""


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
from opaque_keys.edx.keys import UsageKey
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

    def _authenticate_and_login(self, usage_key):
        """
        Authenticate and authorize the user for this LTI message launch.

        We automatically create LTI profile for every valid launch, and
        authenticate the LTI user associated with it.
        """

        # Check library authorization.

        # TODO: Update this check appropriately
        log.warning("Check ContentLibrary.authiorize_lti_launch")
        # if not ContentLibrary.authorize_lti_launch(
        #     usage_key.lib_key,
        #     issuer=self.launch_data["iss"],
        #     client_id=self.launch_data["aud"],
        # ):
        #     return None

        # Check LTI profile.

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
            # TODO: Do we need any of this?
            # perms = api.get_library_user_permissions(
            #     usage_key.lib_key, self.request.user
            # )
            # if not perms:
            #     api.set_library_user_permissions(
            #         usage_key.lib_key, self.request.user, api.AccessLevel.ADMIN_LEVEL
            #     )
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

    def get_context_data(self):
        """
        Setup the template context data.
        """

        handler_urls = {
            str(key): xblock_api.get_handler_url(key, "handler_name", self.request.user)
            for key in itertools.chain(
                [self.block.scope_ids.usage_id], getattr(self.block, "children", [])
            )
        }

        # We are defaulting to student view due to current use case (resource
        # link launches).  Launches within other views are not currently
        # supported.
        fragment = self.block.render("student_view")
        lms_root_url = configuration_helpers.get_value(
            "LMS_ROOT_URL", settings.LMS_ROOT_URL
        )
        return {
            "fragment": fragment,
            "handler_urls_json": json.dumps(handler_urls),
            "lms_root_url": lms_root_url,
        }

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
    def post(self, request):
        """
        Process LTI platform launch requests.
        """

        # Parse LTI launch message.

        try:
            self.launch_message = self.get_launch_message()
        except LtiException as exc:
            log.exception("LTI 1.3: Tool launch failed: %s", exc)
            return self._bad_request_response()

        log.info("LTI 1.3: Launch message body: %s", json.dumps(self.launch_data))

        # Parse content key.

        # TODO: It's a POST but they are expecting some GET params?
        usage_key_str = request.GET.get("id")
        if not usage_key_str:
            return self._bad_request_response()

        # TODO: Probably change this into a UsageKey
        usage_key = UsageKey.from_string(usage_key_str)
        log.info("LTI 1.3: Launch block: id=%s", usage_key)

        # Authenticate the launch and setup LTI profiles.

        edx_user = self._authenticate_and_login(usage_key)
        if not edx_user:
            return self._bad_request_response()

        # Get the block.
        # NOTE: We don't need this
        # self.block = xblock_api.load_block(usage_key, user=self.request.user)

        # Handle Assignment and Grade Service request.

        # TODO: Evaluate if we need to update this?
        self.handle_ags()

        # Render context and response.
        # TODO: Probably use the same rendering from lti 1.1 here for simplicity
        # context = self.get_context_data()
        response = render_courseware(request, usage_key)
        mark_user_change_as_expected(edx_user.id)
        return response

    def handle_ags(self):
        """
        Handle AGS-enabled launches for block in the request.
        """

        # Validate AGS.

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
