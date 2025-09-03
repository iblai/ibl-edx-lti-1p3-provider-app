"""
URL configuration for LTI 1.3 Provider
"""

from django.conf import settings
from django.urls import include, path, re_path

from . import views
from .api.urls import router as api_router

urlpatterns = [
    path("login/", views.LtiToolLoginView.as_view(), name="lti-login"),
    path("launch/", views.LtiToolLaunchView.as_view(), name="lti-launch"),
    path(
        "/orgs/<slug:org_short_name>/deep-link-launch/",
        views.LtiToolLaunchView.as_view(),
        name="deep-link-launch",
    ),
    re_path(
        f"launch/{settings.COURSE_ID_PATTERN}/{settings.USAGE_ID_PATTERN}$",
        views.DisplayTargetResource.as_view(),
        name="lti-display",
    ),
    path("pub/jwks/", views.LtiToolJwksView.as_view(), name="lti-pub-jwks"),
    path(
        "pub/orgs/<slug:org_short_name>/jwks/",
        views.LtiOrgToolJwksView.as_view(),
        name="lti-pub-org-jwks",
    ),
    # API urls
    path("api/orgs/<slug:org_short_name>/", include(api_router.urls)),
]
