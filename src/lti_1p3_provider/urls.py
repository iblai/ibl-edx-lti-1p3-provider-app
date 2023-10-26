"""
URL configuration for LTI 1.3 Provider
"""
from django.conf import settings
from django.urls import path, re_path

from . import views

urlpatterns = [
    path("login/", views.LtiToolLoginView.as_view(), name="lti-login"),
    path("launch/", views.LtiToolLaunchView.as_view(), name="lti-launch"),
    re_path(
        f"launch/{settings.COURSE_ID_PATTERN}/{settings.USAGE_ID_PATTERN}$",
        views.DisplayTargetResource.as_view(),
        name="lti-display",
    ),
    path("pub/jwks/", views.LtiToolJwksView.as_view(), name="lti-pub-jwks"),
]
