"""
URL configuration for LTI 1.3 Provider
"""
from django.conf import settings
from django.urls import path, re_path

from . import views

urlpatterns = [
    path("login/", views.LtiToolLoginView.as_view(), name="lti-login"),
    re_path("launch/", views.LtiToolLaunchView.as_view(), name="lti-launch"),
    path("pub/jwks/", views.LtiToolJwksView.as_view(), name="lti-pub-jwks"),
]
