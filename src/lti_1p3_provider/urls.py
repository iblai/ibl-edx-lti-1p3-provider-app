"""
URL configuration for LTI 1.3 Provider
"""
from django.urls import include, path, re_path

from . import views

urlpatterns = [
    re_path(
        r"^lti/1.3/",
        include(
            [
                path("login/", views.LtiToolLoginView.as_view(), name="lti-login"),
                path("launch/", views.LtiToolLaunchView.as_view(), name="lti-launch"),
                path("pub/jwks/", views.LtiToolJwksView.as_view(), name="lti-pub-jwks"),
            ]
        ),
    ),
]
