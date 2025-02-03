"""
Unit tests for Content Libraries authentication module.
"""

from django.test import TestCase

from lti_1p3_provider.auth import Lti1p3AuthenticationBackend
from lti_1p3_provider.models import LtiProfile, get_user_model


class LtiAuthenticationBackendTest(TestCase):
    """
    AuthenticationBackend tests.
    """

    iss = "http://foo.bar"
    aud = "a-random-test-aud"
    sub = "a-random-test-sub"
    email = "test@example.com"

    def test_without_profile(self):
        get_user_model().objects.create(username="foobar")
        backend = Lti1p3AuthenticationBackend()
        user = backend.authenticate(None, iss=self.iss, aud=self.aud, sub=self.sub)
        self.assertIsNone(user)

    def test_with_profile(self):
        profile = LtiProfile.objects.get_or_create_from_claims(
            iss=self.iss, aud=self.aud, sub=self.sub
        )
        backend = Lti1p3AuthenticationBackend()
        user = backend.authenticate(None, iss=self.iss, aud=self.aud, sub=self.sub)
        self.assertIsNotNone(user)
        self.assertEqual(user.lti_1p3_provider_lti_profile, profile)

    def test_with_profile_and_email(self):
        """Email is not considered when doing lookups"""
        profile = LtiProfile.objects.get_or_create_from_claims(
            iss=self.iss, aud=self.aud, sub=self.sub, email=self.email
        )
        backend = Lti1p3AuthenticationBackend()
        user = backend.authenticate(None, iss=self.iss, aud=self.aud, sub=self.sub)
        self.assertIsNotNone(user)
        self.assertEqual(user.lti_1p3_provider_lti_profile, profile)

    def test_inactive_user_returns_none(self):
        profile = LtiProfile.objects.get_or_create_from_claims(
            iss=self.iss, aud=self.aud, sub=self.sub
        )
        user = profile.user
        user.is_active = False
        user.save()
        backend = Lti1p3AuthenticationBackend()
        user = backend.authenticate(None, iss=self.iss, aud=self.aud, sub=self.sub)
        self.assertIsNone(user)
