"""
Unit tests for Content Libraries authentication module.
"""


from django.test import TestCase


from lti_1p3_provider.models import LtiProfile
from lti_1p3_provider.models import get_user_model
from lti_1p3_provider.auth import Lti1p3AuthenticationBackend


class LtiAuthenticationBackendTest(TestCase):
    """
    AuthenticationBackend tests.
    """

    iss = "http://foo.bar"
    aud = "a-random-test-aud"
    sub = "a-random-test-sub"

    def test_without_profile(self):
        get_user_model().objects.create(username="foobar")
        backend = Lti1p3AuthenticationBackend()
        user = backend.authenticate(None, iss=self.iss, aud=self.aud, sub=self.sub)
        self.assertIsNone(user)

    def test_with_profile(self):
        profile = LtiProfile.objects.create(
            platform_id=self.iss, client_id=self.aud, subject_id=self.sub
        )
        backend = Lti1p3AuthenticationBackend()
        user = backend.authenticate(None, iss=self.iss, aud=self.aud, sub=self.sub)
        self.assertIsNotNone(user)
        self.assertEqual(user.lti_1p3_provider_lti_profile, profile)
