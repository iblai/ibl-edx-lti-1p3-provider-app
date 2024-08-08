"""
Unit tests for Content Libraries models.
"""

from unittest import mock

import pytest
import requests_mock
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from opaque_keys.edx.keys import CourseKey, UsageKey

from lti_1p3_provider.models import LtiGradedResource, LtiProfile

from . import factories

COURSE_KEY = CourseKey.from_string("course-v1:Org1+Course1+Run1")
USAGE_KEY = COURSE_KEY.make_usage_key("problem", "some-html-id")


class LtiProfileTest(TestCase):
    """
    LtiProfile model tests.
    """

    def test_get_from_claims_doesnotexists(self):
        with self.assertRaises(LtiProfile.DoesNotExist):
            LtiProfile.objects.get_from_claims(iss="iss", aud="aud", sub="sub")

    def test_get_from_claims_exists(self):
        """
        Given a LtiProfile with iss and sub,
        When get_from_claims()
        Then return the same object.
        """

        iss = "http://foo.example.com/"
        sub = "randomly-selected-sub-for-testing"
        aud = "randomly-selected-aud-for-testing"
        profile = LtiProfile.objects.create(
            platform_id=iss, client_id=aud, subject_id=sub
        )

        queried_profile = LtiProfile.objects.get_from_claims(iss=iss, aud=aud, sub=sub)

        self.assertEqual(
            queried_profile,
            profile,
            "The queried profile is equal to the profile created.",
        )

    def test_subject_url(self):
        """
        Given a profile
        Then has a valid subject_url.
        """
        iss = "http://foo.example.com"
        sub = "randomly-selected-sub-for-testing"
        aud = "randomly-selected-aud-for-testing"
        expected_url = "http://foo.example.com/randomly-selected-aud-for-testing/randomly-selected-sub-for-testing"
        profile = LtiProfile.objects.create(
            platform_id=iss, client_id=aud, subject_id=sub
        )
        self.assertEqual(expected_url, profile.subject_url)

    def test_create_with_user(self):
        """
        Given a profile without a user
        When save is called
        Then a user is created.
        """

        iss = "http://foo.example.com/"
        sub = "randomly-selected-sub-for-testing"
        aud = "randomly-selected-aud-for-testing"
        with mock.patch(
            "lti_1p3_provider.models.generate_random_edx_username",
            return_value="rando-username",
        ):
            profile = LtiProfile.objects.create(
                platform_id=iss, client_id=aud, subject_id=sub
            )
        self.assertIsNotNone(profile.user)
        self.assertEqual(profile.user.username, "rando-username")

    def test_get_or_create_from_claims(self):
        """
        Given a profile does not exist
        When get or create
        And get or create again
        Then the same profile is returned.
        """
        iss = "http://foo.example.com/"
        sub = "randomly-selected-sub-for-testing"
        aud = "randomly-selected-aud-for-testing"
        self.assertFalse(LtiProfile.objects.exists())
        profile, created = LtiProfile.objects.get_or_create_from_claims(
            iss=iss, aud=aud, sub=sub
        )
        self.assertIsNotNone(profile.user)
        self.assertEqual(iss, profile.platform_id)
        self.assertEqual(sub, profile.subject_id)
        self.assertTrue(created)

        profile_two, created = LtiProfile.objects.get_or_create_from_claims(
            iss=iss, aud=aud, sub=sub
        )
        self.assertEqual(profile_two, profile)
        self.assertFalse(created)

    def test_get_or_create_from_claims_twice(self):
        """
        Given a profile
        When another profile is created
        Then success
        """
        iss = "http://foo.example.com/"
        aud = "randomly-selected-aud-for-testing"
        sub_one = "randomly-selected-sub-for-testing"
        sub_two = "another-randomly-sub-for-testing"
        self.assertFalse(LtiProfile.objects.exists())
        LtiProfile.objects.get_or_create_from_claims(iss=iss, aud=aud, sub=sub_one)
        LtiProfile.objects.get_or_create_from_claims(iss=iss, aud=aud, sub=sub_two)


@pytest.mark.django_db
class TestLtiGradedResource:
    """
    LtiGradedResource model tests.
    """

    iss = "fake-iss-for-test"

    sub = "fake-sub-for-test"

    aud = "fake-aud-for-test"

    def test_get_from_user_id_when_no_user_then_not_found(self):
        user_id = 0
        with pytest.raises(LtiGradedResource.DoesNotExist):
            LtiGradedResource.objects.get_from_user_id(user_id)

    def test_get_from_user_id_when_no_profile_then_not_found(self):
        user = get_user_model().objects.create(username="foobar")
        with pytest.raises(LtiGradedResource.DoesNotExist):
            LtiGradedResource.objects.get_from_user_id(user.pk)

    def test_get_from_user_id_when_profile_then_found(self):
        profile, _ = LtiProfile.objects.get_or_create_from_claims(
            iss=self.iss, aud=self.aud, sub=self.sub
        )
        LtiGradedResource.objects.create(profile=profile)
        resource = LtiGradedResource.objects.get_from_user_id(profile.user.pk)
        assert profile == resource.profile

    def test_upsert_from_ags_launch(self):
        """
        Give no graded resource
        When get_or_create_from_launch twice
        Then created at first, retrieved at second.
        """

        resource_id = "resource-foobar"
        course_key = COURSE_KEY
        usage_key = USAGE_KEY
        lineitem = "http://canvas.docker/api/lti/courses/1/line_items/7"
        resource_endpoint = {
            "lineitem": lineitem,
            "scope": [
                "https://purl.imsglobal.org/spec/lti-ags/scope/lineitem",
                "https://purl.imsglobal.org/spec/lti-ags/scope/score",
            ],
        }
        resource_link = {
            "id": resource_id,
            "title": "A custom title",
        }

        profile, _ = LtiProfile.objects.get_or_create_from_claims(
            iss=self.iss, aud=self.aud, sub=self.sub
        )
        res = LtiGradedResource.objects.upsert_from_ags_launch(
            profile.user, course_key, usage_key, resource_endpoint, resource_link
        )

        assert resource_id == res.resource_id
        assert lineitem == res.ags_lineitem
        assert usage_key == res.usage_key
        assert profile == res.profile
        assert course_key == res.course_key

        res2 = LtiGradedResource.objects.upsert_from_ags_launch(
            profile.user, course_key, usage_key, resource_endpoint, resource_link
        )

        assert res == res2

    @pytest.mark.parametrize(
        "earned, possible, given", ((0, 0, 0), (0, 1, 0), (5, 10, 0.5))
    )
    def test_update_score(self, earned, possible, given):
        """Check we send the right payload when updating a score"""
        tool = factories.LtiToolFactory()
        now = timezone.now()
        resource = factories.LtiGradedResourceFactory(
            profile__client_id=tool.client_id,
            profile__platform_id=factories.PLATFORM_ISSUER,
        )
        with requests_mock.mock() as m:
            m.post(tool.auth_token_url, json={"access_token": "test-token"})
            m.post(f"{resource.ags_lineitem}/scores", status_code=200)

            resource.update_score(earned, possible, now)
            last_request = m.last_request

        expected_payload = {
            "scoreGiven": given,
            "scoreMaximum": 1,
            "activityProgress": "Submitted",
            "gradingProgress": "FullyGraded",
            "timestamp": now.isoformat(),
            "userId": resource.profile.subject_id,
        }
        assert last_request.json() == expected_payload


@pytest.mark.django_db
class TestLaunchGate:
    def test_can_access_key_empty_sets_returns_false(self):
        """If neither allowed_keys nor allowed_orgs is set, returns False"""
        key = UsageKey.from_string("block-v1:org+course+run+type@some+block@html_id")
        gate = factories.LaunchGateFactory()

        assert not gate.can_access_key(key)

    def test_can_access_key_not_in_allowed_keys_or_allowed_orgs_returns_false(self):
        """If target key not in allowed_keys or allowed_orgs, returns False"""
        allowed_keys = [
            UsageKey.from_string("block-v1:no+course+run+type@some+block@html_id1"),
            UsageKey.from_string("block-v1:no+course+run+type@some+block@html_id2"),
        ]
        allowed_keys = [str(key) for key in allowed_keys]
        allowed_orgs = ["org1", "org2"]
        target_key = UsageKey.from_string(
            "block-v1:bad_org+course+run+type@some+block@html_id"
        )
        # target org not org1/org2, target key not in allowed_keys
        gate = factories.LaunchGateFactory(
            allowed_keys=allowed_keys, allowed_orgs=allowed_orgs
        )

        assert not gate.can_access_key(target_key)

    def test_can_access_key_allowed_keys_match_returns_true(self):
        """If target key in allowed_keys, returns True"""
        allowed_keys = [
            UsageKey.from_string("block-v1:org+course+run+type@some+block@html_id1"),
            UsageKey.from_string("block-v1:org+course+run+type@some+block@html_id2"),
        ]
        key = allowed_keys[1]
        allowed_keys = [str(key) for key in allowed_keys]
        gate = factories.LaunchGateFactory(allowed_keys=allowed_keys)

        assert gate.can_access_key(key)

    @pytest.mark.parametrize(
        "key",
        (
            UsageKey.from_string("block-v1:org1+course+run+type@some+block@html_id"),
            UsageKey.from_string("block-v1:org1+course+run+type@verical+block@html_id"),
            UsageKey.from_string("block-v1:org2+other+run+type@some+block@html_id"),
        ),
    )
    def test_can_access_key_allowed_orgs_match_returns_true(self, key):
        """If target key in allowed_orgs, returns True"""
        gate = factories.LaunchGateFactory(allowed_orgs=["org1", "org2"])

        assert gate.can_access_key(key)
