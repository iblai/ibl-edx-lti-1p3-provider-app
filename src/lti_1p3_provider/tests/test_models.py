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
        email = ""
        self.assertFalse(LtiProfile.objects.exists())
        profile = LtiProfile.objects.get_or_create_from_claims(
            iss=iss, aud=aud, sub=sub, email=email
        )
        self.assertIsNotNone(profile.user)
        self.assertEqual(iss, profile.platform_id)
        self.assertEqual(sub, profile.subject_id)

        profile_two = LtiProfile.objects.get_or_create_from_claims(
            iss=iss, aud=aud, sub=sub, email=email
        )
        self.assertEqual(profile_two, profile)

    def test_get_or_create_from_claims_with_email(self):
        """
        Given a profile does not exist
        When get or create with email
        And get or create again
        Then the same profile is returned.
        """
        iss = "http://foo.example.com/"
        sub = "randomly-selected-sub-for-testing"
        aud = "randomly-selected-aud-for-testing"
        email = "test@example.com"
        self.assertFalse(LtiProfile.objects.exists())
        profile = LtiProfile.objects.get_or_create_from_claims(
            iss=iss, aud=aud, sub=sub, email=email
        )
        self.assertIsNotNone(profile.user)
        self.assertEqual(iss, profile.platform_id)
        self.assertEqual(sub, profile.subject_id)

        profile_two = LtiProfile.objects.get_or_create_from_claims(
            iss=iss, aud=aud, sub=sub, email=email
        )
        self.assertEqual(profile_two, profile)

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
        LtiProfile.objects.get_or_create_from_claims(
            iss=iss, aud=aud, sub=sub_one, email=""
        )
        LtiProfile.objects.get_or_create_from_claims(
            iss=iss, aud=aud, sub=sub_two, email=""
        )

    def test_get_or_create_from_claims_twice_with_email(self):
        """
        Given a profile
        When another profile is created with email
        Then success
        """
        iss = "http://foo.example.com/"
        aud = "randomly-selected-aud-for-testing"
        sub_one = "randomly-selected-sub-for-testing"
        email1 = "test1@example.com"
        sub_two = "another-randomly-sub-for-testing"
        email2 = "test2@example.com"
        self.assertFalse(LtiProfile.objects.exists())
        LtiProfile.objects.get_or_create_from_claims(
            iss=iss, aud=aud, sub=sub_one, email=email1
        )
        LtiProfile.objects.get_or_create_from_claims(
            iss=iss, aud=aud, sub=sub_two, email=email2
        )


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
        profile = LtiProfile.objects.get_or_create_from_claims(
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

        profile = LtiProfile.objects.get_or_create_from_claims(
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


class TestLaunchGateCanAccessKeyNoBlockTypeFilters:
    """Tests can_access_key when no block type filters are set"""

    def test_empty_sets_returns_false(self):
        """If not allowed_keys, allowed_courses, or allowed_orgs is set, returns False"""
        key = UsageKey.from_string("block-v1:org+course+run+type@some+block@html_id")
        gate = factories.LaunchGateFactory.build()

        assert not gate.can_access_key(key)

    def test_key_not_in_keys_or_courses_or_orgs_returns_false(self):
        """If target key not in allowed_keys or allowed_orgs, returns False"""
        allowed_keys = [
            UsageKey.from_string("block-v1:no+course+run+type@some+block@html_id1"),
            UsageKey.from_string("block-v1:no+course+run+type@some+block@html_id2"),
        ]
        allowed_courses = [str(allowed_keys[0].course_key)]
        allowed_keys = [str(key) for key in allowed_keys]
        allowed_orgs = ["org1", "org2"]
        target_key = UsageKey.from_string(
            "block-v1:bad_org+course+run+type@some+block@html_id"
        )
        # target org not org1/org2, target key not in allowed_keys, not in
        # allowed_courses
        gate = factories.LaunchGateFactory.build(
            allowed_keys=allowed_keys,
            allowed_courses=allowed_courses,
            allowed_orgs=allowed_orgs,
        )

        assert not gate.can_access_key(target_key)

    def test_key_in_allowed_keys_returns_true(self):
        """If target key in allowed_keys, returns True"""
        allowed_keys = [
            UsageKey.from_string("block-v1:org+course+run+type@some+block@html_id1"),
            UsageKey.from_string("block-v1:org+course+run+type@some+block@html_id2"),
        ]
        key = allowed_keys[1]
        allowed_keys = [str(key) for key in allowed_keys]
        gate = factories.LaunchGateFactory.build(allowed_keys=allowed_keys)

        assert gate.can_access_key(key)

    @pytest.mark.parametrize(
        "key",
        (
            UsageKey.from_string("block-v1:org1+course+run+type@some+block@html_id"),
            UsageKey.from_string("block-v1:org1+course+run+type@verical+block@html_id"),
            UsageKey.from_string("block-v1:org2+other+run+type@some+block@html_id"),
        ),
    )
    def test_key_in_allowed_orgs_returns_true(self, key):
        """If target key in allowed_orgs, returns True"""
        gate = factories.LaunchGateFactory.build(allowed_orgs=["org1", "org2"])

        assert gate.can_access_key(key)

    @pytest.mark.parametrize(
        "key",
        (
            UsageKey.from_string("block-v1:org1+course+run+type@some+block@html_id"),
            UsageKey.from_string("block-v1:org1+course+run+type@verical+block@html_id"),
            UsageKey.from_string("block-v1:org2+other+run+type@some+block@html_id"),
        ),
    )
    def test_key_in_allowed_courses_returns_true(self, key):
        """If target key in allowed_courses, returns True"""
        course1 = CourseKey.from_string("course-v1:org1+course+run")
        course2 = CourseKey.from_string("course-v1:org2+other+run")
        gate = factories.LaunchGateFactory.build(
            allowed_courses=[str(course1), str(course2)]
        )

        assert gate.can_access_key(key)


class TestLaunchGateCanAccessKeyWithBlockTypeFilters:
    @pytest.mark.parametrize(
        "block_type,expected",
        [
            ("unknown", False),
            ("html", True),
        ],
    )
    def test_block_filter(self, block_type, expected):
        """Test if target key's block type is allowed by global block filter"""
        gate = factories.LaunchGateFactory.build(
            allowed_orgs=["org1"], block_filter=["html"]
        )
        key = UsageKey.from_string(
            f"block-v1:org1+course+run+type@{block_type}+block@html_id"
        )

        assert gate.can_access_key(key) is expected

    @pytest.mark.parametrize(
        "course, block_type, expected",
        (
            # only specific types for course1 are allowed
            ("course1", "html", True),
            ("course1", "video", True),
            ("course1", "problem", False),
            ("course1", "vertical", False),
            # All types for course2 are allowed since no specific filter for them
            ("course2", "html", True),
            ("course2", "video", True),
            ("course2", "problem", True),
            ("course2", "vertical", True),
        ),
    )
    def test_course_block_filter(self, course, block_type, expected):
        """If target key's block type in course block filter, returns True"""
        # All keys from org1 are allowed; only html and video are allowed for course1
        # All other keys are allowed for all other courses in org1
        gate = factories.LaunchGateFactory.build(
            allowed_orgs=["org1"],
            course_block_filter={"course-v1:org1+course1+run": ["html", "video"]},
        )
        key = UsageKey.from_string(
            f"block-v1:org1+{course}+run+type@{block_type}+block@html_id"
        )

        assert gate.can_access_key(key) is expected

    @pytest.mark.parametrize(
        "org, course, block_type, expected",
        (
            # only specific types for org1 are allowed
            ("org1", "course1", "html", True),
            ("org1", "course2", "video", True),
            ("org1", "course1", "problem", False),
            ("org1", "course2", "vertical", False),
            # All types for org2 are allowed since no specific filter for them
            ("org2", "course1", "html", True),
            ("org2", "course2", "video", True),
            ("org2", "course1", "problem", True),
            ("org2", "course2", "vertical", True),
        ),
    )
    def test_org_block_filter(self, org, course, block_type, expected):
        """If target key's block type in org block filter, returns True"""
        # only html/video blocks allowed for courses in org 1
        # all types allowed for courses in org 2
        gate = factories.LaunchGateFactory.build(
            allowed_orgs=["org1", "org2"],
            org_block_filter={"org1": ["html", "video"]},
        )
        key = UsageKey.from_string(
            f"block-v1:{org}+{course}+run+type@{block_type}+block@html_id"
        )

        assert gate.can_access_key(key) is expected

    @pytest.mark.parametrize(
        "org, course, block_type, expected",
        (
            # only specific html/video allowed for course1 are allowed
            ("org1", "course1", "html", True),
            ("org1", "course1", "video", True),
            ("org1", "course1", "problem", False),
            ("org1", "course1", "vertical", False),
            # only problems allowed for all other courses in org 1
            ("org1", "course2", "problem", True),
            ("org1", "course3", "problem", True),
            ("org1", "course2", "html", False),
            ("org1", "course3", "video", False),
            # All types for org2 are allowed since no specific filter for them
            ("org2", "course1", "html", True),
            ("org2", "course2", "video", True),
            ("org2", "course1", "problem", True),
            ("org2", "course2", "vertical", True),
        ),
    )
    def test_course_and_org_block_filter(self, org, course, block_type, expected):
        """If target key's block type in course and org block filter, returns True"""
        # only html/video blocks allowed for course1 in org 1
        # Only problems allowed for all other courses in org 1
        # all types allowed for courses in org 2
        gate = factories.LaunchGateFactory.build(
            allowed_orgs=["org1", "org2"],
            course_block_filter={"course-v1:org1+course1+run": ["html", "video"]},
            org_block_filter={"org1": ["problem"]},
        )
        key = UsageKey.from_string(
            f"block-v1:{org}+{course}+run+type@{block_type}+block@html_id"
        )

        assert gate.can_access_key(key) is expected

    @pytest.mark.parametrize(
        "org, course, block_type, expected",
        (
            # only specific html/video allowed for course1 are allowed
            ("org1", "course1", "html", True),
            ("org1", "course1", "video", True),
            ("org1", "course1", "problem", False),
            ("org1", "course1", "vertical", False),
            # only problems allowed for all other courses in org 1
            ("org1", "course2", "problem", True),
            ("org1", "course3", "problem", True),
            ("org1", "course2", "html", False),
            ("org1", "course3", "video", False),
            # Only verticals are allowed in all other orgs/courses
            ("org3", "course1", "html", False),
            ("org3", "course2", "video", False),
            ("org3", "course1", "problem", False),
            ("org3", "course2", "vertical", True),
        ),
    )
    def test_course_and_org_and_block_filter(self, org, course, block_type, expected):
        """If target key's block type in course and org block filter, returns True"""
        # only html/video blocks allowed for course1 in org 1
        # Only problems allowed for all other courses in org 1
        # only vertical blocks allowed for all other keys in any org/cours
        gate = factories.LaunchGateFactory.build(
            allowed_orgs=["org1", "org2", "org3"],
            course_block_filter={"course-v1:org1+course1+run": ["html", "video"]},
            org_block_filter={"org1": ["problem"]},
            block_filter=["vertical"],
        )
        key = UsageKey.from_string(
            f"block-v1:{org}+{course}+run+type@{block_type}+block@html_id"
        )

        assert gate.can_access_key(key) is expected

    def test_empty_course_block_filter_blocks_nothing(self):
        """Empty course block filter should block nothing (not everything)"""
        gate = factories.LaunchGateFactory.build(
            allowed_orgs=["org1"],
            course_block_filter={"course-v1:org1+course1+run": []},  # Empty list
        )
        key = UsageKey.from_string("block-v1:org1+course1+run+type@html+block@html_id")

        # Should return True because empty list means "no filtering"
        assert gate.can_access_key(key) is True

    def test_empty_org_block_filter_blocks_nothing(self):
        """Empty org block filter should block nothing (not everything)"""
        gate = factories.LaunchGateFactory.build(
            allowed_orgs=["org1"],
            org_block_filter={"org1": []},  # Empty list
        )
        key = UsageKey.from_string("block-v1:org1+course1+run+type@html+block@html_id")

        # Should return True because empty list means "no filtering"
        assert gate.can_access_key(key) is True

    @pytest.mark.parametrize(
        "course, block_type, expected",
        (
            # Course1 has empty filter - should allow all block types
            ("course1", "html", True),
            ("course1", "video", True),
            ("course1", "problem", True),
            ("course1", "vertical", True),
            # Course2 has non-empty filter - should only allow html and video
            ("course2", "html", True),
            ("course2", "video", True),
            ("course2", "problem", False),
            ("course2", "vertical", False),
        ),
    )
    def test_mixed_empty_and_non_empty_course_filters(
        self, course, block_type, expected
    ):
        """Mixed empty and non-empty course filters should work correctly"""
        gate = factories.LaunchGateFactory.build(
            allowed_orgs=["org1"],
            course_block_filter={
                "course-v1:org1+course1+run": [],  # Empty - no filtering
                "course-v1:org1+course2+run": [
                    "html",
                    "video",
                ],  # Non-empty - filtering
            },
        )
        key = UsageKey.from_string(
            f"block-v1:org1+{course}+run+type@{block_type}+block@html_id"
        )

        assert gate.can_access_key(key) is expected

    def test_all_access_controls_empty_returns_false(self):
        """When all access controls are empty lists, should return False"""
        gate = factories.LaunchGateFactory.build(
            allowed_keys=[],
            allowed_courses=[],
            allowed_orgs=[],
        )
        key = UsageKey.from_string("block-v1:org1+course1+run+type@html+block@html_id")

        # Should return False because no access is granted
        assert gate.can_access_key(key) is False
