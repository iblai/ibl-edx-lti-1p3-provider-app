"""
Tests for the LTI outcome service handlers, both in outcomes.py and in tasks.py
"""


from unittest.mock import MagicMock, patch

import pytest
from common.djangoapps.student.tests.factories import UserFactory
from django.utils import timezone
from opaque_keys.edx.locator import BlockUsageLocator, CourseLocator

from lti_1p3_provider import tasks

from . import factories


@pytest.mark.django_db
class BaseOutcomeTest:
    """
    Super type for tests of both the leaf and composite outcome celery tasks.
    """

    def setup_method(self):
        self.course_key = CourseLocator(
            org="some_org", course="some_course", run="some_run"
        )
        self.usage_key = BlockUsageLocator(
            course_key=self.course_key, block_type="problem", block_id="block_id"
        )
        self.tool = factories.LtiToolFactory()
        self.profile = factories.LtiProfileFactory()
        self.graded_resource = factories.LtiGradedResourceFactory(profile=self.profile)


class TestSendLeafScore(BaseOutcomeTest):
    """
    Tests for the send_leaf_score method in tasks.py
    """

    @patch("lti_1p3_provider.models.LtiGradedResource.update_score")
    def test_calls_update_score_with_proper_args(self, mock_update_score):
        earned = 1.0
        possible = 2.0
        modified = timezone.now()
        tasks.send_leaf_score(self.graded_resource.id, earned, possible, modified)
        mock_update_score.assert_called_once_with(earned, possible, modified)


@pytest.mark.skip
class SendCompositeOutcomeTest(BaseOutcomeTest):
    """
    Tests for the send_composite_outcome method in tasks.py
    """

    def setUp(self):
        super().setUp()
        self.descriptor = MagicMock()
        self.descriptor.location = BlockUsageLocator(
            course_key=self.course_key,
            block_type="problem",
            block_id="problem",
        )
        self.course_grade = MagicMock()
        self.course_grade_mock = self.setup_patch(
            "lms.djangoapps.lti_provider.tasks.CourseGradeFactory.read",
            self.course_grade,
        )
        self.module_store = MagicMock()
        self.module_store.get_item = MagicMock(return_value=self.descriptor)
        self.check_result_mock = self.setup_patch(
            "lms.djangoapps.lti_provider.tasks.modulestore", self.module_store
        )

    def test_outcome_with_score_score(self, earned, possible, expected):
        self.course_grade.score_for_module = MagicMock(return_value=(earned, possible))
        tasks.send_composite_outcome(
            self.user.id, str(self.course_key), self.assignment.id, 1
        )
        self.send_score_update_mock.assert_called_once_with(self.assignment, expected)

    def test_outcome_with_outdated_version(self):
        self.assignment.version_number = 2
        self.assignment.save()
        tasks.send_composite_outcome(
            self.user.id, str(self.course_key), self.assignment.id, 1
        )
        assert self.course_grade_mock.call_count == 0
