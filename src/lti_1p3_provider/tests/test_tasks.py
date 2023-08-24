"""
Tests for the LTI outcome service handlers, both in outcomes.py and in tasks.py
"""


from unittest.mock import MagicMock, patch

import pytest
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
        modified_dt = modified.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        tasks.send_leaf_score(self.graded_resource.id, earned, possible, modified_dt)
        mock_update_score.assert_called_once_with(earned, possible, modified)


@pytest.fixture
def mock_course_grade():
    with patch("lti_1p3_provider.tasks.CourseGradeFactory.read") as course_grade:
        yield course_grade


@pytest.fixture
def mock_mod_store():
    descriptor = MagicMock()
    descriptor.location = BlockUsageLocator(
        course_key=factories.COURSE_KEY,
        block_type="problem",
        block_id="problem",
    )
    with patch("lti_1p3_provider.tasks.modulestore") as mod_store:
        mod_store.get_item = MagicMock(return_value=descriptor)
        yield mod_store


class TestSendCompositescore(BaseOutcomeTest):
    """
    Tests for the send_composite_score method in tasks.py
    """

    @patch("lti_1p3_provider.models.LtiGradedResource.update_score")
    def test_calls_update_score(
        self, mock_update_score, mock_course_grade, mock_mod_store
    ):
        earned = 1
        possible = 2
        modified = timezone.now()
        modified_dt = modified.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        mock_score = MagicMock()
        mock_score.score_for_module = MagicMock(return_value=(earned, possible))
        mock_course_grade.return_value = mock_score

        tasks.send_composite_score(
            self.profile.user.id,
            str(factories.COURSE_KEY),
            self.graded_resource.id,
            0,
            modified_dt,
        )

        mock_update_score.assert_called_once_with(earned, possible, modified)

    @patch("lti_1p3_provider.models.LtiGradedResource.update_score")
    def test_outdated_version_doesnt_calc_or_send_score(
        self, mock_update_score, mock_course_grade, mock_mod_store
    ):
        earned = 1
        possible = 2
        modified = timezone.now()
        modified_dt = modified.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        mock_score = MagicMock()
        mock_score.score_for_module = MagicMock(return_value=(earned, possible))
        mock_course_grade.return_value = mock_score

        # Version number won't match what is sent now
        self.graded_resource.version_number = 1
        self.graded_resource.save()

        tasks.send_composite_score(
            self.profile.user.id,
            str(factories.COURSE_KEY),
            self.graded_resource.id,
            0,
            modified_dt,
        )

        mock_score.score_for_module.assert_not_called()
        mock_update_score.assert_not_called()

    @patch("lti_1p3_provider.models.LtiGradedResource.update_score")
    def test_outdated_version_after_score_calc_doesnt_send_score(
        self, mock_update_score, mock_course_grade, mock_mod_store
    ):
        """Test version is updated after score calclated, doesn't send score"""
        earned = 1
        possible = 2

        def _inc_version(usage_key):
            self.graded_resource.version_number = 1
            self.graded_resource.save()
            return earned, possible

        modified = timezone.now()
        modified_dt = modified.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        mock_score = MagicMock()
        mock_score.score_for_module = MagicMock(side_effect=_inc_version)
        mock_course_grade.return_value = mock_score

        tasks.send_composite_score(
            self.profile.user.id,
            str(factories.COURSE_KEY),
            self.graded_resource.id,
            0,
            modified_dt,
        )

        mock_score.score_for_module.assert_called_once()
        mock_update_score.assert_not_called()
