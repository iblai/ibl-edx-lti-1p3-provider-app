from unittest import mock

import pytest
from django.conf import settings
from opaque_keys.edx.locator import LibraryLocator

from lti_1p3_provider.models import LtiGradedResource
from lti_1p3_provider.signal_handlers import score_changed_handler
from lti_1p3_provider.tasks import send_composite_score, send_leaf_score

from . import factories


@pytest.fixture
def m_send_leaf(monkeypatch):
    mocked_fn = mock.MagicMock(spec=send_leaf_score)
    monkeypatch.setattr("lti_1p3_provider.signal_handlers.send_leaf_score", mocked_fn)
    yield mocked_fn


@pytest.fixture
def m_send_composite(monkeypatch):
    mocked_fn = mock.MagicMock(spec=send_composite_score)
    monkeypatch.setattr(
        "lti_1p3_provider.signal_handlers.send_composite_score", mocked_fn
    )
    yield mocked_fn


@pytest.mark.django_db
class TestScoreChangedHandler:
    def setup_method(self):
        self.profile = factories.LtiProfileFactory()

    def test_non_course_key_doesnt_send_score(self, m_send_leaf, m_send_composite):
        """If course_key is not a real course key (library), no score is sent"""
        key = LibraryLocator(library="lib", org="org")
        kwargs = factories.ScoreChangedSubmissionFactory(
            user_id=self.profile.user.id, course_id=str(key)
        )

        score_changed_handler(None, **kwargs)

        m_send_leaf.delay.assert_not_called()
        m_send_composite.apply_async.assert_not_called()

    def test_missing_course_id_doesnt_send_score(self, m_send_leaf, m_send_composite):
        """If course_id is missing, score is not sent"""
        kwargs = factories.ScoreChangedSubmissionFactory(
            user_id=self.profile.user.id, course_id=None
        )

        score_changed_handler(None, **kwargs)

        m_send_leaf.delay.assert_not_called()
        m_send_composite.apply_async.assert_not_called()

    @pytest.mark.parametrize(
        "none_param",
        ("weighted_earned", "weighted_possible", "user_id", "modified"),
    )
    def test_required_params_set_to_none_donesnt_send_score(
        self, none_param, m_send_leaf, m_send_composite, caplog
    ):
        """Missing required keys don't send a score update, but log an error"""
        builder_kwargs = {"user_id": self.profile.user.id}
        builder_kwargs[none_param] = None
        kwargs = factories.ScoreChangedSubmissionFactory(**builder_kwargs)

        score_changed_handler(None, **kwargs)

        m_send_leaf.delay.assert_not_called()
        m_send_composite.apply_async.assert_not_called()
        assert caplog.messages[0].startswith("LTI 1.3 Grades Service:")

    @mock.patch("lti_1p3_provider.grades.modulestore")
    @mock.patch("lti_1p3_provider.grades.get_assignments_for_problem")
    def test_send_leaf_score(
        self, m_get_assignments, m_ms, m_send_leaf, m_send_composite
    ):
        """If score changed usage_key is equal to problem usage key, send leaf"""
        resource = factories.LtiGradedResourceFactory(profile=self.profile)
        kwargs = factories.ScoreChangedSubmissionFactory(user_id=self.profile.user.id)

        m_get_assignments.return_value = LtiGradedResource.objects.all()

        score_changed_handler(None, **kwargs)

        m_send_leaf.delay.assert_called_once_with(
            resource.id,
            kwargs["weighted_earned"],
            kwargs["weighted_possible"],
            kwargs["modified"],
        )
        m_send_composite.apply_async.assert_not_called()

    @mock.patch("lti_1p3_provider.grades.modulestore")
    @mock.patch("lti_1p3_provider.grades.get_assignments_for_problem")
    def test_send_composite_score(
        self, m_get_assignments, m_ms, m_send_leaf, m_send_composite
    ):
        """If assignment usage_key not equal to problem usage key, send composite"""
        resource = factories.LtiGradedResourceFactory(profile=self.profile)
        kwargs = factories.ScoreChangedSubmissionFactory(
            user_id=self.profile.user.id,
            usage_id=str(
                factories.COURSE_KEY.make_usage_key(
                    block_type="vertical", block_id="test"
                )
            ),
        )

        m_get_assignments.return_value = LtiGradedResource.objects.all()

        score_changed_handler(None, **kwargs)

        m_send_leaf.delay.assert_not_called()
        m_send_composite.apply_async.assert_called_once_with(
            (
                self.profile.user.id,
                kwargs["course_id"],
                resource.id,
                resource.version_number + 1,
                kwargs["modified"],
            ),
            countdown=settings.LTI_AGGREGATE_SCORE_PASSBACK_DELAY,
        )
