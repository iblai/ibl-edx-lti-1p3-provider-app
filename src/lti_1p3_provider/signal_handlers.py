"""
Content library signal handlers.
"""

import logging

from django.conf import settings
from django.dispatch import receiver
from lms.djangoapps.grades.api import signals as grades_signals
from opaque_keys.edx.keys import LearningContextKey

from .grades import increment_assignment_versions
from .tasks import send_composite_score, send_leaf_score
from .views import parse_course_and_usage_keys

log = logging.getLogger(__name__)


@receiver(grades_signals.PROBLEM_WEIGHTED_SCORE_CHANGED)
def score_changed_handler(sender, **kwargs):  # pylint: disable=unused-argument
    """
    Consume signals that indicate score changes. See the definition of
    PROBLEM_WEIGHTED_SCORE_CHANGED for a description of the signal.

    NOTE: This was taken from lms.djangoapps.lti_provider.signals and updated for our
    needs.
    """
    log.debug("LTI Score Changed Handler")
    modified = kwargs.get("modified", None)
    points_possible = kwargs.get("weighted_possible", None)
    points_earned = kwargs.get("weighted_earned", None)
    user_id = kwargs.get("user_id", None)
    course_id = kwargs.get("course_id", None)
    usage_id = kwargs.get("usage_id", None)

    # Make sure this came from a course because this code only works with courses
    if not course_id:
        log.debug("course_id is None; exiting")
        return
    context_key = LearningContextKey.from_string(course_id)
    if not context_key.is_course:
        log.debug("context_key is not a course")
        return  # This is a content library or something else...

    if None not in (points_earned, points_possible, user_id, course_id, modified):
        course_key, usage_key = parse_course_and_usage_keys(course_id, usage_id)
        resources = increment_assignment_versions(course_key, usage_key, user_id)
        log.debug("Graded Resources: %s", resources)
        for resource in resources:
            if resource.usage_key == usage_key:
                send_leaf_score.delay(
                    resource.id, points_earned, points_possible, modified
                )
                log.debug("Created LTI 1.3 leaf score update task")
            else:
                send_composite_score.apply_async(
                    (
                        user_id,
                        course_id,
                        resource.id,
                        resource.version_number,
                        modified,
                    ),
                    countdown=settings.LTI_AGGREGATE_SCORE_PASSBACK_DELAY,
                )
                log.debug("Created LTI 1.3 composite score update task")
    else:
        log.error(
            (
                "LTI 1.3 Grades Service: Required signal parameter is None. "
                "points_possible: %s, points_earned: %s, user_id: %s, "
                "course_id: %s, usage_id: %s, modified: %s"
            ),
            points_possible,
            points_earned,
            user_id,
            course_id,
            usage_id,
            modified,
        )
