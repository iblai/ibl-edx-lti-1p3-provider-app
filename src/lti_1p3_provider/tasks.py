"""
Asynchronous tasks for the LTI provider app.
"""


import logging

from django.contrib.auth.models import User
from edx_django_utils.monitoring import set_code_owner_attribute
from lms import CELERY_APP
from lms.djangoapps.grades.api import CourseGradeFactory
from opaque_keys.edx.keys import CourseKey
from xmodule.modulestore.django import modulestore

from .models import LtiGradedResource

log = logging.getLogger(__name__)


# NOTE: Why are we naming this task?
@CELERY_APP.task(name="lti_1p3_provider.tasks.send_composite_score")
@set_code_owner_attribute
def send_composite_score(user_id, course_id, resource_id, version, modified):
    """
    Calculate and transmit the score for a composite module (such as a
    vertical).

    A composite module may contain multiple problems, so we need to
    calculate the total points earned and possible for all child problems. This
    requires calculating the scores for the whole course, which is an expensive
    operation.

    Callers should be aware that the score calculation code accesses the latest
    scores from the database. This can lead to a race condition between a view
    that updates a user's score and the calculation of the grade. If the Celery
    task attempts to read the score from the database before the view exits (and
    its transaction is committed), it will see a stale value. Care should be
    taken that this task is not triggered until the view exits.

    The LtiGradedResource model has a version_number field that is incremented
    whenever the score is updated. It is used by this method for two purposes.
    First, it allows the task to exit if it detects that it has been superseded
    by another task that will transmit the score for the same assignment.
    Second, it prevents a race condition where two tasks calculate different
    scores for a single assignment, and may potentially update the campus LMS
    in the wrong order.

    NOTE: ibl: technically order shouldn't matter for lti 1.3 since we send a modified
    timestamp and the LMS should ignore timestamps older than the last submitted one.

    NOTE: ibl: Taken from lms.djangoapps.lti_provider.tasks and adjusted for our needs.
    """
    resource = LtiGradedResource.objects.get(id=resource_id)
    if version != resource.version_number:
        log.info(
            (
                "Score passback for LtiGradedResource %s skipped. More recent score "
                "available."
            ),
            resource.id,
        )
        return

    course_key = CourseKey.from_string(course_id)
    mapped_usage_key = resource.usage_key.map_into_course(course_key)
    user = User.objects.get(id=user_id)
    course = modulestore().get_course(course_key, depth=0)
    course_grade = CourseGradeFactory().read(user, course)
    earned, possible = course_grade.score_for_block(mapped_usage_key)

    resource.refresh_from_db()
    if resource.version_number == version:
        resource.objects.update_score(earned, possible, modified)


@CELERY_APP.task
@set_code_owner_attribute
def send_leaf_score(resource_id, points_earned, points_possible, modified):
    """
    Calculate and transmit the score for a single problem. This method assumes
    that the individual problem was the source of a score update, and so it
    directly takes the points earned and possible values. As such it does not
    have to calculate the scores for the course, making this method far faster
    than sending an outcome for a composite module.
    """
    assignment = LtiGradedResource.objects.get(id=resource_id)
    assignment.objects.update_score(points_earned, points_possible, modified)
