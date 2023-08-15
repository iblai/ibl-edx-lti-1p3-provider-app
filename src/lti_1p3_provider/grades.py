from xmodule.modulestore.django import modulestore

from .models import LtiGradedResource


def increment_assignment_versions(course_key, usage_key, user_id):
    """
    Update the version numbers for all assignments that are affected by a score
    change event. Returns a list of all affected assignments.

    NOTE: Taken from lms.djangoapps.lti_provider.signal_handlers

    The only change is using our `get_assignments_for_problem` method
    """
    problem_descriptor = modulestore().get_item(usage_key)
    # Get all assignments involving the current problem for which the campus LMS
    # is expecting a grade. There may be many possible graded assignments, if
    # a problem has been added several times to a course at different
    # granularities (such as the unit or the vertical).
    assignments = get_assignments_for_problem(problem_descriptor, user_id, course_key)
    for assignment in assignments:
        assignment.version_number += 1
        assignment.save()
    return assignments


def get_assignments_for_problem(problem_descriptor, user_id, course_key):
    """
    Trace the parent hierarchy from a given problem to find all blocks that
    correspond to graded assignment launches for this user. A problem may
    show up multiple times for a given user; the problem could be embedded in
    multiple courses (or multiple times in the same course), or the block could
    be embedded more than once at different granularities (as an individual
    problem and as a problem in a vertical, for example).

    Returns a list of GradedAssignment objects that are associated with the
    given descriptor for the current user.

    NOTE: Taken from lms.djangoapps.lti_provider.outcomes. We have to join profile.
    """
    locations = []
    current_descriptor = problem_descriptor
    while current_descriptor:
        locations.append(current_descriptor.location)
        current_descriptor = current_descriptor.get_parent()
    assignments = LtiGradedResource.objects.filter(
        profile__user_id=user_id, course_key=course_key, usage_key__in=locations
    )
    return assignments
