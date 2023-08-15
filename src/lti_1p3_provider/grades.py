from .models import LtiGradedResource


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
