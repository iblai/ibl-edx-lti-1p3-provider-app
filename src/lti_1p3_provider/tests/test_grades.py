from common.djangoapps.student.tests.factories import UserFactory
from xmodule.modulestore.tests.django_utils import ModuleStoreTestCase
from xmodule.modulestore.tests.factories import BlockFactory, CourseFactory

from lti_1p3_provider.grades import get_assignments_for_problem

from . import factories


class TestGrades(ModuleStoreTestCase):
    """
    Test cases for the assignments_for_problem method in outcomes.py
    """

    def setUp(self):
        super().setUp()
        self.profile = factories.LtiProfileFactory()
        self.user = self.profile.user
        self.user_id = self.user.id
        self.tool = factories.LtiToolFactory()
        self.course = CourseFactory.create()
        self.section = BlockFactory.create(
            parent_location=self.course.location, category="chapter"
        )
        self.subsection = BlockFactory.create(
            parent_location=self.section.location, category="sequential"
        )
        self.unit = BlockFactory.create(
            parent_location=self.subsection.location, category="vertical"
        )
        self.problem = BlockFactory.create(
            parent_location=self.unit.location, category="problem"
        )

    def create_graded_assignment(self, desc, title):
        """
        Create and save a new GradedAssignment model in the test database.
        """
        assignment = factories.LtiGradedResourceFactory(
            profile=self.profile,
            course_key=self.course.id,
            usage_key=desc.location,
            resource_title=title,
        )
        return assignment

    def test_with_no_graded_assignments(self):
        assignments = get_assignments_for_problem(
            self.problem, self.user_id, self.course.id
        )
        assert len(assignments) == 0

    def test_with_graded_unit(self):
        self.create_graded_assignment(self.unit, "graded_unit")
        assignments = get_assignments_for_problem(
            self.problem, self.user_id, self.course.id
        )
        assert len(assignments) == 1
        assert assignments[0].resource_title == "graded_unit"

    def test_with_graded_vertical(self):
        self.create_graded_assignment(self.subsection, "graded_vertical")
        assignments = get_assignments_for_problem(
            self.problem, self.user_id, self.course.id
        )
        assert len(assignments) == 1
        assert assignments[0].resource_title == "graded_vertical"

    def test_with_graded_unit_and_vertical(self):
        self.create_graded_assignment(self.unit, "graded_unit")
        self.create_graded_assignment(self.subsection, "graded_vertical")
        assignments = get_assignments_for_problem(
            self.problem, self.user_id, self.course.id
        )
        assert len(assignments) == 2
        exp = {"graded_unit", "graded_vertical"}
        assert (
            set([assignments[0].resource_title, assignments[1].resource_title]) == exp
        )

    def test_with_unit_used_twice(self):
        """Multiple resource links for user pointed to the same unit"""
        self.create_graded_assignment(self.unit, "graded_unit")
        self.create_graded_assignment(self.unit, "graded_unit2")
        assignments = get_assignments_for_problem(
            self.problem, self.user_id, self.course.id
        )
        assert len(assignments) == 2
        assert assignments[0].resource_title == "graded_unit"
        assert assignments[1].resource_title == "graded_unit2"

    def test_with_unit_graded_for_different_user(self):
        self.create_graded_assignment(self.unit, "graded_unit")
        other_user = UserFactory.create()
        assignments = get_assignments_for_problem(
            self.problem, other_user.id, self.course.id
        )
        assert len(assignments) == 0
