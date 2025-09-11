from organizations.tests.factories import OrganizationFactory
from xmodule.modulestore.django import modulestore
from xmodule.modulestore.tests.django_utils import ModuleStoreTestCase
from xmodule.modulestore.tests.factories import BlockFactory, CourseFactory

from lti_1p3_provider.dl_content_selection import (
    Content,
    build_content_from_block,
    get_selectable_dl_content,
)
from lti_1p3_provider.tests.factories import LaunchGateFactory


def _find_missing_keys(content: Content, keys: list[str]) -> list[str]:
    """
    Recursively search through content and its children to find matching usage_keys.

    Args:
        content: The Content object to search in
        keys: List of usage_keys to search for

    Returns:
        List of keys that were not found in the content structure
    """
    # Start with all keys as not found
    not_found = keys.copy()

    def _search_recursive(content_item: Content) -> None:
        """Helper function to recursively search through content"""
        # Check if the current content has any of the keys we're looking for
        if content_item["usage_key"] in not_found:
            not_found.remove(content_item["usage_key"])

        # Recursively search through children
        for child in content_item["children"]:
            _search_recursive(child)

    _search_recursive(content)
    return not_found


def _get_course_content(courses: list[Content], target_course_id: str) -> Content:
    for course in courses:
        if course["usage_key"] == target_course_id:
            return course
    raise ValueError(f"Course {target_course_id} not found in courses: {courses}")


class TestDlSelection(ModuleStoreTestCase):
    def setUp(self):
        super().setUp()

        # Create organizations
        self.org1 = OrganizationFactory(short_name="org1")
        self.org2 = OrganizationFactory(short_name="org2")

        # Create course1 (org=org1)
        self.course1 = CourseFactory.create(
            org=self.org1.short_name, display_name="Course 1"
        )
        self.course1_section1 = BlockFactory.create(
            parent_location=self.course1.location,
            category="chapter",
            display_name=f"{self.course1.display_name} - Section 1",
        )
        self.course1_subsection1 = BlockFactory.create(
            parent_location=self.course1_section1.location,
            category="sequential",
            display_name=f"{self.course1.display_name} - Subsection 1",
        )
        self.course1_unit1 = BlockFactory.create(
            parent_location=self.course1_subsection1.location,
            category="vertical",
            display_name=f"{self.course1.display_name} - Unit 1",
        )
        self.course1_problem1 = BlockFactory.create(
            parent_location=self.course1_unit1.location,
            category="problem",
            display_name=f"{self.course1.display_name} - Problem 1",
        )
        self.course1_video1 = BlockFactory.create(
            parent_location=self.course1_unit1.location,
            category="video",
            display_name=f"{self.course1.display_name} - Video 1",
        )
        self.course1_unit2 = BlockFactory.create(
            parent_location=self.course1_subsection1.location,
            category="vertical",
            display_name=f"{self.course1.display_name} - Unit 2",
        )
        self.course1_video2 = BlockFactory.create(
            parent_location=self.course1_unit2.location,
            category="video",
            display_name=f"{self.course1.display_name} - Video 2",
        )

        # Create course2 (org=org1)
        self.course2 = CourseFactory.create(
            org=self.org1.short_name, display_name="Course 2"
        )
        self.course2_section1 = BlockFactory.create(
            parent_location=self.course2.location,
            category="chapter",
            display_name=f"{self.course2.display_name} - Section 1",
        )
        self.course2_subsection1 = BlockFactory.create(
            parent_location=self.course2_section1.location,
            category="sequential",
            display_name=f"{self.course2.display_name} - Subsection 1",
        )
        self.course2_unit1 = BlockFactory.create(
            parent_location=self.course2_subsection1.location,
            category="vertical",
            display_name=f"{self.course2.display_name} - Unit 1",
        )
        self.course2_html1 = BlockFactory.create(
            parent_location=self.course2_unit1.location,
            category="html",
            display_name=f"{self.course2.display_name} - HTML 1",
        )

        # Create course3 (org=org2)
        self.course3 = CourseFactory.create(
            org=self.org2.short_name, display_name="Course 3"
        )
        self.course3_section1 = BlockFactory.create(
            parent_location=self.course3.location,
            category="chapter",
            display_name=f"{self.course3.display_name} - Section 1",
        )
        self.course3_subsection1 = BlockFactory.create(
            parent_location=self.course3_section1.location,
            category="sequential",
            display_name=f"{self.course3.display_name} - Subsection 1",
        )
        self.course3_unit1 = BlockFactory.create(
            parent_location=self.course3_subsection1.location,
            category="vertical",
            display_name=f"{self.course3.display_name} - Unit 1",
        )
        self.course3_problem1 = BlockFactory.create(
            parent_location=self.course3_unit1.location,
            category="problem",
            display_name=f"{self.course3.display_name} - Problem 1",
        )
        self.course3_video1 = BlockFactory.create(
            parent_location=self.course3_unit1.location,
            category="video",
            display_name=f"{self.course3.display_name} - Video 1",
        )
        self.course3_unit2 = BlockFactory.create(
            parent_location=self.course3_subsection1.location,
            category="vertical",
            display_name=f"{self.course3.display_name} - Unit 2",
        )
        self.course3_video2 = BlockFactory.create(
            parent_location=self.course3_unit2.location,
            category="video",
            display_name=f"{self.course3.display_name} - Video 2",
        )

        # Create lists of all block lti-servable locations for each course
        # These don't include course or sections bc we can't currently serve those
        self.all_lti_course1_blocks = [
            str(self.course1_subsection1.location),
            str(self.course1_unit1.location),
            str(self.course1_problem1.location),
            str(self.course1_video1.location),
            str(self.course1_unit2.location),
            str(self.course1_video2.location),
        ]

        self.all_lti_course2_blocks = [
            str(self.course2_subsection1.location),
            str(self.course2_unit1.location),
            str(self.course2_html1.location),
        ]

        self.all_lti_course3_blocks = [
            str(self.course3_subsection1.location),
            str(self.course3_unit1.location),
            str(self.course3_problem1.location),
            str(self.course3_video1.location),
            str(self.course3_unit2.location),
            str(self.course3_video2.location),
        ]

    def test_empty_launch_gate_returns_empty_dict(self):
        """If nothing in the launch gate, nothing is returned"""
        lg = LaunchGateFactory.build()
        content = get_selectable_dl_content(lg)
        assert content == {}

    def test_filtering_by_xblock_level_block_type_in_one_org(self):
        """Test filtering problem block types in one org"""
        lg = LaunchGateFactory.build(
            allowed_orgs=[self.org1.short_name], block_filter=["problem"]
        )

        content = get_selectable_dl_content(lg)

        course = build_content_from_block(self.course1)
        course["children"] = [build_content_from_block(self.course1_problem1)]
        expected = {self.org1.short_name: [course]}
        assert content == expected

    def test_filtering_by_xblock_level_block_type_when_block_type_dne(self):
        """Test filtering problem block types in one org when block type doesn't exist"""
        # there are not html blocks in any course in org2
        lg = LaunchGateFactory.build(
            allowed_orgs=[self.org2.short_name], block_filter=["html"]
        )
        content = get_selectable_dl_content(lg)
        assert content == {}

    def test_all_content_allowed(self):
        """Test when all orgs are allowed"""
        lg = LaunchGateFactory.build(
            allowed_orgs=[
                self.org1.short_name,
                self.org2.short_name,
            ]
        )

        content = get_selectable_dl_content(lg)

        # Two orgs
        assert self.org1.short_name in content
        assert self.org2.short_name in content

        # Two courses in org1
        org1_courses = content[self.org1.short_name]
        assert len(org1_courses) == 2

        # One course in org2
        org2_courses = content[self.org2.short_name]
        assert len(org2_courses) == 1

    def test_course_block_filter_with_allowed_orgs(self):
        """Test course block filter"""
        lg = LaunchGateFactory.build(
            allowed_orgs=[self.org1.short_name],
            course_block_filter={
                str(self.course1.location.course_key): ["vertical", "video"]
            },
        )

        content = get_selectable_dl_content(lg)

        # one org
        assert len(content.keys()) == 1
        assert self.org1.short_name in content

        # Two Courses
        org1_courses = content[self.org1.short_name]
        usage_keys = [course["usage_key"] for course in org1_courses]
        assert str(self.course1.location) in usage_keys
        assert str(self.course2.location) in usage_keys

        # Expected Course 1 Content which is filtered
        course_1_content = _get_course_content(org1_courses, str(self.course1.location))
        expected_course_1_keys = [
            str(self.course1_problem1.location),
            str(self.course1_video1.location),
        ]
        assert not _find_missing_keys(course_1_content, expected_course_1_keys)

        # Expected all course 2 content
        course_2_content = _get_course_content(org1_courses, str(self.course2.location))
        assert not _find_missing_keys(course_2_content, self.all_lti_course2_blocks)
