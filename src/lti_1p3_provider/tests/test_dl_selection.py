from organizations.tests.factories import OrganizationFactory
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
    not_found = set(keys.copy())
    if content["block_type"] != "course":
        raise ValueError(f"Content is not a course: {content}")

    all_keys = set([k["usage_key"] for k in content["children"]])
    return list(not_found - all_keys)


def assert_no_duplicate_content(content: dict[str, list[Content]]) -> None:
    """Every key should be unique"""
    all_keys = []
    for org_content in content.values():
        for course in org_content:
            all_keys.extend([k["usage_key"] for k in course["children"]])
    assert len(all_keys) == len(set(all_keys)), sorted(all_keys)


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
        assert_no_duplicate_content(content)
        assert content == {}

    def test_filtering_by_xblock_level_block_type_in_one_org(self):
        """Test filtering problem block types in one org"""
        lg = LaunchGateFactory.build(
            allowed_orgs=[self.org1.short_name], block_filter=["problem"]
        )

        content = get_selectable_dl_content(lg)

        assert_no_duplicate_content(content)
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
        assert_no_duplicate_content(content)
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

        assert_no_duplicate_content(content)
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

        assert_no_duplicate_content(content)
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
            str(self.course1_unit1.location),
            str(self.course1_video1.location),
            str(self.course1_unit2.location),
            str(self.course1_video2.location),
        ]
        assert not _find_missing_keys(course_1_content, expected_course_1_keys)

        # Expected all course 2 content
        course_2_content = _get_course_content(org1_courses, str(self.course2.location))
        assert not _find_missing_keys(course_2_content, self.all_lti_course2_blocks)

    def test_org_block_filter_with_allowed_orgs(self):
        """Test org block filter"""
        lg = LaunchGateFactory.build(
            allowed_orgs=[self.org1.short_name, self.org2.short_name],
            org_block_filter={
                self.org1.short_name: ["problem", "video"],
                self.org2.short_name: ["problem"],
            },
        )

        content = get_selectable_dl_content(lg)

        assert_no_duplicate_content(content)
        # Two orgs
        assert len(content.keys()) == 2
        assert self.org1.short_name in content
        assert self.org2.short_name in content

        # Only Course 1 returned in org 1 since all course 2's content is filtered out
        org1_courses = content[self.org1.short_name]
        assert len(org1_courses) == 1
        assert org1_courses[0]["usage_key"] == str(self.course1.location)

        # Expected Course 1 Content which is filtered to problem and video only
        course_1_content = _get_course_content(org1_courses, str(self.course1.location))
        expected_course_1_keys = [
            str(self.course1_problem1.location),
            str(self.course1_video1.location),
            str(self.course1_video2.location),
        ]
        assert not _find_missing_keys(course_1_content, expected_course_1_keys)

        # Org1, Course 2 results in no content so is not included at all
        # Org2 courses (course3)
        org2_courses = content[self.org2.short_name]
        usage_keys = [course["usage_key"] for course in org2_courses]
        assert str(self.course3.location) in usage_keys

        # Expected Course 3 Content which is filtered to problem only
        course_3_content = _get_course_content(org2_courses, str(self.course3.location))
        expected_course_3_keys = [
            str(self.course3_problem1.location),
        ]
        assert not _find_missing_keys(course_3_content, expected_course_3_keys)

    def test_course_and_org_and_block_filter(self):
        """Test when all three filter types are set"""
        # all courses in org 1 and 2 are allowed
        # only verticals are allowed in course 1
        # only html is allowed in all other courses for org 1
        # problems are allowed for anything other type
        lg = LaunchGateFactory.build(
            allowed_orgs=[self.org1.short_name, self.org2.short_name],
            course_block_filter={
                str(self.course1.location.course_key): ["vertical"],
            },
            org_block_filter={
                self.org1.short_name: ["html"],
            },
            block_filter=["problem"],
        )

        content = get_selectable_dl_content(lg)

        assert_no_duplicate_content(content)
        # Two orgs
        assert len(content.keys()) == 2
        assert self.org1.short_name in content
        assert self.org2.short_name in content

        # Both courses are returned in org 1
        org1_courses = content[self.org1.short_name]
        usage_keys = [course["usage_key"] for course in org1_courses]
        assert str(self.course1.location) in usage_keys
        assert str(self.course2.location) in usage_keys

        # Course 1's units only
        course_1_content = _get_course_content(org1_courses, str(self.course1.location))
        expected_course_1_keys = [
            str(self.course1_unit1.location),
            str(self.course1_unit2.location),
        ]
        assert not _find_missing_keys(course_1_content, expected_course_1_keys)

        # Course 2 html only
        course_2_content = _get_course_content(org1_courses, str(self.course2.location))
        expected_course_2_keys = [
            str(self.course2_html1.location),
        ]
        assert not _find_missing_keys(course_2_content, expected_course_2_keys)

        # Course 3 problem's only
        org2_courses = content[self.org2.short_name]
        course_3_content = _get_course_content(org2_courses, str(self.course3.location))
        expected_course_3_keys = [
            str(self.course3_problem1.location),
        ]
        assert not _find_missing_keys(course_3_content, expected_course_3_keys)

    def test_explicitly_allowed_keys_with_no_block_filters(self):
        """Test explicitly allowed blocks"""
        # Explicitly allowed blocks ignore all filters since you're including those
        # blocks explicitly; no point in having to include them in a broader filter
        lg = LaunchGateFactory.build(allowed_keys=[str(self.course1_problem1.location)])

        content = get_selectable_dl_content(lg)

        assert_no_duplicate_content(content)
        assert content.keys() == set([self.org1.short_name])
        course_1_content = _get_course_content(
            content[self.org1.short_name], str(self.course1.location)
        )
        expected_course_1_keys = [
            str(self.course1_problem1.location),
        ]
        assert not _find_missing_keys(course_1_content, expected_course_1_keys)

    def test_explicitly_allowed_keys_with_block_filters_set(self):
        """Test explicitly allowed blocks with block filters set - explicit keys should still be included"""
        # Even with block filters that would normally exclude these blocks,
        # explicitly allowed keys should still be included
        lg = LaunchGateFactory.build(
            allowed_orgs=[self.org1.short_name, self.org2.short_name],
            block_filter=["html"],  # This would normally exclude problems and videos
            allowed_keys=[
                str(self.course1_problem1.location),
                str(self.course1_video1.location),
                str(self.course3_problem1.location),
            ],
        )

        content = get_selectable_dl_content(lg)

        assert_no_duplicate_content(content)
        # Should have both orgs
        assert self.org1.short_name in content
        assert self.org2.short_name in content

        # Org1 should have the explicitly allowed blocks from course1
        org1_content = content[self.org1.short_name]
        assert len(org1_content) == 2

        # Check that the explicitly allowed blocks are present
        course_1_content = _get_course_content(
            content[self.org1.short_name], str(self.course1.location)
        )
        expected_course_1_keys = [
            str(self.course1_problem1.location),
            str(self.course1_video1.location),
        ]
        assert not _find_missing_keys(course_1_content, expected_course_1_keys)

        # Org2 should have the explicitly allowed block from course3
        org2_content = content[self.org2.short_name]
        assert len(org2_content) == 1

        course_3_content = _get_course_content(
            content[self.org2.short_name], str(self.course3.location)
        )
        expected_course_3_keys = [str(self.course3_problem1.location)]
        assert not _find_missing_keys(course_3_content, expected_course_3_keys)

    def test_explicitly_allowed_keys_with_course_and_org_block_filters(self):
        """Test explicitly allowed keys that coincide with course/org block filters"""
        # Test that explicitly allowed keys get seamlessly added to existing course content
        # when they match the course/org filters
        lg = LaunchGateFactory.build(
            allowed_orgs=[self.org1.short_name, self.org2.short_name],
            course_block_filter={
                str(self.course1.location.course_key): [
                    "vertical"
                ],  # Only allow verticals in course1
            },
            org_block_filter={
                self.org2.short_name: ["problem"],  # Only allow problems in org2
            },
            allowed_keys=[
                str(
                    self.course1_unit1.location
                ),  # This is a vertical in course1 - should be added to course1
                str(
                    self.course3_problem1.location
                ),  # This is a problem in org2 - should be added to course3
                str(
                    self.course1_video1.location
                ),  # This is a video in course1 - should be added despite course filter
            ],
        )

        content = get_selectable_dl_content(lg)

        assert_no_duplicate_content(content)
        # Should have both orgs
        assert self.org1.short_name in content
        assert self.org2.short_name in content

        # Org1 should have course1 with both filtered content and explicitly allowed content
        org1_courses = content[self.org1.short_name]
        course1_content = _get_course_content(org1_courses, str(self.course1.location))

        # Should have the verticals from the course filter
        expected_course1_keys = [
            str(self.course1_unit1.location),
            str(self.course1_unit2.location),
        ]
        assert not _find_missing_keys(course1_content, expected_course1_keys)

        # Should also have the explicitly allowed video (even though it's not a vertical)
        found_keys = []
        for child in course1_content["children"]:
            found_keys.append(child["usage_key"])
        assert str(self.course1_video1.location) in found_keys

        # Org2 should have course3 with the explicitly allowed problem
        org2_courses = content[self.org2.short_name]
        course3_content = _get_course_content(org2_courses, str(self.course3.location))

        # Should have the explicitly allowed problem
        found_keys_org2 = []
        for child in course3_content["children"]:
            found_keys_org2.append(child["usage_key"])
        assert str(self.course3_problem1.location) in found_keys_org2
