from organizations.tests.factories import OrganizationFactory
from xmodule.modulestore.django import modulestore
from xmodule.modulestore.tests.django_utils import ModuleStoreTestCase
from xmodule.modulestore.tests.factories import BlockFactory, CourseFactory

from lti_1p3_provider.dl_content_selection import (
    build_content_from_block,
    get_selectable_dl_content,
)
from lti_1p3_provider.tests.factories import LaunchGateFactory


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
