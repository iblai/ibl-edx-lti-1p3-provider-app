from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any, TypedDict

from opaque_keys import InvalidKeyError
from opaque_keys.edx.keys import CourseKey, UsageKey
from xmodule.modulestore.django import modulestore
from xmodule.modulestore.mixed import MixedModuleStore

from lti_1p3_provider.models import LaunchGate

log = logging.getLogger(__name__)


class Content(TypedDict):
    title: str
    block_type: str
    usage_key: str
    children: list[Content]
    description: str


def get_selectable_dl_content(launch_gate: LaunchGate) -> dict[str, list[Content]]:
    """
    Return a nested Content structure of all the blocks that are servable via LTI.

    Returns a dict with the following structure:
    {org: [Content, ...], ...}

    Where the top level Content is a course. The 'children' key contains a list of all
    the blocks that are servable via LTI in that course. For each of these entries,
    the children are the full subtree of that block. This is so we can allow the user
    to choose from the content in a flat list while still showing all the content that
    would be served when selecting it.

    Example (children key has been removed for brevity)

    Content (course):
      - Content (sequential):
        - Content (vertical):
          - Content (problem):
          - Content (video):
      - Content (vertical):
        - Content (problem):
        - Content (video):
      - Content (problem):
      - Content (video):
    """
    m = modulestore()

    courses = _get_courses(m, launch_gate)

    results: dict[str, list[Content]] = defaultdict(list)

    # allowed_keys will get mutated to remove any content already fetched
    allowed_keys = launch_gate.allowed_keys.copy()

    # Process each course
    for course_key_str, course in courses.items():
        try:
            course_key = CourseKey.from_string(course_key_str)
            org = course_key.org

            # Use bulk operations for better performance
            with m.bulk_operations(course_key):
                # Get course content with filtering
                course_content = _get_course_content(
                    m, course, launch_gate, allowed_keys
                )
                if course_content["children"]:
                    results[org].append(course_content)

        except InvalidKeyError:
            # Skip invalid course keys
            continue

    explicitly_allowed_blocks = _fetch_explicitly_allowed_blocks(
        m, launch_gate, allowed_keys
    )
    results = _add_content(m, results, explicitly_allowed_blocks)

    return results


def _get_courses(m: MixedModuleStore, launch_gate: LaunchGate) -> dict[str, Content]:
    """Return courses from modulestore"""
    result: dict[str, Any] = {}
    orgs = launch_gate.allowed_orgs
    courses = launch_gate.allowed_courses

    # Get courses by organization
    for org in orgs:
        org_courses = m.get_courses(org=org)
        for course in org_courses:
            result[str(course.id)] = course

    # Get specific courses
    for course_key_str in courses:
        # Don't want to double-fetch courses if they happen to be duplicated
        if course_key_str in result:
            continue

        try:
            course_key = CourseKey.from_string(course_key_str)
            if str(course_key) not in result:
                course = m.get_course(course_key)
                if course:
                    result[str(course_key)] = course
        except InvalidKeyError:
            log.error(f"Invalid course key: {course_key_str}")
            continue

    return result


def _fetch_explicitly_allowed_blocks(
    m: MixedModuleStore, launch_gate: LaunchGate, allowed_keys: list[str]
) -> list[Content]:
    """Fetch allowed keys from modulestore using bulk operations"""
    results = []

    if not allowed_keys:
        return []

    for key_str in allowed_keys:
        course_content = []
        try:
            usage_key = UsageKey.from_string(key_str)
        except InvalidKeyError:
            log.error(f"Invalid usage key: {key_str}")
            continue

        block = m.get_item(usage_key)
        # We have to construct full tree in case block has children
        child_content = _traverse_and_filter_block(
            m, block, launch_gate, course_content, allowed_keys
        )
        results.append(child_content)

    return results


def _get_course_content(
    m: MixedModuleStore, course: Any, launch_gate: LaunchGate, allowed_keys: list[str]
) -> Content:
    """Get course content with filtering applied"""
    # Build course content structure
    content = build_content_from_block(course)
    course_content = []

    # Traverse children and apply filters
    children = []
    for chapter in course.get_children():
        # Can't serve Courses/Chapters in edx, so need to go to sequentials
        for seq in chapter.get_children():
            child_content = _traverse_and_filter_block(
                m,
                seq,
                launch_gate,
                course_content,
                allowed_keys,
            )
            if child_content:
                children.append(child_content)

    content["children"] = course_content
    return content


def _traverse_and_filter_block(
    m: MixedModuleStore,
    block: Any,
    launch_gate: LaunchGate,
    course_content: list[Content],
    allowed_keys: list[str],
) -> Content | None:
    """Recursively traverse and filter blocks"""
    # Build content for this block
    content = build_content_from_block(block)

    # Traverse children
    children = []
    for child in block.get_children():
        child_content = _traverse_and_filter_block(
            m,
            child,
            launch_gate,
            course_content,
            allowed_keys,
        )
        if child_content:
            children.append(child_content)

    content["children"] = children
    location = block.location
    if launch_gate.can_access_key(location):
        course_content.append(content)
        # Won't need to refetch this one
        if str(location) in allowed_keys:
            allowed_keys.remove(str(location))
    return content


def build_content_from_block(block: Any) -> Content:
    """Build Content dict from a block"""
    return Content(
        title=block.display_name,
        block_type=block.location.block_type,
        usage_key=str(block.location),
        children=[],  # Will be populated by caller
        description=getattr(block, "description", "") or "",
    )


def _add_content(
    m: MixedModuleStore,
    all_content: dict[str, list[Content]],
    new_blocks: list[Content],
) -> dict[str, list[Content]]:
    """Add new_block to all_content, creating any necessary course entries"""
    if not new_blocks:
        return all_content

    for block_content in new_blocks:
        key = UsageKey.from_string(block_content["usage_key"])
        org = key.course_key.org
        if org not in all_content:
            # Must mean the course is not either so we build the course entry
            course = m.get_course(key.course_key)
            new_course_content = build_content_from_block(course)
            all_content[org] = [new_course_content]

        org_courses = all_content[org]
        course_content = None
        for course in org_courses:
            course_key = key.course_key
            course_id = str(course_key.make_usage_key("course", "course"))
            if course_id == course["usage_key"]:
                course_content = course

        # Course exists
        if course_content:
            course_content["children"].append(block_content)
        # Course does not exist
        else:
            course = m.get_course(key.course_key)
            course_content = build_content_from_block(course)
            course_content["children"].append(block_content)
            org_courses.append(course_content)

    return all_content
