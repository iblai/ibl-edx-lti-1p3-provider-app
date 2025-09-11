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
    Return dict of selectable deep linking content organized by organization.

    Returns a dict with the following structure:
    {org: [Content, ...], ...}

    Where Content is a nested structure representing the course hierarchy.
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
    # Add in any new content to the results
    results = _add_content(results, explicitly_allowed_blocks)

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
) -> dict[str, list[Content]]:
    """Fetch allowed keys from modulestore using bulk operations"""
    results = defaultdict(list)
    course_content = []

    if not allowed_keys:
        return results

    for key_str in allowed_keys:
        try:
            usage_key = UsageKey.from_string(key_str)
        except InvalidKeyError:
            log.error(f"Invalid usage key: {key_str}")
            continue

        block = m.get_item(usage_key)
        content = build_content_from_block(block)
        # We have to construct full tree in case block has children
        child_content = _traverse_and_filter_block(
            m, block, launch_gate, course_content, allowed_keys
        )
        if child_content:
            content["children"] = child_content

        org = usage_key.course_key.org
        for course in results[org]:
            if course["usage_key"] == content["usage_key"]:
                course["children"].extend(content)
        else:
            results[org] = [content]

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
    all_content: dict[str, list[Content]],
    new_blocks: dict[str, list[Content]],
) -> dict[str, list[Content]]:
    if not new_blocks:
        return all_content

    for org, new_courses in new_blocks.items():
        if org not in all_content:
            all_content[org] = new_courses
            continue

        for course in new_courses:
            for org_course in all_content[org]:
                if course["usage_key"] == org_course["usage_key"]:
                    org_course["children"].extend(course["children"])
                    break
            else:
                all_content[org].append(course)

    return all_content
