from __future__ import annotations

from xmodule.modulestore.django import modulestore


def get_selectable_dl_content(
    keys: list[str],
    courses: list[str],
    orgs: list[str],
    block_filter: dict[str, str] | None = None,
) -> dict[str, str]:
    """
    Return dict of selectable deep linking content for given keys, courses, and orgs.
    """

    return {}
