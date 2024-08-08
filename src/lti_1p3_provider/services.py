import logging

from django.utils import timezone
from ibl_request_router.api.manager import manager_api_request

from .exceptions import Lti1p3ProviderError

log = logging.getLogger(__name__)


def create_user_platform_link(edx_user_id: int, platform_key: str) -> None:
    """Create UserPlatformLink in DM for this user and platform"""
    endpoint = "/api/core/users/platforms/"
    payload = {
        "user_id": edx_user_id,
        "platform_key": platform_key,
        "added_on": timezone.now().isoformat(),
        "id_admin": False,
        "active": True,
    }
    resp = manager_api_request(
        method="POST",
        endpoint_path=endpoint,
        data=payload,
    )
    # Non-status-code related error
    if resp is None:
        log.error(
            (
                "Failed to create UserPlatformLink for user_id=%s, platform_key=%s. "
                "No Response"
            )
        )
        raise Lti1p3ProviderError("Failed to create UserPlatformLink")

    if not resp.ok:
        log.error(
            (
                "Failed to create UserPlatformLink for user_id=%s, platform_key=%s\n"
                "- Status code: %s\n- Response: %s"
            ),
            edx_user_id,
            platform_key,
            resp.status_code,
            resp.text,
        )
        raise Lti1p3ProviderError(
            f"Failed to create UserPlatformLink (Status: {resp.status_code})"
        )
