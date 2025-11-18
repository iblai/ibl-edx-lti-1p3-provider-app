from __future__ import annotations

import logging
import typing as t
import uuid
from datetime import datetime, timedelta

from django.contrib.sessions.backends.base import SessionBase
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from .exceptions import DeepLinkingError, MissingSessionError

log = logging.getLogger(__name__)

LTI_SESSION_KEY = "lti_access"
LTI_DEEP_LINKING_SESSION_PREFIX = "lti_deep_link_context_"
LTI_LAUNCH_ID_KEY = "lti_1p3_launch_id"


def set_lti_session_access(
    session: SessionBase, path: str, expiration: datetime | None
) -> None:
    """Grant access to path until expiration. If None, it's as long as logged in"""
    access = {path: None if expiration is None else expiration.isoformat()}
    if LTI_SESSION_KEY not in session:
        session[LTI_SESSION_KEY] = access
    else:
        session[LTI_SESSION_KEY].update(access)

    log.debug("LTI Session Set to: %s", session[LTI_SESSION_KEY])


def set_lti_session_launch_id(session: SessionBase, launch_id: str) -> None:
    """Grant access to path until expiration. If None, it's as long as logged in"""
    session[LTI_LAUNCH_ID_KEY] = launch_id
    log.debug("Stored launch id: %s", session[LTI_LAUNCH_ID_KEY])


def has_lti_session_access(session: SessionBase, path) -> bool:
    """Return True if access to path exists and isn't expired"""
    lti_access = session.get(LTI_SESSION_KEY, None)
    log.debug("LTI Session Fetched: %s", lti_access)
    if lti_access is None:
        raise MissingSessionError(f"Missing lti session key: {LTI_SESSION_KEY}")

    if path not in lti_access:
        raise MissingSessionError(f"Missing path {path} in {LTI_SESSION_KEY}")

    expiration = lti_access[path]

    if expiration is None:
        return True

    expiration = parse_datetime(expiration)
    return True if timezone.now() <= expiration else False


def generate_deep_linking_token() -> str:
    """Generate a unique token for deep linking session."""
    return str(uuid.uuid4())


def _get_deep_linking_session_key(token: str) -> str:
    """Return the session key for deep linking context based on token."""
    return f"{LTI_DEEP_LINKING_SESSION_PREFIX}{token}"


def store_deep_linking_context(
    session: SessionBase,
    token: str,
    launch_id: str,
    session_duration_sec: int = 1800,
) -> dict[str, t.Any]:
    """
    Store deep linking context in session with token-specific key.

    Args:
        session: Django session object
        token: Unique token for this session
        launch_id: Launch ID associated with this session
        session_duration_sec: Session duration in seconds (default 30 minutes)
    """
    now = timezone.now()
    expires_at = now + timedelta(seconds=session_duration_sec)

    session_key = _get_deep_linking_session_key(token)
    session[session_key] = {
        "token": token,
        "launch_id": launch_id,
        "created_at": now.timestamp(),
        "expires_at": expires_at.timestamp(),
    }

    session.modified = True
    return session[session_key]


def validate_deep_linking_session(
    session: SessionBase, token: str, user_authenticated: bool
) -> dict:
    """
    Validate deep linking session access for given token.

    Args:
        session: Django session object
        token: Token to validate
        user_authenticated: Whether user is authenticated

    Returns:
        dict: Deep linking context if valid

    Raises:
        DeepLinkingError: If validation fails with user-friendly message
    """
    # Check if user is authenticated
    if not user_authenticated:
        log.warning("Deep linking access denied: user not authenticated")
        raise DeepLinkingError(
            title="Authentication Required",
            message="Please perform a deep link launch from your learning platform.",
            status_code=401,
        )

    # Check if session has deep linking context for this token
    session_key = _get_deep_linking_session_key(token)
    dl_context = session.get(session_key)
    if not dl_context:
        log.warning(
            "Deep linking access denied: no deep linking session for token %s...",
            token[:8],
        )
        raise DeepLinkingError(
            title="Invalid Access Link",
            message="This content selection link is invalid or expired. Please launch again from your learning platform.",
            status_code=404,
        )
    launch_id = dl_context.get("launch_id")
    if not launch_id:
        log.error(
            "Deep linking access denied: no launch id in context for token %s...",
            token[:8],
        )
        raise DeepLinkingError(
            title="Invalid Access Link",
            message="This content selection link is invalid. Please launch again from your learning platform.",
            status_code=400,
        )
    tool_text = f"launch_id={launch_id}"
    # Validate token matches (extra security check)
    if dl_context.get("token") != token:
        log.error(
            "Deep linking access denied for Tool (%s): token mismatch for token %s...",
            tool_text,
            token[:8],
        )
        # Clear potentially corrupted session
        del session[session_key]
        raise DeepLinkingError(
            title="Invalid Access Link",
            message="This content selection link is invalid. Please launch again from your learning platform.",
            status_code=400,
        )

    # Check if session hasn't expired
    expires_at = dl_context.get("expires_at")
    if not expires_at:
        log.error(
            "Deep linking access denied for Tool (%s): no expiration in context for token %s...",
            tool_text,
            token[:8],
        )
        # Clear potentially corrupted session
        del session[session_key]
        raise DeepLinkingError(
            title="Invalid Session",
            message="Your content selection session is invalid. Please launch again from your learning platform.",
            status_code=500,
        )

    if timezone.now().timestamp() > expires_at:
        log.info(
            "Deep linking session expired for Tool (%s), token %s...",
            tool_text,
            token[:8],
        )
        # Clear expired session
        del session[session_key]
        raise DeepLinkingError(
            title="Deep Linking Session Expired",
            message="Your content selection session has expired. Please launch again from your learning platform to select new content.",
            status_code=403,
        )

    return dl_context


def clear_deep_linking_session(session: SessionBase, token: str) -> None:
    """
    Clear deep linking session for given token.

    Args:
        session: Django session object
        token: Token to clear
    """
    session_key = _get_deep_linking_session_key(token)
    if session_key in session:
        dl_context = session[session_key]

        del session[session_key]

        log.info(
            "Successfully removed deep linking session for launch id %s, token %s",
            dl_context.get("launch_id", "unknown"),
            token[:8] + "...",
        )
    else:
        log.error(
            "Attempted to clear non-existent deep linking session for token %s...",
            token[:8],
        )
