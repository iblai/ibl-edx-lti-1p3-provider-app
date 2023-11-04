from __future__ import annotations

import logging
from datetime import datetime

from django.contrib.sessions.backends.base import SessionBase
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from .exceptions import MissingSessionError

log = logging.getLogger(__name__)

LTI_SESSION_KEY = "lti_access"


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
