import logging
from datetime import datetime

from django.contrib.sessions.backends.base import SessionBase
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from .exceptions import MissingSessionError

log = logging.getLogger(__name__)

LTI_SESSION_KEY = "lti_access"


def set_lti_session_access(
    session: SessionBase, path: str, expiration: datetime
) -> None:
    """Grant access to path for session_lengh seconds"""
    access = {path: expiration.isoformat()}
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
        raise MissingSessionError("Missing lti session key: %s", LTI_SESSION_KEY)

    expiration = lti_access.get(path)
    if not expiration:
        raise MissingSessionError("Missing path from %s: %s", LTI_SESSION_KEY, path)

    expiration = parse_datetime(expiration)
    return True if timezone.now() <= expiration else False
