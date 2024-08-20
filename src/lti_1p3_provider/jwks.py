from __future__ import annotations

import json
from typing import Any

from pylti1p3.contrib.django.lti1p3_tool_config.models import LtiToolKey
from pylti1p3.registration import Registration


def get_jwks_for_org(org_short_name: str) -> dict[str, Any]:
    """Return JWKS filtered for specified org"""
    keys = (
        LtiToolKey.objects.select_related("key_org__key")
        .filter(key_org__org__short_name=org_short_name)
        .order_by("id")
    )
    jwks = []
    public_key_lst = []

    for key in keys:
        if key.public_key and key.public_key not in public_key_lst:
            if key.public_jwk:
                jwks.append(json.loads(key.public_jwk))
            else:
                jwks.append(Registration.get_jwk(key.public_key))
            public_key_lst.append(key.public_key)
    return {"keys": jwks}
