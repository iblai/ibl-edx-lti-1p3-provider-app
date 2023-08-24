# ibl-edx-lti-1p3-provider
LTI 1.3 Provider Implementation for general edx usage

**NOTE**
_By default EdX has no gates for which clients can access which courses. A client can access any `UsageKey` within a `Course` simply by knowing what they are and specifing them in the launch url._

We can implement a gate at a later time.

**NOTE**
The implementation currently mimics the existing `LTI 1.1` provider where the launch url is formatted like: `/lti/1p3/launch/<course_id>/<usage_id>`. For LTI 1.3 this means that if a client wants to reuse their securitiy contract for a different launch they would need to add the new URL to their acceptable `redirect_uri`'s.

**Future Breaking Change**
The more friendly implementation in LTI 1.3 is to use a static launch url: `/lti/1p3/launch/` and then use the `target_link_uri` claim to determine what content to acutally show the user. This allows a consumer to easily reuse an existing security contract in a new resource link.

This implemenation has already been completed on the `feat/#1-static-redirect-uri` branch, but will be a breaking change for consumer as the url formats will change as follows:
- `redirect_uri`:
    - from: `/lti/1p3/launch/course-v1:Org+Course+Run/block-v1:Org+Course+Run+type@problem+block@htmlid`
    - to: `/lti/1p3/launch/`
- `target_link_uri`:
    - from: `/lti/1p3/launch/course-v1:Org+Course+Run/block-v1:Org+Course+Run+type@problem+block@htmlid`
    - to: `/lti/1p3/launch/?course_id=course-v1:Org%2BCourse%2BRun&usage_id=block-v1:Org%2BCourse%2BRun%2Btype@problem%2Bblock@htmlid`

# Installation
```shell
pip install git+https://github.com/ibleducation/ibl-edx-lti-1p3-provider-app
```

# Setup
## Edx
- Ensure `settings.FEATURES['ENABLE_LTI_1P3_PROVIDER] = True` is set in `lms/envs/common.py`
- Add a condition to add the lti 1.3 provider authentication backend:
```python

if FEATURES.get("ENABLE_LTI_1P3_PROVIDER"):
    AUTHENTICATION_BACKENDS.append("lti_1p3_provider.auth.Lti1p3AuthenticationBackend")
```

These are both implemented in the included `tutor_plugins/enable_lti_1p3_provider.py` tutor plugin.

## Optional Settings
- `LTI_AGGREGATE_SCORE_PASSBACK_DELAY`: Number of seconds to wait to perform grade passback on composite modules (subsections and units). This helps [batch requests](https://docs.celeryq.dev/en/stable/userguide/calling.html#eta-and-countdown). [default: 15 minutes](https://github.com/openedx/edx-platform/blob/6db1e1db26a0d307446109334f49841aa9aae599/lms/envs/common.py/#L4302-L4312)


## Setup an LTI Tool Key
You technically only need to do this once. It's going to be the Private/Public key for one or multiple tools to use.

- Go to the django admin
- Select `Lti 1.3 tool keys` under the `PYLTI 1.3 TOOL CONFIG` heading
- Select `Add LTI 1.3 TOOL KEY`
- Give it a name
- Add a `Private Key` and it's correspondging `Public Key`
    - These should be a PEM in the formats: `-----BEGIN RSA PRIVATE KEY-----` and `-----BEGIN PUBLIC KEY-----`
- Click `Save`


## Setup a Tool
To setup a Tool, complete the following steps. You will need to get several entries from the `Platform` (Consumer):
- Go to the django admin
- Select `Lti 1.3 tools` under the `PYLTI 1.3 TOOL CONFIG` heading
- Select `Add LTI 1.3 TOOL`
    - `Title`: Give the tool a name
    - `Is active`: Make sure this is checked
    - `Issuer`: Get from the `Platform`
    - `Client id`: Get from `Platform`
    - `Use by default`: leave this unchecked
    - `Auth login url`: Get from `Platform` (OIDC Authorication Endpoint)
    - `Auth token url`: Get from `Platform` (OIDC Token Endpoint)
    - `Auth audience`: Should be able to leave this blank
    - `Key set url`: Get from `Platform` if available
    - `Key set`: If no `Key set url` is available, paste the JWKS information here
        - This will be a `json` string like the following:
        ```json
        {
            "e": "AQAB",
            "kid": "_MrLpE3BZv9Ecxpo5J93WTm732I0ktE64nv6c8ywywI",
            "kty": "RSA",
            "n": "uDmuwK_POsBicZy7lnFAMo_9QNu-W_yqTuzV8g5p-NM1xzD4Gj1dJel2IKi-eh9Rwyc8dPrJWfA0BaHx0ggA9hMXLVjql9UtRYm3wf7uJ8JfDfePYOHGHymLalRVCT_wXP7EO0l1BarNRqG-c9OVG6rELryosQxCgt5p4ipE_RU5OPOYK5eZKnOUAHkcbUO1Xtqlm8FghWqjrDEqS6wbteCBqUuFYBjReG47L-UJp_THt0hI-iYnnDmuIVZdkVpmNYHW3RbsZIj1Oc62msRzknLHP-UJlN6125H3hwvBzcl2xLXMi8eQ5Nd1NKP0Zj-asEJgiCU5cMp0U6F63wZ-oQ",
            "alg": "RS256",
            "use": "sig"
        }
        ```
    - `Tool key`: Select one of the `Lti Tool Key`'s you generated earlier
        - This is the Private/Public key the Tool will use to sign its messages and that the `Platform` will use to verify them
    - `Deployment ids`: Get from `Platform`
        - This should be a list of strings: `["1", "deployment 2"]`, etc
- Select `Save`

## Info to give the Platform
Provide the following information to the `Platform` for their side of the integration:
- Tool Launch Endpoint: `https://<lms_domain.com>/lti/1p3/launch/<course_id>/<usage_id>`
- Login Initiations Endpoint: `https://<lms_domain.com>/lti/1p3/login/`
- JWKS Endpoint (Tool Keyset): `https://<lms_domain.com>/lti/1p3/pub/jwks/`
- Deep Linking Endpoint: _Not yet implemented_

To use the LTI Assignment and Grades service (Grade pasback), the `Platform` will need to allow the following scopes for the Tool OAuth2 client:
- `https://purl.imsglobal.org/spec/lti-ags/scope/lineitem`
- `https://purl.imsglobal.org/spec/lti-ags/scope/score`

# Additional Notes
- The course must be published and available (course must be started) for a `Platform` for be able to use it.
