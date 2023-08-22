import json
from time import time

import factory
from common.djangoapps.student.tests.factories import UserFactory
from django.urls import reverse
from opaque_keys.edx.locator import CourseLocator
from pylti1p3.contrib.django.lti1p3_tool_config.models import LtiTool, LtiToolKey
from pylti1p3.registration import Registration

from lti_1p3_provider.models import LtiGradedResource, LtiProfile

COURSE_KEY = CourseLocator(org="Org1", course="Course1", run="Run1")
USAGE_KEY = COURSE_KEY.make_usage_key("vertical", "some-html-id")
PLATFORM_ISSUER = "https://platform-server.local"

TOOL_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA10J7KckUBNpn+augqvkLBDHlmU04yTTG1Rjkp9ATEP/vt0t/
OtgIiMV2lBMXpDzHkJl67ZUSnOzDyeQfmSfCODn/5my5PGbMEBSFC4yKx94UVQhB
zPygfIAuUFyMzsoYQgiZpIInm7Rg8zGlWazNv9RonuDzGAtkVAdCsVBrAP0JdWfG
rRZUpTfQl/diblq3CxZaagAJVqnRWuWoNAv7m1NozqedNdZIjG8pXzM+yMP/8gQN
8/mh2wmu8uNSwg54WGFDzGnQ55jYBKDjFr0PSCC9lK8+u/8p097xJ5RQbRbcX6Le
4YzsgjQj6aBaF6yNOSFKRGqLALrGW6ho6ypxxQIDAQABAoIBAH4TAe/HRWJSSPOC
AeghVMJwNvlCsS+nKY1FtyZSR9h9Dflczne4b8crX/f59q7KqleWjNj5pp0iTsnA
QoGBN8+WqLpck2E9E+eXHRVWizHkcCQdYeydSaGhsX5/tjinRO3n+5TOZkRbsSy+
twl+nELuNRhYyAgdI/XTCsyvPPymJAseh6WXbWt9bUFYex+I7sjJjpjcN1XajL3F
F7rTJk7b7rhpIKSmGVd9wTokW5Iw3Nsv5/X4ONflGO7s5pD9CMbVW1yWs/wigsYy
hCti5gLyfCyWxQaeTdASd2a6UABZGiWMOBUv+gnH8ft/xkTBbdSilcUzeF7yRJF6
SmPMsgECgYEA73jhevLVXyVLY468OINU4S0K6llV4ca9FZ1cTasCeZ1hH/5HWxAe
VbSB5FCe0M+eIEwDod+fftvxzJSuR1bIeipNxYenousznvgOGSA4U6sg39NNMeHc
iZNU/PvJ0Rxy1po7NaatH+a8jaElBzDWkKx9dbClsv7mvLVFVzDY5l0CgYEA5h3N
IjB+8CUKPyiQ4FczaYtJtTKiJl/kZIB8TFfgoT60g8vXgESeq+WJ3RFRKdkNOs5c
LDogafVldSz5dpIy7uT90PTswOiA+ZrItzIfdGXhPvm09DggJF8OcG2ezr5iwIZL
00PIwTsYAItgvbB39O60aG1Kkasbng9l+l7tMokCgYBAzq324BDuluE4KEC36pLl
/ZKeqV6co3Q4jUWVn1okH3tRdTdKZapP93HPoCHa0NUyWGADRsmbQ1rEytf/ZnUK
2rgBZRzw8kYeF3N5SUb1HbLf4AdcIIvWj5DIhjuv48sQWNz9QAZKQ99zVND4iTcI
ICYz24J8Vo+LMmN5nTaV4QKBgHcmiybe0Xtq0mlticZ/oGFP+/RUqV0RXeMkHDgz
cF5NZ46up4EFBtue2Mmcw9fVSWJfo55K4qm6pLQNe4YHoVPNQhdGGqiwOsgDe1ZQ
H7VXY1AGX8nsncf3aDSSrh4CuoNRhkV33aUgAgeWI5tUmmg6iTNhE7FlVcF726PO
LydxAoGBAJzS155vOYmsyUBApHEID2rToIAmmVvmNBAUmQ4s/waVP7Ki5Z3EeHjc
TGeEIIKzYpOjacnYGxW1jR3GRaidbC1/GkaH4X40S5nNOUnDubogwbRseK0/p/wc
roFAOJMyDjXo+QbCFAPy/0cGWzIrbQ5FD03IZ3B6AahIdl3CeGzD
-----END RSA PRIVATE KEY-----"""

TOOL_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA10J7KckUBNpn+augqvkL
BDHlmU04yTTG1Rjkp9ATEP/vt0t/OtgIiMV2lBMXpDzHkJl67ZUSnOzDyeQfmSfC
ODn/5my5PGbMEBSFC4yKx94UVQhBzPygfIAuUFyMzsoYQgiZpIInm7Rg8zGlWazN
v9RonuDzGAtkVAdCsVBrAP0JdWfGrRZUpTfQl/diblq3CxZaagAJVqnRWuWoNAv7
m1NozqedNdZIjG8pXzM+yMP/8gQN8/mh2wmu8uNSwg54WGFDzGnQ55jYBKDjFr0P
SCC9lK8+u/8p097xJ5RQbRbcX6Le4YzsgjQj6aBaF6yNOSFKRGqLALrGW6ho6ypx
xQIDAQAB
-----END PUBLIC KEY-----"""

PLATFORM_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA6WAbp8EbTHrlMtpJWfBX55t5vsCZAIGjgK/6LV1CjDzO0Wx/
yjWNugLe6cjLep3ZC0fYiQuRYZ5pyBrmdqT7w2pvySDFHCjHXkUGVtna9aQvX1Qt
ExTLmFKLQ0bip2JkbUcFSJTRTb0u41/xGenSvY9yEyQwvQELbw7FEO/iHayJD2Gd
n4BmaVgi/N05/wKtN4+KJALnf5uEKpcu7KvMXWjoGwwEdjk7msSR3+kz/b3y3Um3
vAvn52fSMXftM6QLqXeJjORZGV4P4enkOn6z4Dxgl26zrL1QTRU8YMCC8qyTM38I
uP7M+dOxq+IiMXKvDuqEjP61dLO4H4tulqENNwIDAQABAoIBAHx4YAem/PJbkab/
uaOYhqnmyJYujuwwOI5ITXyogvfc7snPvpCQ45hUM6QpDi3Fxp83oIvneZDBNtYd
UtHwyL6/JAP30Glmbn8e/XSRGTFucj273ZaRvsztKY2mXvi7h6io+m5twPxfbISl
BSi3B0lHGqaO5NfJmNmQ3RZdexIrkOsKbqsrO9K182Bm3cGKHMF7l/ASUSkVmhBb
+LJ8DC9vASA33WsUrJyKpDvt6Wq2RBfNilKmuThWnkhbryUZcN9BCGXIvXjuRrUl
QB/hYdeRlrdWXHWfSiqEaw3LEYdAKazcA29VPuropzo1GwEzSzniEPvvsw4Uc3qZ
HVxThFECgYEA9Ktws9IzqybZ6aJevTrimjmnkoOo0A+F8I21RwaBU5etG0bAOMfc
lnmzLbb9YvkYBrZOaXCDDKTFrG7ESPd58PWj8EFZLEkaprka8wkS1krayVuBnOjd
HSdP6476ycwDE0h3JdY3rUL7VcqNfC5rGuV2l7Wy0uwwvebcGeeXLxUCgYEA9C7G
M85Ap4ePKAIE+4aAu6ZagLuB0nNynHXcQjqXKxlKa/+LOS5pmJEsVmp/lqgbAuKb
ulYDyC5Y6yIALhg25F5bcf0vIjI+lGOto2ti6vM0Zm92w+rMAILtODHj9hkouVC/
YJznGSagNnpeYWJxfnl6pGSR1exPlNnOfK0oPhsCgYAc79XRfq/bsymcpzZ7POam
BOGbw3SIvv1BWREyiENtZofzrOd5D7I4HcaiRn0rYniD+rXFZKgrK6WxYhxW4OYM
KJEuDhyEz1SWmVflnJIcxBeiLu9iZmwYUZjzLCLfEQDgG/bzg6VsGXruR5l6MWc7
dB4VjUjMB2EwZIhti+VmjQKBgDuGS3rFhK1SNmuiUmSeXTNhUh6flv4edon9kTvz
3HX9LE83dFD0J3mxqgVG4ONxB2SkqSG7ZiCea76mAzU5Yeg5uEEJXzwO04KI6gM0
YmCz+Mof0evgiOp3ACz6vH95kpvaO0zp8swGxneBTRCgVtpl8qewfHyRprS6g8OQ
0oaRAoGBALqoBw5NCizJXo25v1cHMRRHka996T8DowIgJClFlL73ggxitBHfNPWG
VWBdXfScQgAHU5y2DjrMfthnDY3ghOiCX3duEzFBp/2yTuZhMF6Wb5IKW+Sg9xAp
CWApJbnbNUyXCzYU8ZcLWKDrIre/wUCCXqZ+oqRfQEhhdeJKh49U
-----END RSA PRIVATE KEY-----"""

PLATFORM_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6WAbp8EbTHrlMtpJWfBX
55t5vsCZAIGjgK/6LV1CjDzO0Wx/yjWNugLe6cjLep3ZC0fYiQuRYZ5pyBrmdqT7
w2pvySDFHCjHXkUGVtna9aQvX1QtExTLmFKLQ0bip2JkbUcFSJTRTb0u41/xGenS
vY9yEyQwvQELbw7FEO/iHayJD2Gdn4BmaVgi/N05/wKtN4+KJALnf5uEKpcu7KvM
XWjoGwwEdjk7msSR3+kz/b3y3Um3vAvn52fSMXftM6QLqXeJjORZGV4P4enkOn6z
4Dxgl26zrL1QTRU8YMCC8qyTM38IuP7M+dOxq+IiMXKvDuqEjP61dLO4H4tulqEN
NwIDAQAB
-----END PUBLIC KEY-----"""


class OidcLoginFactory(factory.DictFactory):
    """Query params for an 3rd party launch"""

    login_hint: str = "test_user"
    iss = PLATFORM_ISSUER

    class Params:
        domain = "localhost"
        protocol = "http"
        course_id = str(COURSE_KEY)
        usage_id = str(USAGE_KEY)

    @factory.lazy_attribute
    def target_link_uri(self):
        """Return target link uri for domain, course_id, and usage_id"""
        endpoint = reverse(
            "lti_1p3_provider:lti-launch",
            kwargs={"course_id": self.course_id, "usage_id": self.usage_id},
        )
        return f"{self.protocol}://{self.domain}{endpoint}"


class LtiToolKeyFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = LtiToolKey

    name = factory.Sequence(lambda n: f"Key {n}")
    private_key = TOOL_PRIVATE_KEY
    public_key = TOOL_PUBLIC_KEY


class LtiToolFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = LtiTool

    title = factory.Sequence(lambda n: f"Tool Consumer {n}")
    is_active = True
    issuer = PLATFORM_ISSUER
    client_id = factory.Sequence(lambda n: f"client-id-{n}")
    use_by_default = False
    auth_login_url = "http://some-domain.local/auth"
    auth_token_url = "http://some-domain.local/token"
    auth_audience = ""
    key_set_url = None
    tool_key = factory.SubFactory(LtiToolKeyFactory)
    deployment_ids = '["1"]'

    @factory.lazy_attribute
    def key_set(self):
        jwt = Registration.get_jwk(PLATFORM_PUBLIC_KEY)
        keys = {"keys": [jwt]}
        return json.dumps(keys)


class LtiProfileFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = LtiProfile

    user = factory.SubFactory(UserFactory)
    platform_id = PLATFORM_ISSUER
    client_id = "client-id"
    subject_id = factory.Sequence(lambda n: f"user-{n}")


class LtiGradedResourceFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = LtiGradedResource

    profile = factory.SubFactory(LtiProfileFactory)
    course_key = COURSE_KEY
    usage_key = USAGE_KEY
    resource_id = factory.Sequence(lambda n: f"resource-link-id-{n}")
    resource_title = "Resource Title"
    ags_lineitem = factory.Sequence(lambda n: f"{PLATFORM_ISSUER}/ags/lineitem/{n}")
    version_number = 0


class ResourceLinkFactory(factory.DictFactory):
    """Resource Link Claim keys"""

    id = "some-link-id"
    title = "Resource Title"


class LtiAgsFactory(factory.DictFactory):
    class Params:
        has_result_scope = True
        has_score_scope = True
        has_lineitem_scope = True

    lineitems = "http://platform-server.local/ags/100/lineitems"
    lineitem = "http://platform-server.local/ags/100/lineitems/1234/lineitem"

    @factory.lazy_attribute
    def scope(self):
        scopes = []
        if self.has_result_scope:
            scopes.append(
                "https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly"
            )
        if self.has_score_scope:
            scopes.append("https://purl.imsglobal.org/spec/lti-ags/scope/score")
        if self.has_lineitem_scope:
            scopes.append("https://purl.imsglobal.org/spec/lti-ags/scope/lineitem")
        return scopes


class IdTokenFactory(factory.DictFactory):
    """An LTI Launch request"""

    # Aud is tool's client_id
    aud: str
    state: str
    iss = PLATFORM_ISSUER
    sub = "test-user"
    iat = factory.LazyAttribute(lambda self: int(time()))
    exp = factory.LazyAttribute(lambda self: int(time()) + 1000)
    nonce = "test-nonce"

    # LTI Params
    deployment_id = "1"
    target_link_uri: str
    resource_link = factory.SubFactory(ResourceLinkFactory)
    roles = factory.LazyAttribute(
        lambda self: ["http://purl.imsglobal.org/vocab/lis/v2/membership#Learner"]
    )
    lineitem = None

    @classmethod
    def _create(cls, model_class, *args, **kwargs):
        obj = super()._create(model_class, *args, **kwargs)
        obj[
            "https://purl.imsglobal.org/spec/lti/claim/message_type"
        ] = "LtiResourceLinkRequest"
        obj["https://purl.imsglobal.org/spec/lti/claim/version"] = "1.3.0"
        obj["https://purl.imsglobal.org/spec/lti/claim/deployment_id"] = obj.pop(
            "deployment_id"
        )
        obj["https://purl.imsglobal.org/spec/lti/claim/target_link_uri"] = obj.pop(
            "target_link_uri"
        )
        obj["https://purl.imsglobal.org/spec/lti/claim/resource_link"] = obj.pop(
            "resource_link"
        )
        obj["https://purl.imsglobal.org/spec/lti/claim/roles"] = obj.pop("roles")

        # Adds optional ags lineitm if present
        if obj["lineitem"]:
            obj["https://purl.imsglobal.org/spec/lti-ags/claim/endpoint"] = obj.pop(
                "lineitem"
            )
        else:
            obj.pop("lineitem")

        return obj
