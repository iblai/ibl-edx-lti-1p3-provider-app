import factory
from django.urls import reverse
from opaque_keys.edx.keys import CourseKey, UsageKey
from pylti1p3.contrib.django.lti1p3_tool_config.models import LtiTool, LtiToolKey

COURSE_KEY = CourseKey.from_string("course-v1:Org1+Course1+Run1")
USAGE_KEY = COURSE_KEY.make_usage_key("vertical", "some-html-id")

TEST_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
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

TEST_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA10J7KckUBNpn+augqvkL
BDHlmU04yTTG1Rjkp9ATEP/vt0t/OtgIiMV2lBMXpDzHkJl67ZUSnOzDyeQfmSfC
ODn/5my5PGbMEBSFC4yKx94UVQhBzPygfIAuUFyMzsoYQgiZpIInm7Rg8zGlWazN
v9RonuDzGAtkVAdCsVBrAP0JdWfGrRZUpTfQl/diblq3CxZaagAJVqnRWuWoNAv7
m1NozqedNdZIjG8pXzM+yMP/8gQN8/mh2wmu8uNSwg54WGFDzGnQ55jYBKDjFr0P
SCC9lK8+u/8p097xJ5RQbRbcX6Le4YzsgjQj6aBaF6yNOSFKRGqLALrGW6ho6ypx
xQIDAQAB
-----END PUBLIC KEY-----"""


class OidcLoginFactory(factory.DictFactory):
    """Query params for an 3rd party launch"""

    login_hint: str = "test_user"
    iss = "localhost"

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
    private_key = TEST_PRIVATE_KEY
    public_key = TEST_PUBLIC_KEY


class LtiToolFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = LtiTool

    title = factory.Sequence(lambda n: f"Tool Consumer {n}")
    is_active = True
    issuer = "localhost"
    client_id = factory.Sequence(lambda n: f"client-id-{n}")
    use_by_default = False
    auth_login_url = "http://some-domain.local/auth"
    auth_token_url = "http://some-domain.local/token"
    auth_audience = ""
    key_set_url = None
    key_set = None
    tool_key = factory.SubFactory(LtiToolKeyFactory)
    deployment_ids = "[]"
