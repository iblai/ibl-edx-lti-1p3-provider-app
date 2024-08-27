from __future__ import annotations

import copy
from typing import Any

import pytest
from common.djangoapps.student.tests.factories import UserFactory
from django.urls import reverse
from lti_1p3_provider.models import LtiKeyOrg, LtiToolOrg
from lti_1p3_provider.tests import factories
from openedx.core.djangoapps.oauth_dispatch.tests.factories import (
    AccessTokenFactory,
    ApplicationFactory,
)
from organizations.tests.factories import OrganizationFactory
from pylti1p3.contrib.django.lti1p3_tool_config.models import LtiTool, LtiToolKey


@pytest.fixture(autouse=True)
def enable_lti_1p3(settings):
    settings.FEATURES["ENABLE_LTI_1P3_PROVIDER"] = True


@pytest.fixture
def admin_token() -> str:
    user = UserFactory(is_staff=True)
    app = ApplicationFactory(user=user)
    access_token = AccessTokenFactory(user=user, application=app)
    yield access_token.token


@pytest.fixture
def non_admin_token() -> str:
    user = UserFactory(is_staff=False)
    app = ApplicationFactory(user=user)
    access_token = AccessTokenFactory(user=user, application=app)
    yield access_token.token


class BaseView:
    def request(
        self,
        client,
        method: str,
        endpoint: str,
        data: dict[str, Any] | None = None,
        token: str = "",
    ):
        extra = {"HTTP_AUTHORIZATION": f"Bearer {token}"}
        if method in ("post", "put"):
            extra["content_type"] = "application/json"
        if not token:
            extra.pop("HTTP_AUTHORIZATION")

        return getattr(client, method)(endpoint, data=data, **extra)


@pytest.mark.django_db
class TestLtiKeyViews(BaseView):
    def _get_list_endpoint(self, org_short_name) -> str:
        return reverse(
            "lti_1p3_provider:lti-keys-list", kwargs={"org_short_name": org_short_name}
        )

    def _get_detail_endpoint(self, org_short_name, pk) -> str:
        return reverse(
            "lti_1p3_provider:lti-keys-detail",
            kwargs={"org_short_name": org_short_name, "pk": pk},
        )

    def test_create_returns_201(self, client, admin_token):
        """Test creating a key for an org returns a 201"""
        org1 = OrganizationFactory()
        payload = {"name": "test"}
        endpoint = self._get_list_endpoint(org1.short_name)

        resp = self.request(client, "post", endpoint, data=payload, token=admin_token)

        # LtiToolKey is created
        key = LtiToolKey.objects.get(name=f"{org1.short_name}-test")
        assert key.private_key
        assert key.public_key
        assert key.public_jwk

        # LtiKeyOrg is created
        key_org = key.key_org
        assert key_org.org == org1

        # Good response
        key = key_org.key
        assert resp.status_code == 201
        assert resp.json() == {
            "public_key": key.public_key,
            "public_jwk": key.public_jwk,
            "name": "test",
            "id": key.id,
        }

    def test_create_org_dne_returns_400(self, client, admin_token):
        """Test creating key for org that DNE returns 400"""
        payload = {"name": "test"}
        endpoint = self._get_list_endpoint("dne")

        resp = self.request(client, "post", endpoint, data=payload, token=admin_token)

        assert resp.json() == {"non_field_errors": ["Org: 'dne' Does Not Exist"]}
        assert resp.status_code == 400

    def test_create_name_already_exists_in_org_returns_400(self, client, admin_token):
        """Test creating a tool name that already exists in org returns 400"""
        org1 = OrganizationFactory()
        factories.LtiToolKeyFactory(name=f"{org1.short_name}-test")
        payload = {"name": "test"}
        endpoint = self._get_list_endpoint(org1.short_name)

        resp = self.request(client, "post", endpoint, data=payload, token=admin_token)

        assert resp.json() == ["Key name: 'test' already exists"]
        assert resp.status_code == 400

    def test_create_same_name_in_multiple_orgs_succeeds_200(self, client, admin_token):
        """Multiple orgs can create tokens with the same name from their perspective"""
        org1 = OrganizationFactory()
        org2 = OrganizationFactory()
        payload = {"name": "test"}
        endpoint1 = self._get_list_endpoint(org1.short_name)
        endpoint2 = self._get_list_endpoint(org2.short_name)

        resp1 = self.request(client, "post", endpoint1, data=payload, token=admin_token)
        resp2 = self.request(client, "post", endpoint2, data=payload, token=admin_token)

        assert resp1.status_code == 201
        assert resp2.status_code == 201

        key1 = LtiKeyOrg.objects.get(org=org1).key
        assert key1.name == f"{org1.short_name}-test"
        key2 = LtiKeyOrg.objects.get(org=org2).key
        assert key2.name == f"{org2.short_name}-test"

    def test_list_returns_keys_for_specified_org_only(self, client, admin_token):
        """Test returns LtiKeys for specified org only"""
        org1 = OrganizationFactory()
        org2 = OrganizationFactory()
        key1_org1 = factories.LtiKeyOrgFactory(
            org=org1, key__name=f"{org1.short_name}-key-1"
        )
        key2_org1 = factories.LtiKeyOrgFactory(
            org=org1, key__name=f"{org1.short_name}-key-2"
        )
        endpoint = self._get_list_endpoint(key1_org1.org.short_name)

        # These won't be returned
        key1_org2 = factories.LtiKeyOrgFactory(
            org=org2, key__name=f"{org2.short_name}-key-1"
        )
        key2_org2 = factories.LtiKeyOrgFactory(
            org=org2, key__name=f"{org2.short_name}-key-2"
        )

        resp = self.request(client, "get", endpoint, token=admin_token)

        data = resp.json()["results"]

        key1 = key1_org1.key
        key2 = key2_org1.key
        assert data == [
            {
                "name": "key-1",
                "public_key": key1.public_key,
                "public_jwk": key1.public_jwk,
                "id": key1.id,
            },
            {
                "name": "key-2",
                "public_key": key2.public_key,
                "public_jwk": key2.public_jwk,
                "id": key2.id,
            },
        ]
        assert resp.status_code == 200

    def test_list_org_dne_returns_empty_list_with_200(self, client, admin_token):
        """If org dne, empty list is returned with 200"""
        endpoint = self._get_list_endpoint("dne")

        resp = self.request(client, "get", endpoint, token=admin_token)

        data = resp.json()
        assert data["count"] == 0
        assert data["results"] == []
        assert resp.status_code == 200

    def test_delete_returns_204(self, client, admin_token):
        """Delete removes LtiToolKey and LtiKeyOrg for specified enttiy, returns 204"""
        key_org = factories.LtiKeyOrgFactory()
        org = key_org.org
        key = key_org.key
        endpoint = self._get_detail_endpoint(org.short_name, key.pk)

        resp = self.request(client, "delete", endpoint, token=admin_token)

        assert resp.status_code == 204

        assert LtiKeyOrg.objects.count() == 0
        assert LtiToolKey.objects.count() == 0

    def test_delete_key_not_in_target_org_returns_404(self, client, admin_token):
        """Delete removes LtiToolKey and LtiKeyOrg for specified enttiy, returns 204"""
        other_org = OrganizationFactory()
        key_org = factories.LtiKeyOrgFactory()
        key = key_org.key
        endpoint = self._get_detail_endpoint(other_org.short_name, key.pk)

        resp = self.request(client, "delete", endpoint, token=admin_token)

        assert resp.json() == {"detail": "Not found."}
        assert resp.status_code == 404

    def test_detail_returns_200(self, client, admin_token):
        """Detail endpoint returns entity"""
        org = OrganizationFactory()
        key_org = factories.LtiKeyOrgFactory(
            org=org, key__name=f"{org.short_name}-test"
        )
        org = key_org.org
        key = key_org.key
        endpoint = self._get_detail_endpoint(org.short_name, key.pk)

        resp = self.request(client, "get", endpoint, token=admin_token)

        assert resp.json() == {
            "name": "test",
            "public_key": key.public_key,
            "public_jwk": key.public_jwk,
            "id": key.id,
        }
        assert resp.status_code == 200

    def test_update_key_name_already_exists_returns_400(self, client, admin_token):
        """Test updating a tool name that already exists in org returns 400"""
        org1 = OrganizationFactory()
        org_key1 = factories.LtiKeyOrgFactory(
            org=org1, key__name=f"{org1.short_name}-test1"
        )
        org_key = factories.LtiKeyOrgFactory(
            org=org1, key__name=f"{org1.short_name}-test"
        )
        # try to rename it to test which is already taken in this org
        payload = {"name": "test1"}
        endpoint = self._get_detail_endpoint(org1.short_name, org_key.key.id)

        resp = self.request(client, "put", endpoint, data=payload, token=admin_token)

        assert resp.json() == ["Key name: 'test1' already exists"]
        assert resp.status_code == 400

    def test_update_returns_200(self, client, admin_token):
        """Update updates name and returns 200"""
        org = OrganizationFactory()
        key_org = factories.LtiKeyOrgFactory(
            org=org, key__name=f"{org.short_name}-test"
        )
        org = key_org.org
        key = key_org.key
        endpoint = self._get_detail_endpoint(org.short_name, key.pk)
        payload = {"name": "new-name"}

        resp = self.request(client, "put", endpoint, data=payload, token=admin_token)

        assert resp.json() == {
            "name": "new-name",
            "public_key": key.public_key,
            "public_jwk": key.public_jwk,
            "id": key.id,
        }
        assert resp.status_code == 200
        key.refresh_from_db()
        assert key.name == f"{org.short_name}-new-name"


@pytest.mark.django_db
class TestLtiToolViews(BaseView):
    def _get_list_endpoint(self, org_short_name) -> str:
        return reverse(
            "lti_1p3_provider:lti-tools-list", kwargs={"org_short_name": org_short_name}
        )

    def _get_detail_endpoint(self, org_short_name, pk) -> str:
        return reverse(
            "lti_1p3_provider:lti-tools-detail",
            kwargs={"org_short_name": org_short_name, "pk": pk},
        )

    def setup_method(self):
        self.key_org = factories.LtiKeyOrgFactory()
        self.org = self.key_org.org
        self.key = self.key_org.key

        self.payload = {
            "title": "test",
            "is_active": True,
            "issuer": "https://issuer.local",
            "client_id": "12345",
            "auth_login_url": "https://issuer.local/auth",
            "auth_token_url": "https://issuer.local/token",
            "auth_audience": "",
            "key_set_url": "https://issuer.local/keyset",
            "key_set": "",
            "tool_key": self.key.id,
            "deployment_ids": [1, "test", 1234, "5"],
            "launch_gate": {
                "allowed_keys": [
                    f"block-v1:{self.org.short_name}+course+run+type@obj+block@uuid"
                ],
                "allowed_courses": [f"course-v1:{self.org.short_name}+course+run"],
                "allow_all_within_org": False,
            },
        }

    @pytest.mark.parametrize("pop_key_field", ("key_set_url", "key_set"))
    def test_create_returns_201(self, pop_key_field, client, admin_token):
        """Test creating a tool for an org returns a 201

        Allows missing either key_set or key_set_url
        """
        endpoint = self._get_list_endpoint(self.org.short_name)
        self.payload["key_set"] = factories.TOOL_JWK
        self.payload.pop(pop_key_field)

        resp = self.request(
            client, "post", endpoint, data=self.payload, token=admin_token
        )

        assert resp.status_code == 201, resp.json()
        tool = LtiTool.objects.get(client_id="12345")
        expected = self.payload.copy()
        expected["id"] = tool.id
        expected[pop_key_field] = None
        expected["deployment_ids"] = [str(x) for x in self.payload["deployment_ids"]]
        assert resp.json() == expected
        assert tool.tool_org.org == self.org
        # Validate launchg gate created
        launch_gate = tool.launch_gate
        assert launch_gate.allowed_keys == self.payload["launch_gate"]["allowed_keys"]
        assert (
            launch_gate.allowed_courses
            == self.payload["launch_gate"]["allowed_courses"]
        )
        assert not launch_gate.allowed_orgs

    def test_create_invalid_course_key_returns_400(self, client, admin_token):
        """If course_key is invalid, returns 400"""
        endpoint = self._get_list_endpoint(self.org.short_name)
        self.payload["launch_gate"]["allowed_courses"] = ["bad-key"]

        resp = self.request(
            client, "post", endpoint, data=self.payload, token=admin_token
        )

        assert resp.status_code == 400, resp.json()
        assert resp.json() == {
            "launch_gate": {
                "allowed_courses": [
                    "Invalid Course Key. Format is: course-v1:<org>+<course>+<run>"
                ]
            }
        }

    def test_create_invalid_usage_key_returns_400(self, client, admin_token):
        """If usage_key is invalid, returns 400"""
        endpoint = self._get_list_endpoint(self.org.short_name)
        self.payload["launch_gate"]["allowed_keys"] = ["bad-key"]

        resp = self.request(
            client, "post", endpoint, data=self.payload, token=admin_token
        )

        assert resp.status_code == 400, resp.json()
        assert resp.json() == {
            "launch_gate": {
                "allowed_keys": [
                    "Invalid Usage Key. Format is: "
                    "block-v1:<org>+<course>+<run>+type@<block_type>+block@<hex_uuid>"
                ]
            }
        }

    def test_create_using_non_supplied_defaults_returns_201_with_defaults_set(
        self, client, admin_token
    ):
        """If default values are not supplied, still works and sets as defaults"""
        endpoint = self._get_list_endpoint(self.org.short_name)
        expected = self.payload.copy()
        self.payload.pop("is_active")
        self.payload.pop("auth_audience")
        self.payload.pop("key_set")

        resp = self.request(
            client, "post", endpoint, data=self.payload, token=admin_token
        )

        assert resp.status_code == 201, resp.json()
        tool = LtiTool.objects.get(client_id="12345")
        expected["id"] = tool.id
        expected["auth_audience"] = None
        expected["key_set"] = None
        expected["deployment_ids"] = [str(x) for x in self.payload["deployment_ids"]]
        assert resp.json() == expected
        assert tool.tool_org.org == self.org

    def test_create_missing_both_key_set_and_key_set_url_returns_400(
        self, client, admin_token
    ):
        """Test missing key_set_url and key_set returns 400"""
        endpoint = self._get_list_endpoint(self.org.short_name)
        self.payload.pop("key_set_url")
        self.payload.pop("key_set")

        resp = self.request(
            client, "post", endpoint, data=self.payload, token=admin_token
        )

        assert resp.json() == {
            "non_field_errors": ["Either key_set_url or key_set must be supplied"]
        }
        assert resp.status_code == 400

    def test_create_if_org_dne_returns_400(self, client, admin_token):
        """Test creating key for org that DNE returns 400"""
        endpoint = self._get_list_endpoint("dne")

        resp = self.request(
            client, "post", endpoint, data=self.payload, token=admin_token
        )

        assert resp.json() == {
            "tool_key": [f'Invalid pk "{self.key.id}" - object does not exist.'],
            "launch_gate": {
                "allowed_courses": ["Course Key must be within org: dne"],
                "allowed_keys": ["Usage Key must be within org: dne"],
            },
        }
        assert resp.status_code == 400

    def test_create_if_launch_gate_courses_or_keys_not_in_org_returns_400(
        self, client, admin_token
    ):
        """If launch gate courses/keys not within target org, 400 is returned"""
        org1 = OrganizationFactory()
        org2 = OrganizationFactory()
        self.payload["launch_gate"]["allowed_courses"] = [
            f"course-v1:{org1.short_name}+course+run"
        ]
        self.payload["launch_gate"]["allowed_keys"] = [
            f"block-v1:{org2.short_name}+course+run+type@obj+block@uuid"
        ]
        endpoint = self._get_list_endpoint(self.org.short_name)

        resp = self.request(
            client, "post", endpoint, data=self.payload, token=admin_token
        )

        assert resp.json() == {
            "launch_gate": {
                "allowed_courses": [
                    f"Course Key must be within org: {self.org.short_name}"
                ],
                "allowed_keys": [
                    f"Usage Key must be within org: {self.org.short_name}"
                ],
            },
        }
        assert resp.status_code == 400

    def test_create_tool_key_dne_returns_400(self, client, admin_token):
        """If key DNE, 400 is returned"""
        bad_id = self.key.id + 1000
        endpoint = self._get_list_endpoint(self.org.short_name)
        self.payload["tool_key"] = bad_id

        resp = self.request(
            client, "post", endpoint, data=self.payload, token=admin_token
        )

        assert resp.json() == {
            "tool_key": [f'Invalid pk "{bad_id}" - object does not exist.']
        }
        assert resp.status_code == 400

    def test_create_tool_key_in_other_org_returns_400(self, client, admin_token):
        """If trying to use a key that doesn't belong to your org, 400 is returned"""
        new_key_org = factories.LtiKeyOrgFactory()
        endpoint = self._get_list_endpoint(self.org.short_name)
        # This key belongs to a different org
        self.payload["tool_key"] = new_key_org.key.id

        resp = self.request(
            client, "post", endpoint, data=self.payload, token=admin_token
        )

        assert resp.json() == {
            "tool_key": [f'Invalid pk "{new_key_org.key.id}" - object does not exist.']
        }
        assert resp.status_code == 400

    def test_create_issuer_and_client_id_already_exists_returns_400(
        self, client, admin_token
    ):
        """Test creating tool if issuer/client_id already exists fails with 400"""
        tool_org = factories.LtiToolOrgFactory()
        tool = tool_org.tool
        endpoint = self._get_list_endpoint(self.org.short_name)
        self.payload["issuer"] = tool.issuer
        self.payload["client_id"] = tool.client_id

        resp = self.request(
            client, "post", endpoint, data=self.payload, token=admin_token
        )

        assert resp.json() == {
            "non_field_errors": ["The fields issuer, client_id must make a unique set."]
        }
        assert resp.status_code == 400

    def test_list_returns_tools_for_specified_org_only_200(self, client, admin_token):
        """Test returns LtiKeys for specified org only"""
        org1 = OrganizationFactory()
        org2 = OrganizationFactory()
        tool1_org1 = factories.LtiToolOrgFactory(org=org1)
        tool2_org1 = factories.LtiToolOrgFactory(org=org1)
        endpoint = self._get_list_endpoint(tool1_org1.org.short_name)

        # These won't be returned
        tool1_org2 = factories.LtiToolOrgFactory(org=org2)
        tool2_org2 = factories.LtiToolOrgFactory(org=org2)
        tool3_org2 = factories.LtiToolOrgFactory(org=org2)

        resp = self.request(client, "get", endpoint, token=admin_token)

        assert resp.status_code == 200, resp.json()
        data = resp.json()
        assert data["count"] == 2
        ids_returned = set([x["id"] for x in data["results"]])
        expected_ids = set([tool1_org1.tool.id, tool2_org1.tool.id])
        assert ids_returned == expected_ids

    def test_list_org_dne_returns_empty_list_with_200(self, client, admin_token):
        """If org dne, empty list is returned with 200"""
        endpoint = self._get_list_endpoint("dne")

        resp = self.request(client, "get", endpoint, token=admin_token)

        data = resp.json()
        assert data["count"] == 0
        assert data["results"] == []
        assert resp.status_code == 200

    def test_delete_returns_204(self, client, admin_token):
        """Delete removes LtiTool and LtiToolOrg for specified enttiy, returns 204"""
        tool_org = factories.LtiToolOrgFactory(org=self.org)
        endpoint = self._get_detail_endpoint(self.org.short_name, tool_org.tool.pk)

        resp = self.request(client, "delete", endpoint, token=admin_token)

        assert resp.status_code == 204
        assert LtiToolOrg.objects.count() == 0
        assert LtiTool.objects.count() == 0

    def test_delete_tool_not_in_target_org_returns_404(self, client, admin_token):
        """If target tool not in specified org, returns a 400"""
        # This tool is part of a different org
        tool_org = factories.LtiToolOrgFactory()
        endpoint = self._get_detail_endpoint(self.org.short_name, tool_org.tool.pk)

        resp = self.request(client, "delete", endpoint, token=admin_token)

        assert resp.json() == {"detail": "Not found."}
        assert resp.status_code == 404

    def test_detail_returns_200(self, client, admin_token):
        """Detail endpoint returns entity"""
        org = OrganizationFactory()
        tool_org = factories.LtiToolOrgFactory(org=org)
        tool = tool_org.tool
        org = tool_org.org
        endpoint = self._get_detail_endpoint(org.short_name, tool.pk)

        resp = self.request(client, "get", endpoint, token=admin_token)

        assert resp.status_code == 200, resp.json()
        assert resp.json()["id"] == tool.id

    def test_update_returns_200(self, client, admin_token):
        """Update updates entity and returns 200"""
        key_org = factories.LtiToolOrgFactory(org=self.org, tool__tool_key=self.key)
        new_key = factories.LtiKeyOrgFactory(org=self.org)
        tool = key_org.tool
        existing_gate = factories.LaunchGateFactory(tool=tool)
        endpoint = self._get_detail_endpoint(self.org.short_name, tool.pk)
        self.payload["tool_key"] = new_key.key.id
        self.payload["launch_gate"]["allow_all_within_org"] = True

        resp = self.request(
            client, "put", endpoint, data=self.payload, token=admin_token
        )

        expected = copy.deepcopy(self.payload)
        expected["id"] = tool.id
        expected["deployment_ids"] = [str(x) for x in self.payload["deployment_ids"]]

        assert resp.status_code == 200, resp.json()
        assert resp.json() == expected
        existing_gate.refresh_from_db()
        assert existing_gate.allowed_keys == self.payload["launch_gate"]["allowed_keys"]
        assert (
            existing_gate.allowed_courses
            == self.payload["launch_gate"]["allowed_courses"]
        )
        assert existing_gate.allowed_orgs == [self.org.short_name]

    def test_update_with_tool_key_from_other_org_returns_400(self, client, admin_token):
        """Update updates entity and returns 200"""
        new_org = OrganizationFactory()
        tool_org = factories.LtiToolOrgFactory(org=self.org, tool__tool_key=self.key)
        new_key = factories.LtiKeyOrgFactory(org=new_org)
        org = tool_org.org
        tool = tool_org.tool
        endpoint = self._get_detail_endpoint(self.org.short_name, tool.pk)
        self.payload["tool_key"] = new_key.key.id

        resp = self.request(
            client, "put", endpoint, data=self.payload, token=admin_token
        )

        assert resp.status_code == 400, resp.json()
        assert resp.json() == {
            "tool_key": [f'Invalid pk "{new_key.key.id}" - object does not exist.'],
        }
