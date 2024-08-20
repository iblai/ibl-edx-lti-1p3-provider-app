from __future__ import annotations

from typing import Any

import pytest
from common.djangoapps.student.tests.factories import UserFactory
from django.urls import reverse
from lti_1p3_provider.models import LtiKeyOrg
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

        assert resp.json() == ["Tool name: 'test' already exists"]
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
            "use_by_default": False,
            "auth_login_url": "https://issuer.local/auth",
            "auth_token_url": "https://issuer.local/token",
            "auth_audience": "",
            "key_set_url": "https://issuer.local/keyset",
            "key_set": "",
            "tool_key": self.key.id,
            "deployment_ids": [1, "test", 1234, "5"],
        }

    def test_create_returns_201(self, client, admin_token):
        """Test creating a tool for an org returns a 201"""
        payload = {
            "title": "test",
            "is_active": True,
            "issuer": "https://issuer.local",
            "client_id": "12345",
            "use_by_default": False,
            "auth_login_url": "https://issuer.local/auth",
            "auth_token_url": "https://issuer.local/token",
            "auth_audience": "",
            "key_set_url": "https://issuer.local/keyset",
            "key_set": "",
            "tool_key": self.key.id,
            "deployment_ids": [1, "test", 1234, "5"],
        }
        endpoint = self._get_list_endpoint(self.org.short_name)

        resp = self.request(client, "post", endpoint, data=payload, token=admin_token)

        tool = LtiTool.objects.get(client_id="12345")
        expected = payload.copy()
        expected["id"] = tool.id
        expected["deployment_ids"] = [str(x) for x in payload["deployment_ids"]]
        assert resp.json() == expected
        assert tool.tool_org.org == self.org

    @pytest.mark.skip
    def test_create_org_dne_returns_400(self, client, admin_token):
        """Test creating key for org that DNE returns 400"""
        endpoint = self._get_list_endpoint("dne")

        resp = self.request(client, "post", endpoint, data=payload, token=admin_token)

        assert resp.json() == {"non_field_errors": ["Org: 'dne' Does Not Exist"]}
        assert resp.status_code == 400

    @pytest.mark.skip
    def test_create_name_already_exists_in_org_returns_400(self, client, admin_token):
        """Test creating a tool name that already exists in org returns 400"""
        org1 = OrganizationFactory()
        factories.LtiToolKeyFactory(name=f"{org1.short_name}-test")
        payload = {"name": "test"}
        endpoint = self._get_list_endpoint(org1.short_name)

        resp = self.request(client, "post", endpoint, data=payload, token=admin_token)

        assert resp.json() == ["Tool name: 'test' already exists"]
        assert resp.status_code == 400

    @pytest.mark.skip
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

    @pytest.mark.skip
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

    @pytest.mark.skip
    def test_list_org_dne_returns_empty_list_with_200(self, client, admin_token):
        """If org dne, empty list is returned with 200"""
        endpoint = self._get_list_endpoint("dne")

        resp = self.request(client, "get", endpoint, token=admin_token)

        data = resp.json()
        assert data["count"] == 0
        assert data["results"] == []
        assert resp.status_code == 200

    @pytest.mark.skip
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

    @pytest.mark.skip
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

    @pytest.mark.skip
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
