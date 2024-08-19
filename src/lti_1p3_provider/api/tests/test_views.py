from __future__ import annotations

import pytest
from django.urls import reverse
from lti_1p3_provider.api import serializers
from lti_1p3_provider.models import LtiKeyOrg
from lti_1p3_provider.tests import factories
from organizations.tests.factories import OrganizationFactory
from pylti1p3.contrib.django.lti1p3_tool_config.models import LtiTool, LtiToolKey


@pytest.fixture(autouse=True)
def enable_lti_1p3(settings):
    settings.FEATURES["ENABLE_LTI_1P3_PROVIDER"] = True


@pytest.mark.django_db
class TestLtiKeyViews:
    def _get_list_endpoint(self, org_short_name) -> str:
        return reverse(
            "lti_1p3_provider:lti-keys-list", kwargs={"org_short_name": org_short_name}
        )

    def _get_detail_endpoint(self, org_short_name, pk) -> str:
        return reverse(
            "lti_1p3_provider:lti-keys-detail",
            kwargs={"org_short_name": org_short_name, "pk": pk},
        )

    def test_create_returns_201(self, client):
        """Test creating a key for an org returns a 201"""
        org1 = OrganizationFactory()
        payload = {"name": "test"}
        endpoint = self._get_list_endpoint(org1.short_name)

        resp = client.post(endpoint, data=payload)

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
            "name": key.name,
            "id": key.id,
        }

    def test_create_org_dne_returns_400(self, client):
        """Test creating key for org that DNE returns 400"""
        payload = {"name": "test"}
        endpoint = self._get_list_endpoint("dne")

        resp = client.post(endpoint, data=payload)

        assert resp.json() == {"non_field_errors": ["Org: 'dne' Does Not Exist"]}
        assert resp.status_code == 400

    def test_create_name_already_exists_in_org_returns_400(self, client):
        """Test creating a tool name that already exists in org returns 400"""
        org1 = OrganizationFactory()
        factories.LtiToolKeyFactory(name=f"{org1.short_name}-test")
        payload = {"name": "test"}
        endpoint = self._get_list_endpoint(org1.short_name)

        resp = client.post(endpoint, data=payload)

        assert resp.json() == ["Tool name: 'test' already exists"]
        assert resp.status_code == 400

    def test_list_returns_keys_for_specified_org_only(self, client):
        """Test returns LtiKeys for specified org only"""
        key1_org1 = factories.LtiKeyOrgFactory()
        key2_org1 = factories.LtiKeyOrgFactory(org=key1_org1.org)
        endpoint = self._get_list_endpoint(key1_org1.org.short_name)

        # These won't be returned
        key1_org2 = factories.LtiKeyOrgFactory()
        key2_org2 = factories.LtiKeyOrgFactory(org=key1_org2.org)

        resp = client.get(endpoint)

        data = resp.json()["results"]
        key1 = key1_org1.key
        key2 = key2_org1.key
        assert data == [
            {
                "name": key1.name,
                "public_key": key1.public_key,
                "public_jwk": key1.public_jwk,
                "id": key1.id,
            },
            {
                "name": key2.name,
                "public_key": key2.public_key,
                "public_jwk": key2.public_jwk,
                "id": key2.id,
            },
        ]
        assert resp.status_code == 200

    def test_list_org_dne_returns_empty_list_with_200(self, client):
        """If org dne, empty list is returned with 200"""
        endpoint = self._get_list_endpoint("dne")

        resp = client.get(endpoint)

        data = resp.json()
        assert data["count"] == 0
        assert data["results"] == []
        assert resp.status_code == 200

    def test_delete_returns_204(self, client):
        """Delete removes LtiToolKey and LtiKeyOrg for specified enttiy, returns 204"""
        key_org = factories.LtiKeyOrgFactory()
        org = key_org.org
        key = key_org.key
        endpoint = self._get_detail_endpoint(org.short_name, key.pk)

        resp = client.delete(endpoint)

        assert resp.status_code == 204

        assert LtiKeyOrg.objects.count() == 0
        assert LtiToolKey.objects.count() == 0

    def test_detail_endpoint_returns_200(self, client):
        """Detail endpoint returns entity"""
        key_org = factories.LtiKeyOrgFactory()
        org = key_org.org
        key = key_org.key
        endpoint = self._get_detail_endpoint(org.short_name, key.pk)

        resp = client.get(endpoint)

        assert resp.json() == {
            "name": key.name,
            "public_key": key.public_key,
            "public_jwk": key.public_jwk,
            "id": key.id,
        }
        assert resp.status_code == 200
