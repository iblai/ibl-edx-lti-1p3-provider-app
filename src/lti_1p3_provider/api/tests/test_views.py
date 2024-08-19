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
        assert resp.status_code == 201
        data = resp.json()
        assert data.keys() == {"name", "public_jwk", "public_key"}

    def test_create_name_already_exists_in_org_returns_400(self, client):
        """Test creating a tool name that already exists in org returns 400"""
        org1 = OrganizationFactory()
        factories.LtiToolKeyFactory(name=f"{org1.short_name}-test")
        payload = {"name": "test"}
        endpoint = self._get_list_endpoint(org1.short_name)

        resp = client.post(endpoint, data=payload)

        assert resp.json() == ["Tool name: 'test' already exists"]
        assert resp.status_code == 400

    def test_list_returns_keys_for_specified_orgs_only(self):
        pass

    def test_delete(self):
        pass
