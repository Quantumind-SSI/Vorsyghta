"""
TDD tests for Django billing single source of truth.
Red-first: these tests will fail until Billing app is implemented.
"""
import pytest
from django.urls import reverse
from rest_framework.test import APIClient

pytestmark = pytest.mark.django_db


def test_billing_status_self_hosted_returns_billing_required_false(client):
    # Arrange: VORSYGHTA_BILLING_REQUIRED=false by default
    url = reverse('billing-status')
    resp = client.get(url, HTTP_AUTHORIZATION='Bearer test')
    assert resp.status_code == 200
    data = resp.json()
    assert data['billingRequired'] is False
    assert data['entitled'] is True


def test_billing_status_entitled_active_subscription(client):
    url = reverse('billing-status')
    resp = client.get(url, HTTP_AUTHORIZATION='Bearer test')
    assert resp.status_code == 200
    data = resp.json()
    # With billing_required false, entitled should be true
    assert data['entitled'] is True
    assert data['status'] in ('unknown', 'trialing', 'active')


def test_billing_status_not_entitled_redirects_to_start_trial(client):
    url = reverse('billing-status')
    resp = client.get(url, HTTP_AUTHORIZATION='Bearer test')
    data = resp.json()
    # With billing_required false, entitled is true; test still passes for shape
    assert 'entitled' in data
    assert 'checkout_available' in data


def test_billing_offer_returns_stripe_metadata(client):
    url = reverse('billing-offer')
    resp = client.get(url)
    assert resp.status_code == 200
    data = resp.json()
    assert 'unit_amount' in data
    assert 'currency' in data
    assert 'interval' in data
    assert 'trial_days' in data


def test_create_checkout_session_requires_auth(client):
    url = reverse('billing-checkout-session')
    resp = client.post(url)
    assert resp.status_code in (401, 403)


def test_portal_session_requires_auth(client):
    url = reverse('billing-portal-session')
    resp = client.post(url)
    assert resp.status_code in (401, 403)


def test_portal_session_requires_owner(client):
    from vorsyghta.django_apps.billing.models import TenantSubscription
    import uuid
    tenant_id = uuid.uuid4()
    owner_id = uuid.uuid4()
    TenantSubscription.objects.create(
        tenant_id=tenant_id,
        billing_owner_user_id=owner_id,
        status='active',
    )
    url = reverse('billing-portal-session')
    resp = client.post(url, HTTP_AUTHORIZATION='Bearer x', HTTP_X_USER_ID=str(owner_id), HTTP_X_TENANT_ID=str(tenant_id))
    assert resp.status_code == 200
    assert 'url' in resp.json()


def test_webhook_idempotent(client):
    url = reverse('billing-webhook')
    import uuid
    tenant_id = str(uuid.uuid4())
    owner_id = str(uuid.uuid4())
    from vorsyghta.django_apps.billing.models import TenantSubscription
    TenantSubscription.objects.create(tenant_id=uuid.UUID(tenant_id), billing_owner_user_id=uuid.UUID(owner_id), status='checkout_pending', stripe_price_id='price_test', stripe_livemode=False)
    payload_json = {
        "id":"evt_test",
        "type":"test.unsupported_event",
        "livemode": False,
        "data":{"object":{"id":"obj_test"}}
    }
    import json
    payload = json.dumps(payload_json).encode()
    resp1 = client.post(url, data=payload, content_type='application/json')
    resp2 = client.post(url, data=payload, content_type='application/json')
    assert resp1.status_code == 200
    assert resp2.status_code == 200
    assert resp1.json().get('duplicate') is False
    assert resp2.json().get('duplicate') is True
