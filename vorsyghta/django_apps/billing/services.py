"""Stripe billing service stub for Django billing app."""
import os
import json
from datetime import datetime, timezone, timedelta

def billing_required_from_env():
    val = os.getenv('VORSYGHTA_BILLING_REQUIRED', 'false').lower()
    return val in ('1', 'true', 'yes', 'on')

class StripeBillingService:
    """Minimal stub; real implementation would call Stripe SDK."""
    def __init__(self):
        self.billing_required = billing_required_from_env()
        self.settings_price_id = os.getenv('STRIPE_PRICE_ID', 'price_test_team_monthly')
        self.expected_livemode = os.getenv('STRIPE_LIVEMODE', 'false').lower() in ('1', 'true', 'yes')

    def get_hosted_checkout_session(self, tenant_id, user_id):
        # Stub returns deterministic URL
        return {'url': 'https://checkout.stripe.com/test', 'expires_at': None}

    def get_customer_portal_session(self, tenant_id, user_id):
        return {'url': 'https://billing.stripe.com/portal/test', 'expires_at': None}

    def get_offer(self):
        return {
            'name': 'Team',
            'description': 'Team plan',
            'unit_amount': 4900,
            'currency': 'usd',
            'interval': 'month',
            'interval_count': 1,
            'trial_days': 14,
        }

    def verify_webhook_signature(self, payload, sig_header):
        # Stub: accept all signatures for now
        return True

    def verify_webhook(self, payload: bytes, sig_header: str | None) -> dict:
        # Stub verification: parse JSON and return event dict
        try:
            return json.loads(payload.decode('utf-8'))
        except Exception:
            return {}

    def create_checkout_session(self, tenant_id, billing_owner_user_id, billing_owner_email, stripe_customer_id, checkout_attempt_number, include_trial):
        session_id = f"cs_test_{tenant_id}_{billing_owner_user_id}"
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(hours=24)
        customer_id = stripe_customer_id or f"cus_test_{tenant_id}"
        subscription_id = f"sub_test_{tenant_id}"
        return {
            'session_id': session_id,
            'url': f'https://checkout.stripe.com/pay/{session_id}',
            'expires_at': expires_at,
            'customer_id': customer_id,
            'subscription_id': subscription_id,
            'price_id': self.settings_price_id,
            'livemode': self.expected_livemode,
            'tenant_id': str(tenant_id),
            'billing_owner_user_id': str(billing_owner_user_id),
        }

    def retrieve_checkout_session(self, session_id, tenant_id, billing_owner_user_id):
        # Deterministic stub: assume session exists and is complete
        now = datetime.now(timezone.utc)
        return {
            'session_id': session_id,
            'status': 'complete',
            'url': f'https://checkout.stripe.com/pay/{session_id}',
            'expires_at': now + timedelta(hours=1),
            'customer_id': f'cus_test_{tenant_id}',
            'subscription_id': f'sub_test_{tenant_id}',
            'price_id': self.settings_price_id,
            'livemode': self.expected_livemode,
            'tenant_id': str(tenant_id),
            'billing_owner_user_id': str(billing_owner_user_id),
        }

    def create_portal_session(self, customer_id):
        return {
            'url': f'https://billing.stripe.com/portal/{customer_id}',
            'expires_at': None,
        }

    def retrieve_subscription(self, subscription_id, allow_no_trial=False):
        now = datetime.now(timezone.utc)
        trial_started = now - timedelta(days=1)
        trial_ends = now + timedelta(days=13)
        entitlement_ends = now + timedelta(days=30)
        return {
            'subscription_id': subscription_id,
            'customer_id': f'cus_test_{subscription_id}',
            'status': 'active',
            'price_id': self.settings_price_id,
            'livemode': self.expected_livemode,
            'trial_started_at': trial_started,
            'trial_ends_at': trial_ends,
            'entitlement_ends_at': entitlement_ends,
            'cancel_at_period_end': False,
            'tenant_id': '00000000-0000-0000-0000-000000000000',
            'billing_owner_user_id': '00000000-0000-0000-0000-000000000001',
        }

