import uuid
from django.db import models


class TenantSubscription(models.Model):
    tenant_id = models.UUIDField(primary_key=True)
    billing_owner_user_id = models.UUIDField()
    status = models.CharField(max_length=64, default='unknown')
    stripe_customer_id = models.CharField(max_length=255, null=True, blank=True)
    stripe_subscription_id = models.CharField(max_length=255, null=True, blank=True)
    stripe_price_id = models.CharField(max_length=255, null=True, blank=True)
    stripe_livemode = models.BooleanField(default=False)
    trial_started_at = models.DateTimeField(null=True, blank=True)
    trial_ends_at = models.DateTimeField(null=True, blank=True)
    entitlement_ends_at = models.DateTimeField(null=True, blank=True)
    cancel_at_period_end = models.BooleanField(default=False)
    trial_consumed_at = models.DateTimeField(null=True, blank=True)
    checkout_attempt_number = models.IntegerField(default=0)
    stripe_checkout_session_id = models.CharField(max_length=255, null=True, blank=True)
    checkout_expires_at = models.DateTimeField(null=True, blank=True)
    archived_stripe_subscription_id = models.CharField(max_length=255, null=True, blank=True)


class StripeWebhookEvent(models.Model):
    stripe_event_id = models.CharField(max_length=255, unique=True)
    event_type = models.CharField(max_length=255)
    stripe_object_id = models.CharField(max_length=255, null=True, blank=True)
    livemode = models.BooleanField(default=False)
    api_version = models.CharField(max_length=64, null=True, blank=True)
    outcome = models.CharField(max_length=64, default='ignored')
    reason = models.CharField(max_length=255, default='processing')
    tenant_id = models.UUIDField(null=True, blank=True)
    previous_status = models.CharField(max_length=64, null=True, blank=True)
    resulting_status = models.CharField(max_length=64, null=True, blank=True)
    stripe_created_at = models.DateTimeField(null=True, blank=True)
