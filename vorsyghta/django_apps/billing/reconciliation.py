"""Django port of Stripe webhook reconciliation logic.

Mirrors vorsyghta/api/routers/billing.py reconciliation path.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from django.db import transaction
from django.utils import timezone as dj_tz

from .models import TenantSubscription, StripeWebhookEvent


class BillingStatus:
    CHECKOUT_PENDING = "checkout_pending"
    TRIALING = "trialing"
    ACTIVE = "active"
    INCOMPLETE = "incomplete"
    INCOMPLETE_EXPIRED = "incomplete_expired"
    PAST_DUE = "past_due"
    UNPAID = "unpaid"
    PAUSED = "paused"
    CANCELED = "canceled"
    UNKNOWN = "unknown"


_SUBSCRIPTION_EVENTS = {
    "customer.subscription.created",
    "customer.subscription.updated",
    "customer.subscription.deleted",
    "customer.subscription.trial_will_end",
}
_INVOICE_EVENTS = {
    "invoice.paid",
    "invoice.payment_succeeded",
    "invoice.payment_failed",
    "invoice.payment_action_required",
    "invoice.finalization_failed",
}
_CHECKOUT_EVENTS = {"checkout.session.completed", "checkout.session.expired"}
_SUPPORTED_EVENTS = _SUBSCRIPTION_EVENTS | _INVOICE_EVENTS | _CHECKOUT_EVENTS
_RESUBSCRIPTION_TERMINAL_STATUSES = {
    BillingStatus.CANCELED,
    BillingStatus.INCOMPLETE_EXPIRED,
}


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _event_text(value: dict[str, Any], key: str) -> str:
    text = value.get(key)
    if not isinstance(text, str) or not text.strip():
        raise ValueError(f"Stripe {key} is missing")
    return text.strip()


def _optional_text(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _resource_id(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, dict):
        return _optional_text(value.get("id"))
    return None


def _optional_mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _required_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"Invalid {label}")
    return value


def _event_object(event: dict[str, Any]) -> dict[str, Any]:
    data = _required_mapping(event.get("data"), "event data")
    return _required_mapping(data.get("object"), "event object")


def _event_timestamp(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        raise ValueError("Stripe event timestamp is invalid")
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc)
    except Exception:
        raise ValueError("Stripe event timestamp is invalid")


def _new_event_receipt(event: dict[str, Any], event_id: str, event_type: str, event_object: dict[str, Any]) -> StripeWebhookEvent:
    livemode = event.get("livemode")
    if not isinstance(livemode, bool):
        raise ValueError("Stripe event mode is invalid")
    return StripeWebhookEvent(
        stripe_event_id=event_id,
        event_type=event_type,
        stripe_object_id=_resource_id(event_object.get("id")),
        livemode=livemode,
        api_version=_optional_text(event.get("api_version")),
        outcome="ignored",
        reason="processing",
        stripe_created_at=_event_timestamp(event.get("created")),
    )


class _Reconciliation:
    __slots__ = ("tenant_id", "previous_status", "resulting_status", "outcome", "reason")

    def __init__(self, tenant_id, previous_status, resulting_status, outcome, reason):
        self.tenant_id = tenant_id
        self.previous_status = previous_status
        self.resulting_status = resulting_status
        self.outcome = outcome
        self.reason = reason


def subscription_is_entitled(billing_status: str, entitlement_ends_at: datetime | None, *, tenant_is_active: bool = True, now: datetime | None = None) -> bool:
    if billing_status not in {BillingStatus.TRIALING, BillingStatus.ACTIVE}:
        return False
    if not tenant_is_active:
        return False
    if entitlement_ends_at is None:
        return False
    boundary = _as_utc(entitlement_ends_at)
    current_time = _as_utc(now or datetime.now(timezone.utc))
    return current_time < boundary


def _subscription_id_for_event(event_type: str, event_object: dict[str, Any]) -> str | None:
    if event_type in _SUBSCRIPTION_EVENTS:
        return _event_text(event_object, "id")
    direct = _resource_id(event_object.get("subscription"))
    if direct:
        return direct
    parent = _optional_mapping(event_object.get("parent"))
    details = _optional_mapping(parent.get("subscription_details"))
    return _resource_id(details.get("subscription"))


def _checkout_event_identity(event_object: dict[str, Any]) -> tuple[str, str]:
    if event_object.get("mode") != "subscription":
        raise ValueError("Checkout mode validation failed")
    metadata = _required_mapping(event_object.get("metadata"), "checkout metadata")
    tenant_id = _event_text(metadata, "tenant_id")
    owner_id = _event_text(metadata, "billing_owner_user_id")
    if event_object.get("client_reference_id") != tenant_id:
        raise ValueError("Checkout tenant validation failed")
    return tenant_id, owner_id


def _superseded_subscription_reconciliation(record: TenantSubscription, subscription_id: str) -> _Reconciliation | None:
    if subscription_id == record.archived_stripe_subscription_id:
        return _Reconciliation(
            str(record.tenant_id),
            record.status,
            record.status,
            "ignored",
            "superseded_subscription",
        )
    if record.archived_stripe_subscription_id and record.stripe_subscription_id is None:
        return _Reconciliation(
            str(record.tenant_id),
            record.status,
            record.status,
            "ignored",
            "replacement_checkout_required",
        )
    return None


def _reject_bound_subscription(record: TenantSubscription) -> _Reconciliation:
    previous_status = record.status
    record.status = BillingStatus.UNKNOWN
    record.entitlement_ends_at = None
    record.cancel_at_period_end = False
    record.save(update_fields=["status", "entitlement_ends_at", "cancel_at_period_end"])
    return _Reconciliation(
        str(record.tenant_id),
        previous_status,
        record.status,
        "rejected",
        "subscription_validation_failed",
    )


def _validate_record_binding(record: TenantSubscription, snapshot: dict[str, Any], checkout: dict[str, Any] | None) -> None:
    if record.billing_owner_user_id != uuid.UUID(snapshot["billing_owner_user_id"]):
        raise ValueError("Billing owner validation failed")
    if record.stripe_price_id != snapshot["price_id"] or record.stripe_livemode != snapshot["livemode"]:
        raise ValueError("Subscription binding validation failed")
    if record.stripe_customer_id and record.stripe_customer_id != snapshot["customer_id"]:
        raise ValueError("Stripe customer validation failed")
    if record.stripe_subscription_id and record.stripe_subscription_id != snapshot["subscription_id"]:
        replacement_allowed = (
            record.status == BillingStatus.CHECKOUT_PENDING and record.stripe_checkout_session_id is not None
        )
        if not replacement_allowed:
            raise ValueError("Stripe subscription validation failed")
    if checkout is not None and record.stripe_checkout_session_id != checkout.get("session_id"):
        raise ValueError("Stripe Checkout session validation failed")


def _validate_consumed_trial(record: TenantSubscription, snapshot: dict[str, Any]) -> None:
    consumed = record.trial_consumed_at
    started = snapshot.get("trial_started_at")
    if consumed is not None and started is not None:
        if _as_utc(consumed) != _as_utc(started):
            raise ValueError("A different trial was already consumed")


def _validate_checkout_subscription(checkout: dict[str, Any], snapshot: dict[str, Any]) -> None:
    if checkout["tenant_id"] != snapshot["tenant_id"]:
        raise ValueError("Checkout tenant validation failed")
    if checkout["billing_owner_user_id"] != snapshot["billing_owner_user_id"]:
        raise ValueError("Checkout owner validation failed")
    if checkout["customer_id"] != snapshot["customer_id"]:
        raise ValueError("Checkout customer validation failed")
    if checkout["subscription_id"] != snapshot["subscription_id"]:
        raise ValueError("Checkout subscription validation failed")
    if checkout["price_id"] != snapshot["price_id"] or checkout["livemode"] != snapshot["livemode"]:
        raise ValueError("Checkout subscription mode validation failed")


def _validate_event_resource(event_type: str, event_object: dict[str, Any], snapshot: dict[str, Any]) -> None:
    if event_type in _SUBSCRIPTION_EVENTS:
        if _event_text(event_object, "id") != snapshot["subscription_id"]:
            raise ValueError("Subscription event validation failed")
        customer_id = _resource_id(event_object.get("customer"))
        metadata = _optional_mapping(event_object.get("metadata"))
        if customer_id and customer_id != snapshot["customer_id"]:
            raise ValueError("Subscription customer validation failed")
        if metadata and metadata.get("tenant_id") != snapshot["tenant_id"]:
            raise ValueError("Subscription tenant validation failed")
        if metadata and metadata.get("billing_owner_user_id") != snapshot["billing_owner_user_id"]:
            raise ValueError("Subscription owner validation failed")
        return
    invoice_customer = _resource_id(event_object.get("customer"))
    if invoice_customer and invoice_customer != snapshot["customer_id"]:
        raise ValueError("Invoice customer validation failed")


def _apply_subscription_snapshot(record: TenantSubscription, snapshot: dict[str, Any], *, checkout: dict[str, Any] | None = None) -> _Reconciliation:
    previous_status = record.status
    _validate_consumed_trial(record, snapshot)
    record.status = snapshot["status"]
    record.stripe_customer_id = snapshot["customer_id"]
    record.stripe_subscription_id = snapshot["subscription_id"]
    record.stripe_price_id = snapshot["price_id"]
    record.stripe_livemode = snapshot["livemode"]
    record.trial_started_at = snapshot.get("trial_started_at")
    record.trial_ends_at = snapshot.get("trial_ends_at")
    record.entitlement_ends_at = snapshot.get("entitlement_ends_at")
    record.cancel_at_period_end = snapshot.get("cancel_at_period_end", False)
    if record.trial_consumed_at is None and snapshot.get("trial_started_at") is not None:
        record.trial_consumed_at = snapshot.get("trial_started_at")
    if checkout is not None:
        record.stripe_checkout_session_id = checkout.get("session_id")
        record.checkout_expires_at = checkout.get("expires_at")
    record.save()
    return _Reconciliation(
        str(record.tenant_id),
        previous_status,
        record.status,
        "processed",
        "subscription_synchronized",
    )


def _expire_pending_checkout(record: TenantSubscription, checkout: dict[str, Any]) -> _Reconciliation:
    if str(record.tenant_id) != checkout["tenant_id"]:
        raise ValueError("Locked tenant billing record does not match Checkout")
    if str(record.billing_owner_user_id) != checkout["billing_owner_user_id"]:
        raise ValueError("Billing owner validation failed")
    if record.stripe_price_id != checkout["price_id"] or record.stripe_livemode != checkout["livemode"]:
        raise ValueError("Checkout binding validation failed")
    if record.stripe_customer_id and record.stripe_customer_id != checkout["customer_id"]:
        raise ValueError("Stripe customer validation failed")
    previous_status = record.status
    if record.stripe_checkout_session_id != checkout.get("session_id"):
        return _Reconciliation(
            str(record.tenant_id),
            previous_status,
            previous_status,
            "ignored",
            "superseded_checkout",
        )
    if previous_status != BillingStatus.CHECKOUT_PENDING:
        return _Reconciliation(
            str(record.tenant_id),
            previous_status,
            previous_status,
            "ignored",
            "checkout_already_reconciled",
        )
    record.status = BillingStatus.INCOMPLETE_EXPIRED
    record.stripe_checkout_session_id = None
    record.checkout_expires_at = None
    record.save(update_fields=["status", "stripe_checkout_session_id", "checkout_expires_at"])
    return _Reconciliation(
        str(record.tenant_id),
        previous_status,
        record.status,
        "processed",
        "checkout_expired",
    )


def _lock_subscription_for_event(event_type: str, event_object: dict[str, Any], subscription_id: str) -> TenantSubscription | None:
    if event_type in _SUBSCRIPTION_EVENTS:
        metadata = _required_mapping(event_object.get("metadata"), "subscription metadata")
        tenant_id = _event_text(metadata, "tenant_id")
        try:
            tenant_uuid = uuid.UUID(tenant_id)
        except Exception:
            raise ValueError("Invalid tenant_id")
        try:
            return TenantSubscription.objects.select_for_update().get(tenant_id=tenant_uuid)
        except TenantSubscription.DoesNotExist:
            raise ValueError("No tenant billing record exists")
    try:
        record = TenantSubscription.objects.select_for_update().get(stripe_subscription_id=subscription_id)
        if record.stripe_subscription_id != subscription_id:
            return None
        return record
    except TenantSubscription.DoesNotExist:
        return None


def _reconcile_checkout_event(service, event_type: str, event_object: dict[str, Any]) -> _Reconciliation:
    tenant_id_str, owner_id_str = _checkout_event_identity(event_object)
    tenant_uuid = uuid.UUID(tenant_id_str)
    try:
        record = TenantSubscription.objects.select_for_update().get(tenant_id=tenant_uuid)
    except TenantSubscription.DoesNotExist:
        raise ValueError("No pending tenant billing record exists")
    checkout = service.retrieve_checkout_session(
        _event_text(event_object, "id"),
        tenant_id=str(tenant_uuid),
        billing_owner_user_id=owner_id_str,
    )
    if event_type == "checkout.session.expired":
        if checkout.get("status") != "expired":
            return _Reconciliation(tenant_id_str, None, None, "ignored", "stale_checkout_event")
        return _expire_pending_checkout(record, checkout)
    if checkout.get("status") != "complete" or not checkout.get("customer_id") or not checkout.get("subscription_id"):
        raise ValueError("Completed Checkout state is invalid")
    snapshot = service.retrieve_subscription(
        checkout["subscription_id"],
        allow_no_trial=record.trial_consumed_at is not None,
    )
    _validate_checkout_subscription(checkout, snapshot)
    _validate_record_binding(record, snapshot, checkout)
    # Unique binding check
    others = TenantSubscription.objects.filter(
        stripe_subscription_id=snapshot["subscription_id"],
    ).exclude(tenant_id=record.tenant_id)
    if others.exists():
        raise ValueError("Stripe resource belongs to another tenant")
    return _apply_subscription_snapshot(record, snapshot, checkout=checkout)


def _reconcile_current_subscription(service, event_type: str, event_object: dict[str, Any], subscription_id: str, record: TenantSubscription) -> _Reconciliation:
    snapshot = service.retrieve_subscription(
        subscription_id,
        allow_no_trial=record.trial_consumed_at is not None,
    )
    if snapshot["subscription_id"] != subscription_id:
        raise ValueError("Subscription identifier validation failed")
    _validate_event_resource(event_type, event_object, snapshot)
    _validate_record_binding(record, snapshot, None)
    # Unique binding
    if TenantSubscription.objects.filter(
        stripe_customer_id=snapshot["customer_id"]
    ).exclude(tenant_id=record.tenant_id).exists():
        raise ValueError("Stripe resource belongs to another tenant")
    if TenantSubscription.objects.filter(
        stripe_subscription_id=snapshot["subscription_id"]
    ).exclude(tenant_id=record.tenant_id).exists():
        raise ValueError("Stripe resource belongs to another tenant")
    return _apply_subscription_snapshot(record, snapshot)


def reconcile_event(service, event: dict[str, Any]) -> tuple[dict[str, Any], _Reconciliation]:
    event_id = _event_text(event, "id")
    event_type = _event_text(event, "type")
    event_object = _event_object(event)

    # Idempotency check
    try:
        receipt_qs = StripeWebhookEvent.objects.filter(stripe_event_id=event_id)
        if receipt_qs.exists():
            receipt = receipt_qs.first()
            return {"duplicate": True, "outcome": "duplicate"}, _Reconciliation(None, None, None, "duplicate", "duplicate")
    except Exception:
        pass

    receipt = _new_event_receipt(event, event_id, event_type, event_object)
    receipt.save()

    if event_type not in _SUPPORTED_EVENTS:
        recon = _Reconciliation(None, None, None, "ignored", "unsupported_event")
        receipt.outcome = recon.outcome
        receipt.reason = recon.reason
        receipt.save(update_fields=["outcome", "reason"])
        return {"duplicate": False, "outcome": "ignored"}, recon

    if event_type in _CHECKOUT_EVENTS:
        recon = _reconcile_checkout_event(service, event_type, event_object)
    else:
        subscription_id = _subscription_id_for_event(event_type, event_object)
        if subscription_id is None:
            recon = _Reconciliation(None, None, None, "ignored", "invoice_without_subscription")
        else:
            record = _lock_subscription_for_event(event_type, event_object, subscription_id)
            if record is None:
                recon = _Reconciliation(None, None, None, "ignored", "unbound_invoice")
            else:
                ignored = _superseded_subscription_reconciliation(record, subscription_id)
                if ignored is not None:
                    recon = ignored
                else:
                    recon = _reconcile_current_subscription(service, event_type, event_object, subscription_id, record)

    # Apply reconciliation to receipt
    receipt.tenant_id = uuid.UUID(recon.tenant_id) if recon.tenant_id else None
    receipt.previous_status = recon.previous_status
    receipt.resulting_status = recon.resulting_status
    receipt.outcome = recon.outcome
    receipt.reason = recon.reason
    receipt.save(update_fields=["tenant_id", "previous_status", "resulting_status", "outcome", "reason"])
    return {"duplicate": False, "outcome": recon.outcome}, recon
