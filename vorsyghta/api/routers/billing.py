"""Stripe-hosted billing endpoints and local entitlement reconciliation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from vorsyghta.db.models.auth import TenantRecord, UserRecord
from vorsyghta.db.models.billing import (
    BillingStatus,
    StripeWebhookEventRecord,
    TenantSubscriptionRecord,
)
from vorsyghta.db.session import get_session_dep
from vorsyghta.integrations.stripe_billing import (
    BillingOffer,
    CheckoutSnapshot,
    HostedSession,
    StripeBillingConfigurationError,
    StripeBillingProviderError,
    StripeBillingService,
    StripeBillingValidationError,
    StripeWebhookSignatureError,
    SubscriptionSnapshot,
    billing_required_from_env,
    expected_stripe_livemode_from_env,
    get_stripe_billing_service,
)
from vorsyghta.security.rbac import CurrentUser, get_current_user


router = APIRouter(prefix="/billing", tags=["billing"])
_MAX_WEBHOOK_BODY_BYTES = 256 * 1024
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
    BillingStatus.CANCELED.value,
    BillingStatus.INCOMPLETE_EXPIRED.value,
}

# Lifecycle invariants:
# 1. Mutating paths lock tenant first and subscription second.
# 2. A replacement subscription is bound only by its completed Checkout session.
# 3. Archived terminal subscription events never mutate pending or current state.
# 4. Expired replacement sessions clear only retryable Checkout state and never trial history.


class BillingOfferResponse(BaseModel):
    """Public metadata for the active Team offer."""

    name: str
    description: str | None
    unit_amount: int
    currency: str
    interval: str
    interval_count: int
    trial_days: int


class HostedSessionResponse(BaseModel):
    """A short-lived provider-hosted redirect URL."""

    url: str
    expires_at: datetime | None = None


class BillingStatusResponse(BaseModel):
    """Tenant-safe local billing and entitlement projection."""

    status: BillingStatus
    entitled: bool
    billing_required: bool
    trial_available: bool
    checkout_available: bool
    portal_available: bool
    trial_started_at: datetime | None = None
    trial_ends_at: datetime | None = None
    entitlement_ends_at: datetime | None = None
    cancel_at_period_end: bool = False


class WebhookResponse(BaseModel):
    """Sanitized webhook processing acknowledgement."""

    received: bool = True
    duplicate: bool = False
    outcome: str


@dataclass(frozen=True)
class _Reconciliation:
    tenant_id: str | None
    previous_status: str | None
    resulting_status: str | None
    outcome: str
    reason: str


def get_billing_service_dep() -> StripeBillingService:
    """Resolve Stripe lazily so missing settings never block application startup."""
    try:
        return get_stripe_billing_service()
    except StripeBillingConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Billing is not configured",
        ) from exc


def subscription_is_entitled(
    billing_status: BillingStatus | str,
    entitlement_ends_at: datetime | None,
    *,
    tenant_is_active: bool = True,
    now: datetime | None = None,
) -> bool:
    """Return true only for a live trial or paid period on an active tenant."""
    try:
        normalized_status = BillingStatus(billing_status)
    except ValueError:
        return False
    if not tenant_is_active or normalized_status not in {BillingStatus.TRIALING, BillingStatus.ACTIVE}:
        return False
    if entitlement_ends_at is None:
        return False
    boundary = _as_utc(entitlement_ends_at)
    current_time = _as_utc(now or datetime.now(timezone.utc))
    return current_time < boundary


async def require_entitled_user(
    current_user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session_dep),
) -> CurrentUser:
    """Require an active DB identity and a current matching-mode entitlement."""
    try:
        if not billing_required_from_env():
            return current_user
        expected_livemode = expected_stripe_livemode_from_env()
        identity_result = await session.execute(
            select(UserRecord, TenantRecord)
            .join(TenantRecord, TenantRecord.tenant_id == UserRecord.tenant_id)
            .where(
                UserRecord.user_id == current_user.user_id,
                UserRecord.tenant_id == current_user.tenant_id,
            )
        )
        identity = identity_result.one_or_none()
        record = await _get_subscription(session, current_user.tenant_id)
    except StripeBillingConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Billing policy is not configured",
        ) from exc
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Entitlement storage is temporarily unavailable",
        ) from exc
    if identity is None or not identity[0].is_active or not identity[1].is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is inactive")
    if (
        record is None
        or record.stripe_livemode != expected_livemode
        or not subscription_is_entitled(record.status, record.entitlement_ends_at)
    ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Active subscription required")
    return current_user


@router.get("/offer", response_model=BillingOfferResponse)
async def get_offer(
    billing: StripeBillingService = Depends(get_billing_service_dep),
) -> BillingOfferResponse:
    """Return Stripe-authoritative Team Price metadata without provider IDs."""
    try:
        offer = await billing.get_offer()
    except (StripeBillingProviderError, StripeBillingValidationError) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Billing offer is unavailable",
        ) from exc
    return _offer_response(offer)


@router.post("/checkout-session", response_model=HostedSessionResponse)
async def create_checkout_session(
    current_user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session_dep),
    billing: StripeBillingService = Depends(get_billing_service_dep),
) -> HostedSessionResponse:
    """Create or reuse the current user's server-configured hosted Checkout."""
    try:
        return await _create_checkout_for_user(session, billing, current_user)
    except HTTPException:
        await session.rollback()
        raise
    except StripeBillingProviderError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Billing provider is temporarily unavailable",
        ) from exc
    except StripeBillingValidationError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Checkout state is invalid",
        ) from exc
    except SQLAlchemyError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Billing storage is temporarily unavailable",
        ) from exc


@router.get("/status", response_model=BillingStatusResponse)
async def get_billing_status(
    current_user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session_dep),
) -> BillingStatusResponse:
    """Return the current tenant's local, fail-closed entitlement projection."""
    try:
        billing_required = billing_required_from_env()
        tenant = await _get_tenant(session, current_user.tenant_id)
        record = await _get_subscription(session, current_user.tenant_id)
        expected_livemode = (
            expected_stripe_livemode_from_env()
            if billing_required
            else record.stripe_livemode if record is not None else False
        )
    except StripeBillingConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Billing policy is not configured",
        ) from exc
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Billing storage is temporarily unavailable",
        ) from exc
    if record is None:
        return BillingStatusResponse(
            status=BillingStatus.UNKNOWN,
            entitled=False,
            billing_required=billing_required,
            trial_available=True,
            checkout_available=True,
            portal_available=False,
        )
    record_status = _record_status(record.status)
    checkout_available = (
        record_status in {BillingStatus.CANCELED, BillingStatus.INCOMPLETE_EXPIRED}
        or record.stripe_subscription_id is None
        and record_status in {BillingStatus.CHECKOUT_PENDING, BillingStatus.UNKNOWN}
    )
    return BillingStatusResponse(
        status=record_status,
        entitled=subscription_is_entitled(
            record_status,
            record.entitlement_ends_at,
            tenant_is_active=bool(tenant and tenant.is_active and record.stripe_livemode == expected_livemode),
        ),
        billing_required=billing_required,
        trial_available=record.trial_consumed_at is None,
        checkout_available=checkout_available,
        portal_available=record.stripe_customer_id is not None,
        trial_started_at=record.trial_started_at,
        trial_ends_at=record.trial_ends_at,
        entitlement_ends_at=record.entitlement_ends_at,
        cancel_at_period_end=record.cancel_at_period_end,
    )


@router.post("/portal-session", response_model=HostedSessionResponse)
async def create_portal_session(
    current_user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session_dep),
    billing: StripeBillingService = Depends(get_billing_service_dep),
) -> HostedSessionResponse:
    """Create a Stripe Customer Portal session for the tenant billing owner."""
    try:
        await _require_active_identity(session, current_user)
        _tenant, record = await _lock_tenant_subscription(session, current_user.tenant_id)
        if record is None or not record.stripe_customer_id:
            raise HTTPException(status_code=409, detail="No Stripe customer is available")
        if record.billing_owner_user_id != current_user.user_id:
            raise HTTPException(status_code=403, detail="Billing owner access required")
        customer_id = record.stripe_customer_id
        await session.commit()
        hosted = await billing.create_portal_session(customer_id)
    except HTTPException:
        raise
    except StripeBillingProviderError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Billing provider is temporarily unavailable",
        ) from exc
    except StripeBillingValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Billing customer state is invalid",
        ) from exc
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Billing storage is temporarily unavailable",
        ) from exc
    return _hosted_response(hosted)


@router.post("/webhook", response_model=WebhookResponse)
async def stripe_webhook(
    request: Request,
    session: AsyncSession = Depends(get_session_dep),
    billing: StripeBillingService = Depends(get_billing_service_dep),
) -> WebhookResponse:
    """Verify and atomically reconcile one Stripe snapshot event."""
    payload = await _read_webhook_body(request)
    try:
        event = billing.verify_webhook(payload, request.headers.get("stripe-signature"))
        response = await _process_webhook_event(session, billing, event)
        await session.commit()
        return response
    except StripeWebhookSignatureError as exc:
        await session.rollback()
        raise HTTPException(status_code=400, detail="Invalid Stripe webhook signature") from exc
    except StripeBillingValidationError as exc:
        await session.rollback()
        raise HTTPException(status_code=400, detail="Stripe webhook validation failed") from exc
    except StripeBillingProviderError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Billing provider is temporarily unavailable",
        ) from exc
    except SQLAlchemyError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Billing storage is temporarily unavailable",
        ) from exc


async def _create_checkout_for_user(
    session: AsyncSession,
    billing: StripeBillingService,
    current_user: CurrentUser,
) -> HostedSessionResponse:
    billing_owner_email = await _require_active_identity(session, current_user)
    tenant, record = await _lock_tenant_subscription(session, current_user.tenant_id)
    _require_checkout_owner(tenant, record, current_user)
    reused = await _reuse_pending_checkout(billing, record, current_user)
    if reused is not None:
        return reused
    if record and record.stripe_subscription_id:
        await _require_terminal_subscription(billing, record)
        record.archived_stripe_subscription_id = record.stripe_subscription_id
        record.stripe_subscription_id = None
    attempt = (record.checkout_attempt_number if record else 0) + 1
    include_trial = record is None or record.trial_consumed_at is None
    hosted = await billing.create_checkout_session(
        tenant_id=current_user.tenant_id,
        billing_owner_user_id=current_user.user_id,
        billing_owner_email=billing_owner_email,
        stripe_customer_id=record.stripe_customer_id if record else None,
        checkout_attempt_number=attempt,
        include_trial=include_trial,
    )
    record = _store_pending_checkout(record, billing, current_user, hosted, attempt)
    session.add(record)
    await session.commit()
    return _hosted_response(hosted)


def _require_checkout_owner(
    tenant: TenantRecord | None,
    record: TenantSubscriptionRecord | None,
    current_user: CurrentUser,
) -> None:
    if tenant is None or not tenant.is_active:
        raise HTTPException(status_code=403, detail="Active tenant membership required")
    if record is not None and record.billing_owner_user_id != current_user.user_id:
        raise HTTPException(status_code=403, detail="Billing owner access required")


async def _require_terminal_subscription(
    billing: StripeBillingService,
    record: TenantSubscriptionRecord,
) -> None:
    if record.status not in _RESUBSCRIPTION_TERMINAL_STATUSES | {BillingStatus.CHECKOUT_PENDING.value}:
        raise HTTPException(status_code=409, detail="Manage the existing subscription in the billing portal")
    snapshot = await billing.retrieve_subscription(
        record.stripe_subscription_id or "",
        allow_no_trial=record.trial_consumed_at is not None,
    )
    if (
        snapshot.subscription_id != record.stripe_subscription_id
        or snapshot.customer_id != record.stripe_customer_id
        or snapshot.status.value not in _RESUBSCRIPTION_TERMINAL_STATUSES
    ):
        raise HTTPException(status_code=409, detail="A non-terminal Stripe subscription already exists")


async def _reuse_pending_checkout(
    billing: StripeBillingService,
    record: TenantSubscriptionRecord | None,
    current_user: CurrentUser,
) -> HostedSessionResponse | None:
    if record is None or record.status != BillingStatus.CHECKOUT_PENDING.value:
        return None
    if not record.stripe_checkout_session_id:
        return None
    checkout = await billing.retrieve_checkout_session(
        record.stripe_checkout_session_id,
        tenant_id=current_user.tenant_id,
        billing_owner_user_id=current_user.user_id,
    )
    if checkout.status == "open" and checkout.url:
        return HostedSessionResponse(url=checkout.url, expires_at=checkout.expires_at)
    if checkout.status == "complete":
        raise HTTPException(status_code=409, detail="Checkout is awaiting webhook confirmation")
    if checkout.status == "expired":
        return None
    raise StripeBillingValidationError("Checkout status validation failed")


def _store_pending_checkout(
    record: TenantSubscriptionRecord | None,
    billing: StripeBillingService,
    current_user: CurrentUser,
    hosted: HostedSession,
    attempt: int,
) -> TenantSubscriptionRecord:
    if record is None:
        record = TenantSubscriptionRecord(
            tenant_id=current_user.tenant_id,
            billing_owner_user_id=current_user.user_id,
            stripe_price_id=billing.settings.price_id,
            stripe_livemode=billing.settings.expected_livemode,
        )
    record.status = BillingStatus.CHECKOUT_PENDING.value
    record.billing_owner_user_id = current_user.user_id
    record.stripe_price_id = billing.settings.price_id
    record.stripe_livemode = billing.settings.expected_livemode
    record.stripe_checkout_session_id = hosted.session_id
    record.checkout_attempt_number = attempt
    record.checkout_expires_at = hosted.expires_at
    if hosted.customer_id:
        record.stripe_customer_id = hosted.customer_id
    return record


async def _process_webhook_event(
    session: AsyncSession,
    billing: StripeBillingService,
    event: dict[str, Any],
) -> WebhookResponse:
    event_id = _event_text(event, "id")
    event_type = _event_text(event, "type")
    existing = await session.execute(
        select(StripeWebhookEventRecord.id).where(StripeWebhookEventRecord.stripe_event_id == event_id)
    )
    if existing.scalar_one_or_none() is not None:
        return WebhookResponse(duplicate=True, outcome="duplicate")
    event_object = _event_object(event)
    receipt = _new_event_receipt(event, event_id, event_type, event_object)
    session.add(receipt)
    try:
        await session.flush()
    except IntegrityError:
        await session.rollback()
        return WebhookResponse(duplicate=True, outcome="duplicate")
    reconciliation = await _reconcile_event(session, billing, event_type, event_object)
    _apply_reconciliation(receipt, reconciliation)
    return WebhookResponse(outcome=reconciliation.outcome)


async def _reconcile_event(
    session: AsyncSession,
    billing: StripeBillingService,
    event_type: str,
    event_object: dict[str, Any],
) -> _Reconciliation:
    if event_type not in _SUPPORTED_EVENTS:
        return _Reconciliation(None, None, None, "ignored", "unsupported_event")
    if event_type in _CHECKOUT_EVENTS:
        return await _reconcile_checkout_event(session, billing, event_type, event_object)
    subscription_id = _subscription_id_for_event(event_type, event_object)
    if subscription_id is None:
        return _Reconciliation(None, None, None, "ignored", "invoice_without_subscription")
    record = await _lock_subscription_for_event(session, event_type, event_object, subscription_id)
    if record is None:
        return _Reconciliation(None, None, None, "ignored", "unbound_invoice")
    ignored = _superseded_subscription_reconciliation(record, subscription_id)
    if ignored is not None:
        return ignored
    return await _reconcile_current_subscription(
        session,
        billing,
        event_type,
        event_object,
        subscription_id,
        record,
    )


def _superseded_subscription_reconciliation(
    record: TenantSubscriptionRecord,
    subscription_id: str,
) -> _Reconciliation | None:
    if subscription_id == record.archived_stripe_subscription_id:
        return _Reconciliation(
            record.tenant_id,
            record.status,
            record.status,
            "ignored",
            "superseded_subscription",
        )
    if record.archived_stripe_subscription_id and record.stripe_subscription_id is None:
        return _Reconciliation(
            record.tenant_id,
            record.status,
            record.status,
            "ignored",
            "replacement_checkout_required",
        )
    return None


async def _reconcile_current_subscription(
    session: AsyncSession,
    billing: StripeBillingService,
    event_type: str,
    event_object: dict[str, Any],
    subscription_id: str,
    record: TenantSubscriptionRecord,
) -> _Reconciliation:
    try:
        snapshot = await billing.retrieve_subscription(
            subscription_id,
            allow_no_trial=record.trial_consumed_at is not None,
        )
    except StripeBillingValidationError:
        if record.stripe_subscription_id == subscription_id:
            return _reject_bound_subscription(record)
        raise
    if snapshot.subscription_id != subscription_id:
        raise StripeBillingValidationError("Subscription identifier validation failed")
    _validate_event_resource(event_type, event_object, snapshot)
    return await _apply_subscription_snapshot(session, snapshot, record=record)


async def _lock_subscription_for_event(
    session: AsyncSession,
    event_type: str,
    event_object: dict[str, Any],
    subscription_id: str,
) -> TenantSubscriptionRecord | None:
    if event_type in _SUBSCRIPTION_EVENTS:
        metadata = _required_mapping(event_object.get("metadata"), "subscription metadata")
        tenant_id = _event_text(metadata, "tenant_id")
        _tenant, record = await _lock_tenant_subscription(session, tenant_id)
        if record is None:
            raise StripeBillingValidationError("No tenant billing record exists")
        return record
    candidate = await session.scalar(
        select(TenantSubscriptionRecord.tenant_id).where(
            TenantSubscriptionRecord.stripe_subscription_id == subscription_id
        )
    )
    if candidate is None:
        return None
    _tenant, record = await _lock_tenant_subscription(session, candidate)
    if record is None or record.stripe_subscription_id != subscription_id:
        return None
    return record


async def _reconcile_checkout_event(
    session: AsyncSession,
    billing: StripeBillingService,
    event_type: str,
    event_object: dict[str, Any],
) -> _Reconciliation:
    tenant_id, owner_id = _checkout_event_identity(event_object)
    _tenant, record = await _lock_tenant_subscription(session, tenant_id)
    if record is None:
        raise StripeBillingValidationError("No pending tenant billing record exists")
    checkout = await billing.retrieve_checkout_session(
        _event_text(event_object, "id"),
        tenant_id=tenant_id,
        billing_owner_user_id=owner_id,
    )
    if event_type == "checkout.session.expired":
        if checkout.status != "expired":
            return _Reconciliation(tenant_id, None, None, "ignored", "stale_checkout_event")
        return await _expire_pending_checkout(session, checkout, record)
    if checkout.status != "complete" or not checkout.customer_id or not checkout.subscription_id:
        raise StripeBillingValidationError("Completed Checkout state is invalid")
    try:
        snapshot = await billing.retrieve_subscription(
            checkout.subscription_id,
            allow_no_trial=record.trial_consumed_at is not None,
        )
    except StripeBillingValidationError:
        if record.stripe_subscription_id == checkout.subscription_id:
            return _reject_bound_subscription(record)
        raise
    _validate_checkout_subscription(checkout, snapshot)
    return await _apply_subscription_snapshot(session, snapshot, record=record, checkout=checkout)


async def _apply_subscription_snapshot(
    session: AsyncSession,
    snapshot: SubscriptionSnapshot,
    *,
    record: TenantSubscriptionRecord,
    checkout: CheckoutSnapshot | None = None,
) -> _Reconciliation:
    await _require_webhook_identity(
        session,
        snapshot.tenant_id,
        snapshot.billing_owner_user_id,
    )
    if record.tenant_id != snapshot.tenant_id:
        raise StripeBillingValidationError("Locked tenant billing record does not match snapshot")
    await _validate_unique_binding(session, snapshot)
    _validate_record_binding(record, snapshot, checkout)
    previous_status = record.status
    _validate_consumed_trial(record, snapshot)
    record.status = snapshot.status.value
    record.stripe_customer_id = snapshot.customer_id
    record.stripe_subscription_id = snapshot.subscription_id
    record.stripe_price_id = snapshot.price_id
    record.stripe_livemode = snapshot.livemode
    record.trial_started_at = snapshot.trial_started_at
    record.trial_ends_at = snapshot.trial_ends_at
    record.entitlement_ends_at = snapshot.entitlement_ends_at
    record.cancel_at_period_end = snapshot.cancel_at_period_end
    if record.trial_consumed_at is None and snapshot.trial_started_at is not None:
        record.trial_consumed_at = snapshot.trial_started_at
    if checkout is not None:
        record.stripe_checkout_session_id = checkout.session_id
        record.checkout_expires_at = checkout.expires_at
    return _Reconciliation(
        snapshot.tenant_id,
        previous_status,
        record.status,
        "processed",
        "subscription_synchronized",
    )


async def _expire_pending_checkout(
    session: AsyncSession,
    checkout: CheckoutSnapshot,
    record: TenantSubscriptionRecord,
) -> _Reconciliation:
    await _require_webhook_identity(
        session,
        checkout.tenant_id,
        checkout.billing_owner_user_id,
    )
    if record.tenant_id != checkout.tenant_id:
        raise StripeBillingValidationError("Locked tenant billing record does not match Checkout")
    if record.billing_owner_user_id != checkout.billing_owner_user_id:
        raise StripeBillingValidationError("Billing owner validation failed")
    if record.stripe_price_id != checkout.price_id or record.stripe_livemode != checkout.livemode:
        raise StripeBillingValidationError("Checkout binding validation failed")
    if record.stripe_customer_id and record.stripe_customer_id != checkout.customer_id:
        raise StripeBillingValidationError("Stripe customer validation failed")
    previous_status = record.status
    if record.stripe_checkout_session_id != checkout.session_id:
        return _Reconciliation(
            checkout.tenant_id,
            previous_status,
            previous_status,
            "ignored",
            "superseded_checkout",
        )
    if previous_status != BillingStatus.CHECKOUT_PENDING.value:
        return _Reconciliation(
            checkout.tenant_id,
            previous_status,
            previous_status,
            "ignored",
            "checkout_already_reconciled",
        )
    record.status = BillingStatus.INCOMPLETE_EXPIRED.value
    record.stripe_checkout_session_id = None
    record.checkout_expires_at = None
    return _Reconciliation(
        checkout.tenant_id,
        previous_status,
        record.status,
        "processed",
        "checkout_expired",
    )


def _reject_bound_subscription(record: TenantSubscriptionRecord) -> _Reconciliation:
    previous_status = record.status
    record.status = BillingStatus.UNKNOWN.value
    record.entitlement_ends_at = None
    record.cancel_at_period_end = False
    return _Reconciliation(
        record.tenant_id,
        previous_status,
        record.status,
        "rejected",
        "subscription_validation_failed",
    )


def _validate_record_binding(
    record: TenantSubscriptionRecord,
    snapshot: SubscriptionSnapshot,
    checkout: CheckoutSnapshot | None,
) -> None:
    if record.billing_owner_user_id != snapshot.billing_owner_user_id:
        raise StripeBillingValidationError("Billing owner validation failed")
    if record.stripe_price_id != snapshot.price_id or record.stripe_livemode != snapshot.livemode:
        raise StripeBillingValidationError("Subscription binding validation failed")
    if record.stripe_customer_id and record.stripe_customer_id != snapshot.customer_id:
        raise StripeBillingValidationError("Stripe customer validation failed")
    if record.stripe_subscription_id and record.stripe_subscription_id != snapshot.subscription_id:
        replacement_allowed = (
            record.status == BillingStatus.CHECKOUT_PENDING.value and record.stripe_checkout_session_id is not None
        )
        if not replacement_allowed:
            raise StripeBillingValidationError("Stripe subscription validation failed")
    if checkout is not None and record.stripe_checkout_session_id != checkout.session_id:
        raise StripeBillingValidationError("Stripe Checkout session validation failed")


async def _validate_unique_binding(
    session: AsyncSession,
    snapshot: SubscriptionSnapshot,
) -> None:
    result = await session.execute(
        select(TenantSubscriptionRecord.tenant_id).where(
            or_(
                TenantSubscriptionRecord.stripe_customer_id == snapshot.customer_id,
                TenantSubscriptionRecord.stripe_subscription_id == snapshot.subscription_id,
            )
        )
    )
    if any(tenant_id != snapshot.tenant_id for tenant_id in result.scalars().all()):
        raise StripeBillingValidationError("Stripe resource belongs to another tenant")


def _validate_consumed_trial(
    record: TenantSubscriptionRecord,
    snapshot: SubscriptionSnapshot,
) -> None:
    consumed = record.trial_consumed_at
    started = snapshot.trial_started_at
    if consumed is not None and started is not None and _as_utc(consumed) != _as_utc(started):
        raise StripeBillingValidationError("A different trial was already consumed")


def _validate_checkout_subscription(
    checkout: CheckoutSnapshot,
    snapshot: SubscriptionSnapshot,
) -> None:
    if checkout.tenant_id != snapshot.tenant_id:
        raise StripeBillingValidationError("Checkout tenant validation failed")
    if checkout.billing_owner_user_id != snapshot.billing_owner_user_id:
        raise StripeBillingValidationError("Checkout owner validation failed")
    if checkout.customer_id != snapshot.customer_id:
        raise StripeBillingValidationError("Checkout customer validation failed")
    if checkout.subscription_id != snapshot.subscription_id:
        raise StripeBillingValidationError("Checkout subscription validation failed")
    if checkout.price_id != snapshot.price_id or checkout.livemode != snapshot.livemode:
        raise StripeBillingValidationError("Checkout subscription mode validation failed")


def _validate_event_resource(
    event_type: str,
    event_object: dict[str, Any],
    snapshot: SubscriptionSnapshot,
) -> None:
    if event_type in _SUBSCRIPTION_EVENTS:
        if _event_text(event_object, "id") != snapshot.subscription_id:
            raise StripeBillingValidationError("Subscription event validation failed")
        customer_id = _resource_id(event_object.get("customer"))
        metadata = _optional_mapping(event_object.get("metadata"))
        if customer_id and customer_id != snapshot.customer_id:
            raise StripeBillingValidationError("Subscription customer validation failed")
        if metadata and metadata.get("tenant_id") != snapshot.tenant_id:
            raise StripeBillingValidationError("Subscription tenant validation failed")
        if metadata and metadata.get("billing_owner_user_id") != snapshot.billing_owner_user_id:
            raise StripeBillingValidationError("Subscription owner validation failed")
        return
    invoice_customer = _resource_id(event_object.get("customer"))
    if invoice_customer and invoice_customer != snapshot.customer_id:
        raise StripeBillingValidationError("Invoice customer validation failed")


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
        raise StripeBillingValidationError("Checkout mode validation failed")
    metadata = _required_mapping(event_object.get("metadata"), "checkout metadata")
    tenant_id = _event_text(metadata, "tenant_id")
    owner_id = _event_text(metadata, "billing_owner_user_id")
    if event_object.get("client_reference_id") != tenant_id:
        raise StripeBillingValidationError("Checkout tenant validation failed")
    return tenant_id, owner_id


async def _require_active_identity(session: AsyncSession, current_user: CurrentUser) -> str:
    tenant = await _get_tenant(session, current_user.tenant_id)
    user_result = await session.execute(
        select(UserRecord).where(
            UserRecord.user_id == current_user.user_id,
            UserRecord.tenant_id == current_user.tenant_id,
        )
    )
    user = user_result.scalar_one_or_none()
    if tenant is None or not tenant.is_active or user is None or not user.is_active:
        raise HTTPException(status_code=403, detail="Active tenant membership required")
    return str(user.email)


async def _require_webhook_identity(
    session: AsyncSession,
    tenant_id: str,
    owner_id: str,
) -> None:
    tenant = await _get_tenant(session, tenant_id)
    user_result = await session.execute(
        select(UserRecord.id).where(
            UserRecord.user_id == owner_id,
            UserRecord.tenant_id == tenant_id,
        )
    )
    if tenant is None or user_result.scalar_one_or_none() is None:
        raise StripeBillingValidationError("Webhook tenant identity validation failed")


async def _get_tenant(
    session: AsyncSession,
    tenant_id: str,
    *,
    lock: bool = False,
) -> TenantRecord | None:
    statement = select(TenantRecord).where(TenantRecord.tenant_id == tenant_id)
    if lock:
        statement = statement.with_for_update()
    result = await session.execute(statement)
    return result.scalar_one_or_none()


async def _get_subscription(
    session: AsyncSession,
    tenant_id: str,
    *,
    lock: bool = False,
) -> TenantSubscriptionRecord | None:
    statement = select(TenantSubscriptionRecord).where(TenantSubscriptionRecord.tenant_id == tenant_id)
    if lock:
        statement = statement.with_for_update()
    result = await session.execute(statement)
    return result.scalar_one_or_none()


async def _lock_tenant_subscription(
    session: AsyncSession,
    tenant_id: str,
) -> tuple[TenantRecord | None, TenantSubscriptionRecord | None]:
    """Acquire the canonical tenant then subscription row-lock order."""
    tenant = await _get_tenant(session, tenant_id, lock=True)
    if tenant is None:
        return None, None
    subscription = await _get_subscription(session, tenant_id, lock=True)
    return tenant, subscription


def _new_event_receipt(
    event: dict[str, Any],
    event_id: str,
    event_type: str,
    event_object: dict[str, Any],
) -> StripeWebhookEventRecord:
    livemode = event.get("livemode")
    if not isinstance(livemode, bool):
        raise StripeBillingValidationError("Stripe event mode is invalid")
    return StripeWebhookEventRecord(
        stripe_event_id=event_id,
        event_type=event_type,
        stripe_object_id=_resource_id(event_object.get("id")),
        livemode=livemode,
        api_version=_optional_text(event.get("api_version")),
        outcome="ignored",
        reason="processing",
        stripe_created_at=_event_timestamp(event.get("created")),
    )


def _apply_reconciliation(
    receipt: StripeWebhookEventRecord,
    reconciliation: _Reconciliation,
) -> None:
    receipt.tenant_id = reconciliation.tenant_id
    receipt.previous_status = reconciliation.previous_status
    receipt.resulting_status = reconciliation.resulting_status
    receipt.outcome = reconciliation.outcome
    receipt.reason = reconciliation.reason


async def _read_webhook_body(request: Request) -> bytes:
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            parsed_length = int(content_length)
            if parsed_length < 0:
                raise ValueError
            if parsed_length > _MAX_WEBHOOK_BODY_BYTES:
                raise HTTPException(status_code=413, detail="Webhook body is too large")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid Content-Length header") from exc
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > _MAX_WEBHOOK_BODY_BYTES:
            raise HTTPException(status_code=413, detail="Webhook body is too large")
        body.extend(chunk)
    return bytes(body)


def _event_object(event: dict[str, Any]) -> dict[str, Any]:
    data = _required_mapping(event.get("data"), "event data")
    return _required_mapping(data.get("object"), "event object")


def _required_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise StripeBillingValidationError(f"Invalid {label}")
    return value


def _optional_mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _event_text(value: dict[str, Any], key: str) -> str:
    text = value.get(key)
    if not isinstance(text, str) or not text.strip():
        raise StripeBillingValidationError(f"Stripe {key} is missing")
    return text.strip()


def _resource_id(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, dict):
        return _optional_text(value.get("id"))
    return None


def _optional_text(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _event_timestamp(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        raise StripeBillingValidationError("Stripe event timestamp is invalid")
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc)
    except (OverflowError, OSError, ValueError) as exc:
        raise StripeBillingValidationError("Stripe event timestamp is invalid") from exc


def _record_status(value: str) -> BillingStatus:
    try:
        return BillingStatus(value)
    except ValueError:
        return BillingStatus.UNKNOWN


def _offer_response(offer: BillingOffer) -> BillingOfferResponse:
    return BillingOfferResponse(
        name=offer.name,
        description=offer.description,
        unit_amount=offer.unit_amount,
        currency=offer.currency,
        interval=offer.interval,
        interval_count=offer.interval_count,
        trial_days=offer.trial_days,
    )


def _hosted_response(hosted: HostedSession) -> HostedSessionResponse:
    return HostedSessionResponse(url=hosted.url, expires_at=hosted.expires_at)


def _is_future(value: datetime | None) -> bool:
    return value is not None and _as_utc(value) > datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)


__all__ = [
    "get_billing_service_dep",
    "require_entitled_user",
    "router",
    "subscription_is_entitled",
]
