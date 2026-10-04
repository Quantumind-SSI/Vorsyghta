"""Server-side Stripe Billing integration for the Team subscription."""

from __future__ import annotations

import asyncio
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from hashlib import sha256
from ipaddress import ip_address
from time import monotonic
from typing import Any, cast
from urllib.parse import urlsplit

import stripe

from vorsyghta.db.models.billing import BillingStatus


TRIAL_DAYS = 14
_OFFER_CACHE_TTL_SECONDS = 60.0
_DEPLOYED_ENVIRONMENTS = frozenset({"staging", "production"})
_VALID_ENVIRONMENTS = frozenset({"development", "test", "integration", "staging", "production"})


class StripeBillingError(Exception):
    """Base class for safe billing integration failures."""


class StripeBillingConfigurationError(StripeBillingError):
    """Raised when required server-side Stripe settings are invalid."""


class StripeBillingProviderError(StripeBillingError):
    """Raised when Stripe cannot complete a server-side request."""


class StripeBillingValidationError(StripeBillingError):
    """Raised when Stripe state violates the configured billing contract."""


class StripeWebhookSignatureError(StripeBillingError):
    """Raised when a webhook payload cannot be authenticated."""


@dataclass(frozen=True)
class StripeBillingSettings:
    """Validated server-only Stripe settings."""

    secret_key: str = field(repr=False)
    webhook_secret: str = field(repr=False)
    price_id: str
    checkout_success_url: str
    checkout_cancel_url: str
    portal_return_url: str
    automatic_tax_enabled: bool = True
    tax_id_collection_enabled: bool = True
    expected_livemode: bool = False
    request_timeout_seconds: float = 10.0
    max_network_retries: int = 2
    webhook_tolerance_seconds: int = 300
    environment: str = "development"

    def __post_init__(self) -> None:
        values = {
            "STRIPE_SECRET_KEY": self.secret_key,
            "STRIPE_WEBHOOK_SECRET": self.webhook_secret,
            "STRIPE_PRICE_ID": self.price_id,
            "STRIPE_CHECKOUT_SUCCESS_URL": self.checkout_success_url,
            "STRIPE_CHECKOUT_CANCEL_URL": self.checkout_cancel_url,
            "STRIPE_PORTAL_RETURN_URL": self.portal_return_url,
        }
        missing = [name for name, value in values.items() if not value.strip()]
        if missing:
            raise StripeBillingConfigurationError("Stripe billing is not configured")
        if not self.secret_key.startswith(("sk_test_", "sk_live_", "rk_test_", "rk_live_")):
            raise StripeBillingConfigurationError("Stripe billing is not configured")
        if not self.webhook_secret.startswith("whsec_") or not self.price_id.startswith("price_"):
            raise StripeBillingConfigurationError("Stripe billing is not configured")
        normalized_environment = self.environment.strip().lower()
        if normalized_environment not in _VALID_ENVIRONMENTS:
            raise StripeBillingConfigurationError("Stripe billing environment is invalid")
        object.__setattr__(self, "environment", normalized_environment)
        for url in (
            self.checkout_success_url,
            self.checkout_cancel_url,
            self.portal_return_url,
        ):
            _validate_redirect_url(url, normalized_environment)
        if not 0 < self.request_timeout_seconds <= 30:
            raise StripeBillingConfigurationError("Stripe billing is not configured")
        if not 0 <= self.max_network_retries <= 3:
            raise StripeBillingConfigurationError("Stripe billing is not configured")
        if not 1 <= self.webhook_tolerance_seconds <= 900:
            raise StripeBillingConfigurationError("Stripe billing is not configured")
        if not isinstance(self.automatic_tax_enabled, bool):
            raise StripeBillingConfigurationError("Stripe billing is not configured")
        if not isinstance(self.tax_id_collection_enabled, bool):
            raise StripeBillingConfigurationError("Stripe billing is not configured")
        if not isinstance(self.expected_livemode, bool) or self.livemode != self.expected_livemode:
            raise StripeBillingConfigurationError("Stripe key mode does not match expected mode")

    @property
    def livemode(self) -> bool:
        """Return the Stripe mode encoded by the configured API key."""
        return "_live_" in self.secret_key

    @classmethod
    def from_env(cls) -> "StripeBillingSettings":
        """Load billing settings from process environment variables."""
        return cls(
            secret_key=os.getenv("STRIPE_SECRET_KEY", ""),
            webhook_secret=os.getenv("STRIPE_WEBHOOK_SECRET", ""),
            price_id=os.getenv("STRIPE_PRICE_ID", ""),
            checkout_success_url=os.getenv("STRIPE_CHECKOUT_SUCCESS_URL", ""),
            checkout_cancel_url=os.getenv("STRIPE_CHECKOUT_CANCEL_URL", ""),
            portal_return_url=os.getenv("STRIPE_PORTAL_RETURN_URL", ""),
            automatic_tax_enabled=_read_bool_env("STRIPE_AUTOMATIC_TAX_ENABLED", True),
            tax_id_collection_enabled=_read_bool_env("STRIPE_TAX_ID_COLLECTION_ENABLED", True),
            expected_livemode=expected_stripe_livemode_from_env(),
            request_timeout_seconds=_read_float_env("STRIPE_REQUEST_TIMEOUT_SECONDS", 10.0),
            max_network_retries=_read_int_env("STRIPE_MAX_NETWORK_RETRIES", 2),
            webhook_tolerance_seconds=_read_int_env("STRIPE_WEBHOOK_TOLERANCE_SECONDS", 300),
            environment=os.getenv("ENVIRONMENT", "development"),
        )


@dataclass(frozen=True)
class BillingOffer:
    """Public, non-secret metadata for the configured recurring Price."""

    name: str
    description: str | None
    unit_amount: int
    currency: str
    interval: str
    interval_count: int
    trial_days: int = TRIAL_DAYS


@dataclass(frozen=True)
class HostedSession:
    """Internal representation of a Stripe-hosted redirect session."""

    session_id: str
    url: str
    expires_at: datetime | None
    status: str | None = None
    customer_id: str | None = None
    subscription_id: str | None = None


@dataclass(frozen=True)
class CheckoutSnapshot:
    """Validated Stripe Checkout state used during webhook reconciliation."""

    session_id: str
    tenant_id: str
    billing_owner_user_id: str
    price_id: str
    quantity: int
    mode: str
    status: str
    livemode: bool
    customer_id: str | None
    subscription_id: str | None
    expires_at: datetime | None
    url: str | None


@dataclass(frozen=True)
class SubscriptionSnapshot:
    """Normalized Stripe subscription state safe for local persistence."""

    subscription_id: str
    customer_id: str
    tenant_id: str
    billing_owner_user_id: str
    price_id: str
    quantity: int
    status: BillingStatus
    trial_started_at: datetime | None
    trial_ends_at: datetime | None
    entitlement_ends_at: datetime | None
    cancel_at_period_end: bool
    livemode: bool


class StripeBillingService:
    """Stripe API boundary with no process-global API key mutation."""

    def __init__(self, settings: StripeBillingSettings, client: Any | None = None) -> None:
        self.settings = settings
        self._client = client or stripe.StripeClient(
            settings.secret_key,
            max_network_retries=settings.max_network_retries,
            http_client=stripe.HTTPXClient(timeout=settings.request_timeout_seconds),
        )
        self._offer_cache: tuple[float, BillingOffer] | None = None
        self._offer_lock = asyncio.Lock()

    async def get_offer(self) -> BillingOffer:
        """Retrieve and validate the sole configured recurring Price."""
        now = monotonic()
        if self._offer_cache is not None and now < self._offer_cache[0]:
            return self._offer_cache[1]
        async with self._offer_lock:
            now = monotonic()
            if self._offer_cache is not None and now < self._offer_cache[0]:
                return self._offer_cache[1]
            offer = await self._retrieve_offer()
            self._offer_cache = (now + _OFFER_CACHE_TTL_SECONDS, offer)
            return offer

    async def _retrieve_offer(self) -> BillingOffer:
        try:
            price = await self._client.v1.prices.retrieve_async(
                self.settings.price_id,
                params={"expand": ["product"]},
            )
        except stripe.StripeError as exc:
            raise StripeBillingProviderError("Stripe is unavailable") from exc
        return _normalize_offer(price, self.settings.price_id, self.settings.expected_livemode)

    async def create_checkout_session(
        self,
        *,
        tenant_id: str,
        billing_owner_user_id: str,
        billing_owner_email: str | None,
        stripe_customer_id: str | None,
        checkout_attempt_number: int,
        include_trial: bool = True,
    ) -> HostedSession:
        """Create a card-required, Stripe-hosted 14-day subscription trial."""
        metadata = {
            "tenant_id": _required_text(tenant_id, "tenant metadata"),
            "billing_owner_user_id": _required_text(
                billing_owner_user_id,
                "billing owner metadata",
            ),
        }
        params = cast(
            stripe.params.checkout.SessionCreateParams,
            self._checkout_params(metadata, billing_owner_email, stripe_customer_id, include_trial),
        )
        options = cast(
            stripe.RequestOptions,
            {"idempotency_key": _checkout_idempotency_key(tenant_id, checkout_attempt_number)},
        )
        try:
            session = await self._client.v1.checkout.sessions.create_async(
                params=params,
                options=options,
            )
        except stripe.StripeError as exc:
            raise StripeBillingProviderError("Stripe is unavailable") from exc
        return _normalize_hosted_session(session, require_url=True)

    async def retrieve_checkout_session(
        self,
        session_id: str,
        *,
        tenant_id: str,
        billing_owner_user_id: str,
    ) -> CheckoutSnapshot:
        """Retrieve and validate current Checkout state from Stripe."""
        try:
            session = await self._client.v1.checkout.sessions.retrieve_async(
                _required_text(session_id, "checkout session"),
                params={"expand": ["line_items"]},
            )
        except stripe.StripeError as exc:
            raise StripeBillingProviderError("Stripe is unavailable") from exc
        snapshot = _normalize_checkout(session)
        if snapshot.tenant_id != tenant_id or snapshot.billing_owner_user_id != billing_owner_user_id:
            raise StripeBillingValidationError("Checkout ownership validation failed")
        if snapshot.price_id != self.settings.price_id or snapshot.quantity != 1:
            raise StripeBillingValidationError("Checkout price validation failed")
        if snapshot.mode != "subscription" or snapshot.livemode != self.settings.expected_livemode:
            raise StripeBillingValidationError("Checkout mode validation failed")
        return snapshot

    async def retrieve_subscription(
        self,
        subscription_id: str,
        *,
        allow_no_trial: bool = False,
    ) -> SubscriptionSnapshot:
        """Retrieve and normalize the current Stripe subscription snapshot."""
        try:
            subscription = await self._client.v1.subscriptions.retrieve_async(
                _required_text(subscription_id, "subscription"),
            )
        except stripe.StripeError as exc:
            raise StripeBillingProviderError("Stripe is unavailable") from exc
        return _normalize_subscription(
            subscription,
            expected_price_id=self.settings.price_id,
            livemode=self.settings.expected_livemode,
            allow_no_trial=allow_no_trial,
        )

    async def create_portal_session(self, customer_id: str) -> HostedSession:
        """Create a short-lived Stripe-hosted Customer Portal session."""
        try:
            session = await self._client.v1.billing_portal.sessions.create_async(
                params={
                    "customer": _required_text(customer_id, "customer"),
                    "return_url": self.settings.portal_return_url,
                }
            )
        except stripe.StripeError as exc:
            raise StripeBillingProviderError("Stripe is unavailable") from exc
        return _normalize_hosted_session(session, require_url=True)

    def verify_webhook(self, payload: bytes, signature: str | None) -> dict[str, Any]:
        """Verify the raw Stripe webhook body and expected live/test mode."""
        try:
            event = self._client.construct_event(
                payload,
                signature,
                self.settings.webhook_secret,
                tolerance=self.settings.webhook_tolerance_seconds,
            )
        except (stripe.SignatureVerificationError, ValueError) as exc:
            raise StripeWebhookSignatureError("Invalid Stripe webhook") from exc
        event_data = _as_mapping(event, "webhook event")
        livemode = event_data.get("livemode")
        if not isinstance(livemode, bool) or livemode != self.settings.livemode:
            raise StripeBillingValidationError("Stripe event mode validation failed")
        _required_text(event_data.get("id"), "event id")
        _required_text(event_data.get("type"), "event type")
        return event_data

    def _checkout_params(
        self,
        metadata: dict[str, str],
        billing_owner_email: str | None,
        stripe_customer_id: str | None,
        include_trial: bool,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "mode": "subscription",
            "line_items": [{"price": self.settings.price_id, "quantity": 1}],
            "payment_method_types": ["card"],
            "payment_method_collection": "always",
            "billing_address_collection": "required",
            "tax_id_collection": {"enabled": self.settings.tax_id_collection_enabled},
            "automatic_tax": {"enabled": self.settings.automatic_tax_enabled},
            "client_reference_id": metadata["tenant_id"],
            "metadata": metadata,
            "subscription_data": {"metadata": metadata},
            "success_url": self.settings.checkout_success_url,
            "cancel_url": self.settings.checkout_cancel_url,
        }
        if include_trial:
            params["subscription_data"]["trial_period_days"] = TRIAL_DAYS
        if stripe_customer_id:
            params["customer"] = stripe_customer_id
            params["customer_update"] = {"address": "auto", "name": "auto"}
        elif billing_owner_email:
            params["customer_email"] = billing_owner_email
        return params


@lru_cache(maxsize=1)
def get_stripe_billing_service() -> StripeBillingService:
    """Return the lazily configured process-wide Stripe billing client."""
    return StripeBillingService(StripeBillingSettings.from_env())


def _normalize_offer(value: Any, expected_price_id: str, expected_livemode: bool) -> BillingOffer:
    price = _as_mapping(value, "price")
    if price.get("id") != expected_price_id or price.get("active") is not True:
        raise StripeBillingValidationError("Configured Stripe Price is unavailable")
    if price.get("livemode") is not expected_livemode:
        raise StripeBillingValidationError("Configured Stripe Price mode is invalid")
    recurring = _as_mapping(price.get("recurring"), "recurring price")
    product = _as_mapping(price.get("product"), "expanded product")
    amount = price.get("unit_amount")
    interval_count = recurring.get("interval_count", 1)
    if isinstance(amount, bool) or not isinstance(amount, int) or amount < 0:
        raise StripeBillingValidationError("Configured Stripe Price has no fixed amount")
    if isinstance(interval_count, bool) or not isinstance(interval_count, int) or interval_count < 1:
        raise StripeBillingValidationError("Configured Stripe Price has an invalid cadence")
    if product.get("active") is not True:
        raise StripeBillingValidationError("Configured Stripe product is inactive")
    currency = _required_text(price.get("currency"), "price currency").lower()
    interval = _required_text(recurring.get("interval"), "billing interval")
    if len(currency) != 3 or not currency.isalpha() or interval not in {"day", "week", "month", "year"}:
        raise StripeBillingValidationError("Configured Stripe Price has invalid billing metadata")
    return BillingOffer(
        name=_required_text(product.get("name"), "product name"),
        description=_optional_text(product.get("description")),
        unit_amount=amount,
        currency=currency,
        interval=interval,
        interval_count=interval_count,
    )


def _normalize_hosted_session(value: Any, *, require_url: bool) -> HostedSession:
    session = _as_mapping(value, "hosted session")
    url = _optional_text(session.get("url"))
    if require_url and url is None:
        raise StripeBillingValidationError("Stripe did not return a hosted session URL")
    if url is not None:
        _validate_hosted_url(url)
    return HostedSession(
        session_id=_required_text(session.get("id"), "hosted session id"),
        url=url or "",
        expires_at=_optional_timestamp(session.get("expires_at")),
        status=_optional_text(session.get("status")),
        customer_id=_resource_id(session.get("customer")),
        subscription_id=_resource_id(session.get("subscription")),
    )


def _normalize_checkout(value: Any) -> CheckoutSnapshot:
    session = _as_mapping(value, "checkout session")
    metadata = _as_mapping(session.get("metadata"), "checkout metadata")
    line_items = _as_mapping(session.get("line_items"), "checkout line items")
    items = line_items.get("data")
    if not isinstance(items, list) or len(items) != 1:
        raise StripeBillingValidationError("Checkout must contain one line item")
    item = _as_mapping(items[0], "checkout line item")
    quantity = item.get("quantity")
    if isinstance(quantity, bool) or not isinstance(quantity, int):
        raise StripeBillingValidationError("Checkout quantity is invalid")
    livemode = session.get("livemode")
    if not isinstance(livemode, bool):
        raise StripeBillingValidationError("Checkout mode is invalid")
    checkout_status = _required_text(session.get("status"), "checkout status")
    if checkout_status not in {"open", "complete", "expired"}:
        raise StripeBillingValidationError("Checkout status is invalid")
    return CheckoutSnapshot(
        session_id=_required_text(session.get("id"), "checkout session id"),
        tenant_id=_required_text(metadata.get("tenant_id"), "tenant metadata"),
        billing_owner_user_id=_required_text(
            metadata.get("billing_owner_user_id"),
            "billing owner metadata",
        ),
        price_id=_resource_id(item.get("price"), required=True) or "",
        quantity=quantity,
        mode=_required_text(session.get("mode"), "checkout mode"),
        status=checkout_status,
        livemode=livemode,
        customer_id=_resource_id(session.get("customer")),
        subscription_id=_resource_id(session.get("subscription")),
        expires_at=_optional_timestamp(session.get("expires_at")),
        url=_optional_text(session.get("url")),
    )


def _normalize_subscription(
    value: Any,
    *,
    expected_price_id: str,
    livemode: bool,
    allow_no_trial: bool,
) -> SubscriptionSnapshot:
    subscription = _as_mapping(value, "subscription")
    if subscription.get("livemode") is not livemode:
        raise StripeBillingValidationError("Subscription mode validation failed")
    metadata = _as_mapping(subscription.get("metadata"), "subscription metadata")
    items_container = _as_mapping(subscription.get("items"), "subscription items")
    items = items_container.get("data")
    if not isinstance(items, list) or len(items) != 1:
        raise StripeBillingValidationError("Subscription must contain one item")
    item = _as_mapping(items[0], "subscription item")
    price_id = _resource_id(item.get("price"), required=True) or ""
    quantity = item.get("quantity")
    if price_id != expected_price_id or quantity != 1:
        raise StripeBillingValidationError("Subscription price validation failed")
    status = _billing_status(subscription.get("status"))
    trial_start = _optional_timestamp(subscription.get("trial_start"))
    trial_end = _optional_timestamp(subscription.get("trial_end"))
    _validate_trial_window(trial_start, trial_end, allow_no_trial=allow_no_trial)
    period_end = _optional_timestamp(subscription.get("current_period_end") or item.get("current_period_end"))
    entitlement_end = trial_end if status is BillingStatus.TRIALING else period_end
    cancel_at = _optional_timestamp(subscription.get("cancel_at"))
    if cancel_at is not None and (entitlement_end is None or cancel_at < entitlement_end):
        entitlement_end = cancel_at
    if status in (BillingStatus.TRIALING, BillingStatus.ACTIVE) and entitlement_end is None:
        raise StripeBillingValidationError("Subscription entitlement boundary is missing")
    return SubscriptionSnapshot(
        subscription_id=_required_text(subscription.get("id"), "subscription id"),
        customer_id=_resource_id(subscription.get("customer"), required=True) or "",
        tenant_id=_required_text(metadata.get("tenant_id"), "tenant metadata"),
        billing_owner_user_id=_required_text(
            metadata.get("billing_owner_user_id"),
            "billing owner metadata",
        ),
        price_id=price_id,
        quantity=quantity,
        status=status,
        trial_started_at=trial_start,
        trial_ends_at=trial_end,
        entitlement_ends_at=entitlement_end,
        cancel_at_period_end=subscription.get("cancel_at_period_end") is True,
        livemode=livemode,
    )


def _validate_trial_window(
    start: datetime | None,
    end: datetime | None,
    *,
    allow_no_trial: bool,
) -> None:
    if allow_no_trial and start is None and end is None:
        return
    if start is None or end is None or end - start != timedelta(days=TRIAL_DAYS):
        raise StripeBillingValidationError("Subscription trial must be exactly 14 days")


def _billing_status(value: Any) -> BillingStatus:
    try:
        return BillingStatus(str(value))
    except ValueError:
        return BillingStatus.UNKNOWN


def _as_mapping(value: Any, label: str) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        converted = to_dict()
        if isinstance(converted, Mapping):
            return dict(converted)
    raise StripeBillingValidationError(f"Invalid {label}")


def _resource_id(value: Any, *, required: bool = False) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    if value is not None:
        resource = _as_mapping(value, "Stripe resource")
        identifier = _optional_text(resource.get("id"))
        if identifier:
            return identifier
    if required:
        raise StripeBillingValidationError("Stripe resource identifier is missing")
    return None


def _optional_timestamp(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        raise StripeBillingValidationError("Stripe timestamp is invalid")
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc)
    except (OverflowError, OSError, ValueError) as exc:
        raise StripeBillingValidationError("Stripe timestamp is invalid") from exc


def _required_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise StripeBillingValidationError(f"{label.capitalize()} is missing")
    return value.strip()


def _optional_text(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _checkout_idempotency_key(tenant_id: str, attempt: int) -> str:
    if attempt < 1:
        raise StripeBillingValidationError("Checkout attempt is invalid")
    digest = sha256(f"{tenant_id}:{attempt}".encode("utf-8")).hexdigest()
    return f"vorsyghta-checkout-{digest}"


def _is_loopback_hostname(hostname: str) -> bool:
    normalized = hostname.rstrip(".").lower()
    if normalized == "localhost" or normalized.endswith(".localhost"):
        return True
    try:
        return ip_address(normalized).is_loopback
    except ValueError:
        return False


def _validate_redirect_url(value: str, environment: str) -> None:
    parsed = urlsplit(value)
    hostname = parsed.hostname
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or hostname is None
        or parsed.username
        or parsed.password
    ):
        raise StripeBillingConfigurationError("Stripe billing is not configured")
    loopback = _is_loopback_hostname(hostname)
    if environment in _DEPLOYED_ENVIRONMENTS and (parsed.scheme != "https" or loopback):
        raise StripeBillingConfigurationError("Deployed Stripe return URLs require non-loopback HTTPS origins")
    if parsed.scheme == "http" and not loopback:
        raise StripeBillingConfigurationError("Stripe billing is not configured")


def _validate_hosted_url(value: str) -> None:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise StripeBillingValidationError("Stripe hosted URL is invalid")


def _read_int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise StripeBillingConfigurationError("Stripe billing is not configured") from exc


def _read_float_env(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise StripeBillingConfigurationError("Stripe billing is not configured") from exc


def _read_bool_env(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise StripeBillingConfigurationError("Stripe billing is not configured")


def billing_required_from_env() -> bool:
    """Return whether product endpoints require a current paid entitlement."""
    environment = os.getenv("ENVIRONMENT", "development").strip().lower()
    if environment not in _VALID_ENVIRONMENTS:
        raise StripeBillingConfigurationError("Stripe billing environment is invalid")
    deployed_default = environment in _DEPLOYED_ENVIRONMENTS
    return _read_bool_env("VORSYGHTA_BILLING_REQUIRED", deployed_default)


def expected_stripe_livemode_from_env() -> bool:
    """Return the required Stripe mode, defaulting production to live mode."""
    is_production = os.getenv("ENVIRONMENT", "development").strip().lower() == "production"
    expected = _read_bool_env("STRIPE_EXPECTED_LIVEMODE", is_production)
    if is_production and not expected:
        raise StripeBillingConfigurationError("Production billing requires Stripe live mode")
    return expected


__all__ = [
    "BillingOffer",
    "CheckoutSnapshot",
    "HostedSession",
    "StripeBillingConfigurationError",
    "StripeBillingProviderError",
    "StripeBillingService",
    "StripeBillingSettings",
    "StripeBillingValidationError",
    "StripeWebhookSignatureError",
    "SubscriptionSnapshot",
    "TRIAL_DAYS",
    "billing_required_from_env",
    "expected_stripe_livemode_from_env",
    "get_stripe_billing_service",
]
