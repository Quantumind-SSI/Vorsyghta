"""Focused tests for the Stripe billing foundation."""

from __future__ import annotations

import json
import time
import asyncio
from collections.abc import AsyncIterator
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
import stripe
import httpx
from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy import event, func, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from vorsyghta.api.routers.billing import (
    _create_checkout_for_user,
    _process_webhook_event,
    _reconcile_event,
    _reuse_pending_checkout,
    get_billing_service_dep,
    get_billing_status,
    require_entitled_user,
    router,
    subscription_is_entitled,
)
from vorsyghta.db.base import Base
from vorsyghta.db.health import DatabaseHealth
from vorsyghta.db.models.auth import TenantRecord, UserRecord
from vorsyghta.db.models.billing import (
    BillingStatus,
    StripeWebhookEventRecord,
    TenantSubscriptionRecord,
)
from vorsyghta.db.session import get_session_dep
from vorsyghta.integrations.stripe_billing import (
    CheckoutSnapshot,
    HostedSession,
    StripeBillingConfigurationError,
    StripeBillingProviderError,
    StripeBillingService,
    StripeBillingSettings,
    StripeBillingValidationError,
    StripeWebhookSignatureError,
    SubscriptionSnapshot,
    billing_required_from_env,
    expected_stripe_livemode_from_env,
    get_stripe_billing_service,
)
from vorsyghta.security.rbac import CurrentUser, Role, create_access_token, get_current_user


_START = datetime(2026, 1, 1, tzinfo=timezone.utc)
_TRIAL_END = _START + timedelta(days=14)


@pytest.fixture
def billing_settings() -> StripeBillingSettings:
    return StripeBillingSettings(
        secret_key="sk_test_server",
        webhook_secret="whsec_server",
        price_id="price_team",
        checkout_success_url="https://app.example.test/billing/success",
        checkout_cancel_url="https://app.example.test/billing/cancel",
        portal_return_url="https://app.example.test/settings/billing",
    )


@pytest_asyncio.fixture
async def billing_db() -> AsyncIterator[AsyncSession]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")

    @event.listens_for(engine.sync_engine, "connect")
    def _enable_foreign_keys(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    tables = [
        TenantRecord.__table__,
        UserRecord.__table__,
        TenantSubscriptionRecord.__table__,
        StripeWebhookEventRecord.__table__,
    ]
    async with engine.begin() as connection:
        await connection.run_sync(lambda sync_connection: Base.metadata.create_all(sync_connection, tables=tables))
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        yield session
    await engine.dispose()


async def _seed_pending_subscription(session: AsyncSession) -> TenantSubscriptionRecord:
    tenant = TenantRecord(tenant_id="tenant-a", name="Tenant A", is_active=True)
    user = UserRecord(
        user_id="user-a",
        tenant_id="tenant-a",
        email="owner@example.test",
        hashed_password="not-used",
        role="admin",
        is_active=True,
    )
    subscription = TenantSubscriptionRecord(
        tenant_id="tenant-a",
        billing_owner_user_id="user-a",
        status=BillingStatus.CHECKOUT_PENDING.value,
        stripe_checkout_session_id="cs_test_a",
        stripe_price_id="price_team",
        stripe_livemode=False,
        checkout_attempt_number=1,
        checkout_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    session.add_all([tenant, user, subscription])
    await session.commit()
    return subscription


def _subscription_payload(
    *,
    price_id: str = "price_team",
    status: str = "trialing",
    tenant_id: str = "tenant-a",
) -> dict[str, object]:
    return {
        "id": "sub_test_a",
        "customer": "cus_test_a",
        "livemode": False,
        "status": status,
        "metadata": {
            "tenant_id": tenant_id,
            "billing_owner_user_id": "user-a",
        },
        "trial_start": int(_START.timestamp()),
        "trial_end": int(_TRIAL_END.timestamp()),
        "cancel_at_period_end": status == "canceled",
        "items": {
            "data": [
                {
                    "price": {"id": price_id},
                    "quantity": 1,
                    "current_period_end": int((_TRIAL_END + timedelta(days=30)).timestamp()),
                }
            ]
        },
    }


def _snapshot(status: BillingStatus) -> SubscriptionSnapshot:
    entitlement_end = _TRIAL_END if status is BillingStatus.TRIALING else _TRIAL_END + timedelta(days=30)
    return SubscriptionSnapshot(
        subscription_id="sub_test_a",
        customer_id="cus_test_a",
        tenant_id="tenant-a",
        billing_owner_user_id="user-a",
        price_id="price_team",
        quantity=1,
        status=status,
        trial_started_at=_START,
        trial_ends_at=_TRIAL_END,
        entitlement_ends_at=entitlement_end,
        cancel_at_period_end=status is BillingStatus.CANCELED,
        livemode=False,
    )


def _subscription_event(event_id: str, *, tenant_id: str = "tenant-a") -> dict[str, object]:
    return {
        "id": event_id,
        "type": "customer.subscription.updated",
        "livemode": False,
        "api_version": "2026-08-27.basil",
        "created": int(time.time()),
        "data": {
            "object": {
                "id": "sub_test_a",
                "customer": "cus_test_a",
                "metadata": {
                    "tenant_id": tenant_id,
                    "billing_owner_user_id": "user-a",
                },
            }
        },
    }


def _invoice_event(event_id: str, event_type: str) -> dict[str, object]:
    return {
        "id": event_id,
        "type": event_type,
        "livemode": False,
        "api_version": "2026-08-27.basil",
        "created": int(time.time()),
        "data": {
            "object": {
                "id": f"in_{event_id}",
                "customer": "cus_test_a",
                "parent": {
                    "subscription_details": {
                        "subscription": "sub_test_a",
                    }
                },
            }
        },
    }


def _fake_client() -> MagicMock:
    client = MagicMock()
    client.v1 = SimpleNamespace(
        prices=SimpleNamespace(retrieve_async=AsyncMock()),
        subscriptions=SimpleNamespace(retrieve_async=AsyncMock()),
        checkout=SimpleNamespace(
            sessions=SimpleNamespace(
                create_async=AsyncMock(),
                retrieve_async=AsyncMock(),
            )
        ),
        billing_portal=SimpleNamespace(sessions=SimpleNamespace(create_async=AsyncMock())),
    )
    return client


class _SignatureClient:
    def construct_event(
        self,
        payload: bytes,
        signature: str | None,
        secret: str,
        tolerance: int,
    ) -> stripe.Event:
        return stripe.Webhook.construct_event(
            payload,
            signature,
            secret,
            tolerance=tolerance,
            api_key="sk_test_signature",
        )


@pytest.mark.asyncio
async def test_settings_fail_closed_when_unconfigured(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "STRIPE_SECRET_KEY",
        "STRIPE_WEBHOOK_SECRET",
        "STRIPE_PRICE_ID",
        "STRIPE_CHECKOUT_SUCCESS_URL",
        "STRIPE_CHECKOUT_CANCEL_URL",
        "STRIPE_PORTAL_RETURN_URL",
        "STRIPE_AUTOMATIC_TAX_ENABLED",
        "STRIPE_TAX_ID_COLLECTION_ENABLED",
        "STRIPE_EXPECTED_LIVEMODE",
        "STRIPE_REQUEST_TIMEOUT_SECONDS",
        "STRIPE_MAX_NETWORK_RETRIES",
        "STRIPE_WEBHOOK_TOLERANCE_SECONDS",
    ):
        monkeypatch.delenv(name, raising=False)
    get_stripe_billing_service.cache_clear()
    with pytest.raises(StripeBillingConfigurationError):
        StripeBillingSettings.from_env()
    app = FastAPI()
    app.include_router(router, prefix="/api")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/billing/offer")
    assert response.status_code == 503
    assert response.json() == {"detail": "Billing is not configured"}
    get_stripe_billing_service.cache_clear()


def test_stripe_tax_settings_are_strict_and_default_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    required = {
        "STRIPE_SECRET_KEY": "sk_test_server",
        "STRIPE_WEBHOOK_SECRET": "whsec_server",
        "STRIPE_PRICE_ID": "price_team",
        "STRIPE_CHECKOUT_SUCCESS_URL": "https://app.example.test/success",
        "STRIPE_CHECKOUT_CANCEL_URL": "https://app.example.test/cancel",
        "STRIPE_PORTAL_RETURN_URL": "https://app.example.test/billing",
    }
    for name, value in required.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("STRIPE_AUTOMATIC_TAX_ENABLED", raising=False)
    assert StripeBillingSettings.from_env().automatic_tax_enabled is True
    monkeypatch.setenv("STRIPE_AUTOMATIC_TAX_ENABLED", "false")
    assert StripeBillingSettings.from_env().automatic_tax_enabled is False
    monkeypatch.setenv("STRIPE_AUTOMATIC_TAX_ENABLED", "1")
    assert StripeBillingSettings.from_env().automatic_tax_enabled is True
    monkeypatch.setenv("STRIPE_AUTOMATIC_TAX_ENABLED", "sometimes")
    with pytest.raises(StripeBillingConfigurationError):
        StripeBillingSettings.from_env()
    monkeypatch.setenv("STRIPE_AUTOMATIC_TAX_ENABLED", "true")
    monkeypatch.delenv("STRIPE_TAX_ID_COLLECTION_ENABLED", raising=False)
    assert StripeBillingSettings.from_env().tax_id_collection_enabled is True
    monkeypatch.setenv("STRIPE_TAX_ID_COLLECTION_ENABLED", "false")
    assert StripeBillingSettings.from_env().tax_id_collection_enabled is False
    monkeypatch.setenv("STRIPE_TAX_ID_COLLECTION_ENABLED", "sometimes")
    with pytest.raises(StripeBillingConfigurationError):
        StripeBillingSettings.from_env()


def test_billing_policy_and_expected_mode_defaults_are_environment_safe(
    monkeypatch: pytest.MonkeyPatch,
    billing_settings: StripeBillingSettings,
) -> None:
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.delenv("VORSYGHTA_BILLING_REQUIRED", raising=False)
    monkeypatch.delenv("STRIPE_EXPECTED_LIVEMODE", raising=False)
    assert billing_required_from_env() is False
    assert expected_stripe_livemode_from_env() is False
    with pytest.raises(StripeBillingConfigurationError, match="mode"):
        replace(
            billing_settings,
            secret_key="sk_live_server",
            expected_livemode=False,
        )

    monkeypatch.setenv("ENVIRONMENT", "production")
    assert billing_required_from_env() is True
    assert expected_stripe_livemode_from_env() is True
    monkeypatch.setenv("VORSYGHTA_BILLING_REQUIRED", "false")
    assert billing_required_from_env() is False
    monkeypatch.setenv("STRIPE_EXPECTED_LIVEMODE", "false")
    with pytest.raises(StripeBillingConfigurationError, match="live mode"):
        expected_stripe_livemode_from_env()

    monkeypatch.setenv("ENVIRONMENT", "staging")
    monkeypatch.delenv("VORSYGHTA_BILLING_REQUIRED", raising=False)
    assert billing_required_from_env() is True
    assert expected_stripe_livemode_from_env() is False


@pytest.mark.parametrize("environment", ["staging", "production"])
@pytest.mark.parametrize(
    "field",
    ["checkout_success_url", "checkout_cancel_url", "portal_return_url"],
)
def test_deployed_environments_reject_loopback_stripe_return_urls(
    billing_settings: StripeBillingSettings,
    environment: str,
    field: str,
) -> None:
    values = {
        "environment": environment,
        "secret_key": "sk_live_server" if environment == "production" else "sk_test_server",
        "expected_livemode": environment == "production",
        field: "https://localhost:3002/stripe-return",
    }
    with pytest.raises(StripeBillingConfigurationError, match="non-loopback HTTPS"):
        replace(billing_settings, **values)


def test_development_allows_loopback_http_stripe_return_urls(
    billing_settings: StripeBillingSettings,
) -> None:
    configured = replace(
        billing_settings,
        environment="development",
        checkout_success_url="http://localhost:3002/start-trial?checkout=success",
        checkout_cancel_url="http://127.0.0.1:3002/start-trial?checkout=canceled",
        portal_return_url="http://[::1]:3002/app/settings/billing",
    )
    assert configured.environment == "development"


def test_environment_loaded_from_env_rejects_staging_localhost(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = {
        "ENVIRONMENT": "staging",
        "STRIPE_EXPECTED_LIVEMODE": "false",
        "STRIPE_SECRET_KEY": "sk_test_server",
        "STRIPE_WEBHOOK_SECRET": "whsec_server",
        "STRIPE_PRICE_ID": "price_team",
        "STRIPE_CHECKOUT_SUCCESS_URL": "https://localhost:3002/success",
        "STRIPE_CHECKOUT_CANCEL_URL": "https://app.example.test/cancel",
        "STRIPE_PORTAL_RETURN_URL": "https://app.example.test/billing",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    with pytest.raises(StripeBillingConfigurationError, match="non-loopback HTTPS"):
        StripeBillingSettings.from_env()


def test_stripe_environment_name_is_validated(billing_settings: StripeBillingSettings) -> None:
    with pytest.raises(StripeBillingConfigurationError, match="environment"):
        replace(billing_settings, environment="prodution")


def test_billing_policy_rejects_unknown_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "prodution")
    with pytest.raises(StripeBillingConfigurationError, match="environment"):
        billing_required_from_env()


@pytest.mark.asyncio
async def test_ready_returns_503_when_database_is_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    import vorsyghta.api.main as api_main

    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("VORSYGHTA_BILLING_REQUIRED", "false")
    monkeypatch.setattr(
        api_main,
        "check_database_health",
        AsyncMock(return_value=DatabaseHealth(healthy=False, message="database unavailable")),
    )
    monkeypatch.setattr(api_main, "_redis_readiness_status", AsyncMock(return_value="ready"))
    transport = httpx.ASGITransport(app=api_main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/ready")
    assert response.status_code == 503
    assert response.json()["status"] == "not_ready"
    assert response.json()["checks"] == {
        "authentication": "configured",
        "billing": "not_required",
        "database": "unavailable",
        "redis": "ready",
    }


@pytest.mark.asyncio
async def test_ready_requires_valid_billing_configuration_when_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import vorsyghta.api.main as api_main

    monkeypatch.setenv("ENVIRONMENT", "staging")
    monkeypatch.setenv("VORSYGHTA_BILLING_REQUIRED", "true")
    monkeypatch.setenv("STRIPE_EXPECTED_LIVEMODE", "false")
    for name in (
        "STRIPE_SECRET_KEY",
        "STRIPE_WEBHOOK_SECRET",
        "STRIPE_PRICE_ID",
        "STRIPE_CHECKOUT_SUCCESS_URL",
        "STRIPE_CHECKOUT_CANCEL_URL",
        "STRIPE_PORTAL_RETURN_URL",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(
        api_main,
        "check_database_health",
        AsyncMock(return_value=DatabaseHealth(healthy=True, message="database ready")),
    )
    monkeypatch.setattr(api_main, "_redis_readiness_status", AsyncMock(return_value="ready"))
    transport = httpx.ASGITransport(app=api_main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/ready")
    assert response.status_code == 503
    assert response.json()["checks"] == {
        "authentication": "configured",
        "billing": "invalid",
        "database": "ready",
        "redis": "ready",
    }


@pytest.mark.asyncio
async def test_ready_is_200_with_aware_timestamp_when_requirements_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import vorsyghta.api.main as api_main

    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("VORSYGHTA_BILLING_REQUIRED", "false")
    monkeypatch.setattr(
        api_main,
        "check_database_health",
        AsyncMock(return_value=DatabaseHealth(healthy=True, message="database ready")),
    )
    monkeypatch.setattr(api_main, "_redis_readiness_status", AsyncMock(return_value="ready"))
    transport = httpx.ASGITransport(app=api_main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/ready")
    payload = response.json()
    assert response.status_code == 200
    assert payload["status"] == "ready"
    assert datetime.fromisoformat(payload["timestamp"].replace("Z", "+00:00")).tzinfo is not None


class _RateLimitRedis:
    def __init__(self) -> None:
        self.counts: dict[str, int] = {}

    def eval(
        self,
        _script: str,
        _key_count: int,
        identity_key: str,
        global_key: str,
        _window: int,
        identity_limit: int,
    ) -> list[int]:
        identity_count = self.counts.get(identity_key, 0) + 1
        self.counts[identity_key] = identity_count
        if identity_count > identity_limit:
            return [identity_count, -1]
        global_count = self.counts.get(global_key, 0) + 1
        self.counts[global_key] = global_count
        return [identity_count, global_count]


@pytest.mark.asyncio
async def test_auth_rate_limit_is_shared_and_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    import vorsyghta.api.routers.auth as auth_module

    store = _RateLimitRedis()
    monkeypatch.setattr(auth_module, "get_redis_client", lambda: store)
    for _ in range(10):
        await auth_module._enforce_auth_rate_limit("login", "user@example.test")

    with pytest.raises(HTTPException) as captured:
        await auth_module._enforce_auth_rate_limit("login", "user@example.test")
    assert captured.value.status_code == 429
    assert captured.value.headers == {"Retry-After": "300"}


@pytest.mark.asyncio
async def test_rejected_identity_does_not_exhaust_global_registration_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import vorsyghta.api.routers.auth as auth_module

    store = _RateLimitRedis()
    monkeypatch.setattr(auth_module, "get_redis_client", lambda: store)
    for _ in range(10):
        try:
            await auth_module._enforce_auth_rate_limit("register", "blocked@example.test")
        except HTTPException:
            pass

    await auth_module._enforce_auth_rate_limit("register", "new@example.test")
    assert store.counts["vorsyghta:{auth:register}:global"] == 4
    assert all("{auth:register}" in key for key in store.counts)


@pytest.mark.asyncio
async def test_auth_rate_limit_fails_closed_when_deployed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import vorsyghta.api.routers.auth as auth_module

    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setattr(auth_module, "get_redis_client", lambda: None)
    with pytest.raises(HTTPException) as captured:
        await auth_module._enforce_auth_rate_limit("register", "user@example.test")
    assert captured.value.status_code == 503


@pytest.mark.asyncio
async def test_registration_creates_isolated_tenants_and_normalizes_email(
    billing_db: AsyncSession,
) -> None:
    from vorsyghta.api.routers.auth import RegisterRequest, register

    first = await register(
        RegisterRequest(
            email="Owner@One.Example.com",
            password="correct-horse-battery",
            organization_name="  First   Organization  ",
        ),
        billing_db,
    )
    second = await register(
        RegisterRequest(
            email="owner@two.example.com",
            password="another-correct-password",
            organization_name="Second Organization",
        ),
        billing_db,
    )
    assert first.tenant_id != second.tenant_id
    users = (await billing_db.execute(select(UserRecord).order_by(UserRecord.email))).scalars().all()
    tenants = (await billing_db.execute(select(TenantRecord).order_by(TenantRecord.name))).scalars().all()
    assert [(user.email, user.role) for user in users] == [
        ("owner@one.example.com", Role.VIEWER.value),
        ("owner@two.example.com", Role.VIEWER.value),
    ]
    assert [tenant.name for tenant in tenants] == ["First Organization", "Second Organization"]


@pytest.mark.asyncio
async def test_duplicate_registration_conflicts_transactionally(
    billing_db: AsyncSession,
) -> None:
    from vorsyghta.api.routers.auth import RegisterRequest, register

    first = RegisterRequest(
        email="duplicate@example.com",
        password="correct-horse-battery",
        organization_name="First Organization",
    )
    duplicate = RegisterRequest(
        email="DUPLICATE@example.com",
        password="different-password-value",
        organization_name="Second Organization",
    )
    await register(first, billing_db)
    with pytest.raises(HTTPException) as captured:
        await register(duplicate, billing_db)
    assert captured.value.status_code == 409
    assert await billing_db.scalar(select(func.count(UserRecord.id))) == 1
    assert await billing_db.scalar(select(func.count(TenantRecord.id))) == 1


@pytest.mark.asyncio
async def test_legacy_mixed_case_email_login_and_registration_conflict(
    billing_db: AsyncSession,
) -> None:
    from vorsyghta.api.routers.auth import RegisterRequest, login, register
    from vorsyghta.security.rbac import get_password_hash

    billing_db.add(TenantRecord(tenant_id="tenant-legacy", name="Legacy", is_active=True))
    billing_db.add(
        UserRecord(
            user_id="user-legacy",
            tenant_id="tenant-legacy",
            email="Legacy.Owner@Example.com",
            hashed_password=get_password_hash("correct-horse-battery"),
            role=Role.VIEWER.value,
            is_active=True,
        )
    )
    await billing_db.commit()
    token = await login(
        SimpleNamespace(username="legacy.owner@example.com", password="correct-horse-battery"),
        billing_db,
    )
    assert token.tenant_id == "tenant-legacy"
    with pytest.raises(HTTPException) as captured:
        await register(
            RegisterRequest(
                email="LEGACY.OWNER@example.com",
                password="another-valid-password",
                organization_name="Duplicate Legacy",
            ),
            billing_db,
        )
    assert captured.value.status_code == 409
    assert "uq_users_email_lower" in {index.name for index in UserRecord.__table__.indexes}


@pytest.mark.asyncio
async def test_concurrent_registration_allows_only_one_email(tmp_path) -> None:
    from vorsyghta.api.routers.auth import RegisterRequest, register

    engine = create_async_engine(
        f"sqlite+aiosqlite:///{tmp_path / 'registration.db'}",
        connect_args={"timeout": 10},
    )
    async with engine.begin() as connection:
        await connection.run_sync(
            lambda sync_connection: Base.metadata.create_all(
                sync_connection,
                tables=[TenantRecord.__table__, UserRecord.__table__],
            )
        )
    factory = async_sessionmaker(engine, expire_on_commit=False)
    request = RegisterRequest(
        email="race@example.com",
        password="correct-horse-battery",
        organization_name="Race Organization",
    )

    async def attempt_registration():
        async with factory() as session:
            try:
                return await register(request, session)
            except HTTPException as exc:
                return exc

    results = await asyncio.gather(attempt_registration(), attempt_registration())
    await engine.dispose()
    assert sum(not isinstance(result, HTTPException) for result in results) == 1
    conflicts = [result for result in results if isinstance(result, HTTPException)]
    assert len(conflicts) == 1 and conflicts[0].status_code == 409


@pytest.mark.asyncio
async def test_login_and_current_user_fail_closed_for_inactive_or_stale_identity(
    billing_db: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from vorsyghta.api.routers.auth import login
    from vorsyghta.security.rbac import get_password_hash

    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("VORSYGHTA_SECRET_KEY", "test-signing-secret-that-is-long-enough")
    tenant = TenantRecord(tenant_id="tenant-current", name="Current Tenant", is_active=True)
    user = UserRecord(
        user_id="user-current",
        tenant_id="tenant-current",
        email="current@example.com",
        hashed_password=get_password_hash("correct-horse-battery"),
        role=Role.ADMIN.value,
        is_active=True,
    )
    billing_db.add_all([tenant, user])
    await billing_db.commit()
    stale_token = create_access_token(
        user_id="user-current",
        tenant_id="stale-tenant",
        role=Role.VIEWER.value,
        email="stale@example.com",
    )
    current = await get_current_user(stale_token, billing_db)
    assert current.tenant_id == "tenant-current"
    assert current.role is Role.ADMIN
    assert current.email == "current@example.com"

    user.is_active = False
    await billing_db.commit()
    with pytest.raises(HTTPException) as current_error:
        await get_current_user(stale_token, billing_db)
    assert current_error.value.status_code == 403
    with pytest.raises(HTTPException) as login_error:
        await login(
            SimpleNamespace(username="CURRENT@example.com", password="correct-horse-battery"),
            billing_db,
        )
    assert login_error.value.status_code == 401


@pytest.mark.asyncio
async def test_identity_database_outage_returns_controlled_503(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from vorsyghta.api.routers.auth import RegisterRequest, login, register

    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("VORSYGHTA_SECRET_KEY", "test-signing-secret-that-is-long-enough")
    outage = MagicMock()
    outage.execute = AsyncMock(side_effect=SQLAlchemyError("database offline"))
    outage.flush = AsyncMock(side_effect=SQLAlchemyError("database offline"))
    outage.rollback = AsyncMock()
    token = create_access_token("user-outage", "stale", Role.ADMIN.value)
    with pytest.raises(HTTPException) as login_error:
        await login(SimpleNamespace(username="user@example.com", password="valid-password"), outage)
    assert login_error.value.status_code == 503
    with pytest.raises(HTTPException) as current_error:
        await get_current_user(token, outage)
    assert current_error.value.status_code == 503
    with pytest.raises(HTTPException) as register_error:
        await register(
            RegisterRequest(
                email="new@example.com",
                password="correct-horse-battery",
                organization_name="Outage Organization",
            ),
            outage,
        )
    assert register_error.value.status_code == 503
    outage.rollback.assert_awaited()


def test_production_rejects_placeholder_signing_secret_and_default_token_is_30_minutes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from vorsyghta.security.rbac import decode_token

    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("VORSYGHTA_SECRET_KEY", "changeme-replace-in-production-with-256bit-secret")
    with pytest.raises(HTTPException) as captured:
        create_access_token("user", "tenant", Role.VIEWER.value)
    assert captured.value.status_code == 503

    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("VORSYGHTA_SECRET_KEY", "test-signing-secret-that-is-long-enough")
    monkeypatch.delenv("ACCESS_TOKEN_EXPIRE_MINUTES", raising=False)
    before = int(time.time())
    payload = decode_token(create_access_token("user", "tenant", Role.VIEWER.value))
    assert payload.exp is not None
    assert 29 * 60 <= payload.exp - before <= 30 * 60


@pytest.mark.parametrize(
    ("billing_status", "end_delta", "tenant_active", "expected"),
    [
        (BillingStatus.TRIALING, timedelta(seconds=1), True, True),
        (BillingStatus.ACTIVE, timedelta(days=30), True, True),
        (BillingStatus.ACTIVE, timedelta(0), True, False),
        (BillingStatus.ACTIVE, timedelta(days=30), False, False),
        (BillingStatus.PAST_DUE, timedelta(days=30), True, False),
        (BillingStatus.CANCELED, timedelta(days=30), True, False),
        (BillingStatus.UNKNOWN, timedelta(days=30), True, False),
    ],
)
def test_entitlement_requires_active_status_and_future_boundary(
    billing_status: BillingStatus,
    end_delta: timedelta,
    tenant_active: bool,
    expected: bool,
) -> None:
    now = datetime(2026, 9, 14, tzinfo=timezone.utc)
    assert (
        subscription_is_entitled(
            billing_status,
            now + end_delta,
            tenant_is_active=tenant_active,
            now=now,
        )
        is expected
    )


@pytest.mark.parametrize(
    ("billing_status", "boundary_delta", "livemode", "expected_status"),
    [
        (BillingStatus.ACTIVE, timedelta(days=1), False, 200),
        (BillingStatus.TRIALING, timedelta(days=1), False, 200),
        (BillingStatus.ACTIVE, timedelta(seconds=-1), False, 403),
        (BillingStatus.CANCELED, timedelta(days=1), False, 403),
        (BillingStatus.UNPAID, timedelta(days=1), False, 403),
        (BillingStatus.ACTIVE, timedelta(days=1), True, 403),
    ],
)
@pytest.mark.asyncio
async def test_runtime_entitlement_dependency_blocks_direct_product_access(
    billing_db: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    billing_status: BillingStatus,
    boundary_delta: timedelta,
    livemode: bool,
    expected_status: int,
) -> None:
    record = await _seed_pending_subscription(billing_db)
    record.status = billing_status.value
    record.stripe_livemode = livemode
    record.entitlement_ends_at = datetime.now(timezone.utc) + boundary_delta
    await billing_db.commit()
    monkeypatch.setenv("VORSYGHTA_BILLING_REQUIRED", "true")
    monkeypatch.setenv("STRIPE_EXPECTED_LIVEMODE", "false")
    app = FastAPI()

    @app.get("/product")
    async def product(user: CurrentUser = Depends(require_entitled_user)) -> dict[str, str]:
        return {"tenant_id": user.tenant_id}

    async def current_user_override() -> CurrentUser:
        return CurrentUser(user_id="user-a", tenant_id="tenant-a", role=Role.ADMIN)

    async def session_override() -> AsyncIterator[AsyncSession]:
        yield billing_db

    app.dependency_overrides[get_current_user] = current_user_override
    app.dependency_overrides[get_session_dep] = session_override
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/product")
    assert response.status_code == expected_status


@pytest.mark.asyncio
async def test_explicit_self_hosted_mode_does_not_require_subscription(
    billing_db: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VORSYGHTA_BILLING_REQUIRED", "false")
    current = CurrentUser(user_id="self-hosted", tenant_id="local", role=Role.ADMIN)
    assert await require_entitled_user(current, billing_db) == current


@pytest.mark.asyncio
async def test_production_self_hosted_status_does_not_require_stripe_mode(
    billing_db: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await _seed_pending_subscription(billing_db)
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("VORSYGHTA_BILLING_REQUIRED", "false")
    monkeypatch.setenv("STRIPE_EXPECTED_LIVEMODE", "false")
    current = CurrentUser(user_id="user-a", tenant_id="tenant-a", role=Role.ADMIN)

    response = await get_billing_status(current, billing_db)

    assert response.billing_required is False


@pytest.mark.asyncio
async def test_billing_status_is_local_and_fails_closed_on_mode_mismatch(
    billing_db: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = await _seed_pending_subscription(billing_db)
    record.status = BillingStatus.ACTIVE.value
    record.entitlement_ends_at = datetime.now(timezone.utc) + timedelta(days=1)
    record.stripe_livemode = True
    await billing_db.commit()
    monkeypatch.setenv("VORSYGHTA_BILLING_REQUIRED", "true")
    monkeypatch.setenv("STRIPE_EXPECTED_LIVEMODE", "false")
    for name in ("STRIPE_SECRET_KEY", "STRIPE_WEBHOOK_SECRET", "STRIPE_PRICE_ID"):
        monkeypatch.delenv(name, raising=False)
    current = CurrentUser(user_id="user-a", tenant_id="tenant-a", role=Role.ADMIN)
    mismatched = await get_billing_status(current, billing_db)
    assert mismatched.entitled is False
    assert mismatched.billing_required is True
    record.stripe_livemode = False
    await billing_db.commit()
    matched = await get_billing_status(current, billing_db)
    assert matched.entitled is True
    assert matched.billing_required is True


@pytest.mark.asyncio
async def test_billing_status_exposes_server_authoritative_recovery_actions(
    billing_db: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = await _seed_pending_subscription(billing_db)
    record.status = BillingStatus.UNKNOWN.value
    record.stripe_customer_id = "cus_test_a"
    record.stripe_subscription_id = "sub_test_a"
    await billing_db.commit()
    monkeypatch.setenv("VORSYGHTA_BILLING_REQUIRED", "true")
    monkeypatch.setenv("STRIPE_EXPECTED_LIVEMODE", "false")
    current = CurrentUser(user_id="user-a", tenant_id="tenant-a", role=Role.ADMIN)

    response = await get_billing_status(current, billing_db)

    assert response.checkout_available is False
    assert response.portal_available is True
    assert response.trial_available is True


def test_product_routes_are_mounted_with_entitlement_and_exemptions_remain_open() -> None:
    from fastapi.routing import APIRoute

    from vorsyghta.api.main import app

    routes = {route.path: route for route in app.routes if isinstance(route, APIRoute)}
    protected_paths = {
        "/api/manuals/list",
        "/api/knowledge/stats",
        "/api/attack-tracking/stats",
        "/api/threat-intel/stats",
        "/scenarios",
        "/simulations/active",
        "/llm/status",
    }
    for path in protected_paths:
        assert any(dependency.call is require_entitled_user for dependency in routes[path].dependant.dependencies)
    exempt_paths = {"/", "/health", "/ready", "/api/auth/register", "/api/billing/status", "/api/billing/webhook"}
    for path in exempt_paths:
        assert all(dependency.call is not require_entitled_user for dependency in routes[path].dependant.dependencies)


def test_attack_tracking_read_endpoints_require_analyst() -> None:
    from vorsyghta.api.routers.attack_tracking import router as attack_router
    from vorsyghta.security.rbac import require_analyst

    protected = {
        "/attack-tracking/sequences",
        "/attack-tracking/sequences/{sequence_id}",
        "/attack-tracking/tool-usage",
        "/attack-tracking/tool-usage/{usage_id}",
    }
    routes = {route.path: route for route in attack_router.routes}
    for path in protected:
        assert any(dependency.call is require_analyst for dependency in routes[path].dependant.dependencies)

    from vorsyghta.security.rbac import require_viewer

    assert any(
        dependency.call is require_viewer
        for dependency in routes["/attack-tracking/stats"].dependant.dependencies
    )


def test_saas_openapi_hides_direct_execution_and_runtime_returns_404(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import vorsyghta.api.main as main_module
    from vorsyghta.api.routers.attack_tracking import require_direct_execution_enabled

    sequence_path = "/api/attack-tracking/sequences/{sequence_id}/execute"
    tool_path = "/api/attack-tracking/tools/execute"
    monkeypatch.setenv("VORSYGHTA_BILLING_REQUIRED", "true")
    main_module.app.openapi_schema = None
    required_schema = main_module.app.openapi()
    assert sequence_path not in required_schema["paths"]
    assert tool_path not in required_schema["paths"]
    assert "/simulations" not in required_schema["paths"]
    assert "/audit/events" not in required_schema["paths"]
    with pytest.raises(HTTPException) as captured:
        require_direct_execution_enabled()
    assert captured.value.status_code == 404
    with pytest.raises(HTTPException) as surface_error:
        main_module.require_self_hosted_surface()
    assert surface_error.value.status_code == 404

    monkeypatch.setenv("VORSYGHTA_BILLING_REQUIRED", "false")
    optional_schema = main_module.app.openapi()
    assert sequence_path in optional_schema["paths"]
    assert tool_path in optional_schema["paths"]
    assert require_direct_execution_enabled() is None


def test_saas_hides_direct_attack_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi import HTTPException

    from vorsyghta.api.routers.attack_tracking import require_direct_execution_enabled

    monkeypatch.setenv("VORSYGHTA_BILLING_REQUIRED", "true")
    with pytest.raises(HTTPException) as captured:
        require_direct_execution_enabled()
    assert captured.value.status_code == 404

    monkeypatch.setenv("VORSYGHTA_BILLING_REQUIRED", "false")
    assert require_direct_execution_enabled() is None


@pytest.mark.asyncio
async def test_checkout_parameters_are_entirely_server_derived(
    billing_settings: StripeBillingSettings,
) -> None:
    client = _fake_client()
    client.v1.checkout.sessions.create_async.return_value = {
        "id": "cs_test_created",
        "url": "https://checkout.stripe.test/session",
        "expires_at": int((_START + timedelta(hours=1)).timestamp()),
        "status": "open",
    }
    original_global_key = stripe.api_key
    service = StripeBillingService(billing_settings, client=client)
    hosted = await service.create_checkout_session(
        tenant_id="tenant-a",
        billing_owner_user_id="user-a",
        billing_owner_email="owner@example.test",
        stripe_customer_id=None,
        checkout_attempt_number=2,
    )
    assert hosted.url == "https://checkout.stripe.test/session"
    assert stripe.api_key is original_global_key
    call = client.v1.checkout.sessions.create_async.await_args
    params = call.kwargs["params"]
    metadata = {
        "tenant_id": "tenant-a",
        "billing_owner_user_id": "user-a",
    }
    assert params == {
        "mode": "subscription",
        "line_items": [{"price": "price_team", "quantity": 1}],
        "payment_method_types": ["card"],
        "payment_method_collection": "always",
        "billing_address_collection": "required",
        "tax_id_collection": {"enabled": True},
        "automatic_tax": {"enabled": True},
        "client_reference_id": "tenant-a",
        "metadata": metadata,
        "subscription_data": {
            "trial_period_days": 14,
            "metadata": metadata,
        },
        "success_url": billing_settings.checkout_success_url,
        "cancel_url": billing_settings.checkout_cancel_url,
        "customer_email": "owner@example.test",
    }
    assert call.kwargs["options"]["idempotency_key"].startswith("vorsyghta-checkout-")
    checkout_route = next(route for route in router.routes if route.path == "/billing/checkout-session")
    portal_route = next(route for route in router.routes if route.path == "/billing/portal-session")
    assert checkout_route.body_field is None
    assert portal_route.body_field is None


@pytest.mark.asyncio
async def test_existing_customer_checkout_updates_tax_address_and_name(
    billing_settings: StripeBillingSettings,
) -> None:
    client = _fake_client()
    client.v1.checkout.sessions.create_async.return_value = {
        "id": "cs_test_existing",
        "url": "https://checkout.stripe.test/existing",
        "status": "open",
    }
    settings = replace(billing_settings, automatic_tax_enabled=False)
    service = StripeBillingService(settings, client=client)
    await service.create_checkout_session(
        tenant_id="tenant-a",
        billing_owner_user_id="user-a",
        billing_owner_email="ignored@example.test",
        stripe_customer_id="cus_test_a",
        checkout_attempt_number=3,
        include_trial=False,
    )
    metadata = {
        "tenant_id": "tenant-a",
        "billing_owner_user_id": "user-a",
    }
    params = client.v1.checkout.sessions.create_async.await_args.kwargs["params"]
    assert params == {
        "mode": "subscription",
        "line_items": [{"price": "price_team", "quantity": 1}],
        "payment_method_types": ["card"],
        "payment_method_collection": "always",
        "billing_address_collection": "required",
        "tax_id_collection": {"enabled": True},
        "automatic_tax": {"enabled": False},
        "client_reference_id": "tenant-a",
        "metadata": metadata,
        "subscription_data": {"metadata": metadata},
        "success_url": settings.checkout_success_url,
        "cancel_url": settings.checkout_cancel_url,
        "customer": "cus_test_a",
        "customer_update": {"address": "auto", "name": "auto"},
    }


@pytest.mark.asyncio
async def test_terminal_subscription_can_resubscribe_without_another_trial(
    billing_db: AsyncSession,
    billing_settings: StripeBillingSettings,
) -> None:
    record = await _seed_pending_subscription(billing_db)
    record.status = BillingStatus.CANCELED.value
    record.stripe_customer_id = "cus_test_a"
    record.stripe_subscription_id = "sub_test_a"
    record.trial_consumed_at = _START
    await billing_db.commit()
    billing = MagicMock()
    billing.settings = billing_settings
    billing.retrieve_subscription = AsyncMock(return_value=_snapshot(BillingStatus.CANCELED))
    billing.create_checkout_session = AsyncMock(
        return_value=HostedSession(
            session_id="cs_resubscribe",
            url="https://checkout.stripe.test/resubscribe",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
    )
    current = CurrentUser(user_id="user-a", tenant_id="tenant-a", role=Role.ADMIN)
    original_trial_consumed = record.trial_consumed_at
    response = await _create_checkout_for_user(billing_db, billing, current)
    assert response.url == "https://checkout.stripe.test/resubscribe"
    assert billing.create_checkout_session.await_args.kwargs["include_trial"] is False
    assert record.trial_consumed_at == original_trial_consumed
    assert record.stripe_subscription_id is None
    assert record.archived_stripe_subscription_id == "sub_test_a"
    assert record.status == BillingStatus.CHECKOUT_PENDING.value


@pytest.mark.asyncio
async def test_resubscription_rejects_non_terminal_stripe_subscription(
    billing_db: AsyncSession,
    billing_settings: StripeBillingSettings,
) -> None:
    record = await _seed_pending_subscription(billing_db)
    record.status = BillingStatus.CANCELED.value
    record.stripe_customer_id = "cus_test_a"
    record.stripe_subscription_id = "sub_test_a"
    record.trial_consumed_at = _START
    await billing_db.commit()
    billing = MagicMock()
    billing.settings = billing_settings
    billing.retrieve_subscription = AsyncMock(return_value=_snapshot(BillingStatus.ACTIVE))
    billing.create_checkout_session = AsyncMock()
    current = CurrentUser(user_id="user-a", tenant_id="tenant-a", role=Role.ADMIN)
    with pytest.raises(HTTPException) as captured:
        await _create_checkout_for_user(billing_db, billing, current)
    assert captured.value.status_code == 409
    billing.create_checkout_session.assert_not_awaited()


@pytest.mark.asyncio
async def test_portal_parameters_use_only_stored_customer_and_server_return_url(
    billing_settings: StripeBillingSettings,
) -> None:
    client = _fake_client()
    client.v1.billing_portal.sessions.create_async.return_value = {
        "id": "bps_test_created",
        "url": "https://billing.stripe.test/session",
    }
    service = StripeBillingService(billing_settings, client=client)
    hosted = await service.create_portal_session("cus_test_a")
    assert hosted.url == "https://billing.stripe.test/session"
    call = client.v1.billing_portal.sessions.create_async.await_args
    assert call.kwargs["params"] == {
        "customer": "cus_test_a",
        "return_url": billing_settings.portal_return_url,
    }


def test_route_authentication_boundaries_are_explicit() -> None:
    app = FastAPI()
    app.include_router(router, prefix="/api")
    paths = app.openapi()["paths"]
    assert paths["/api/billing/offer"]["get"].get("security") is None
    assert paths["/api/billing/webhook"]["post"].get("security") is None
    assert paths["/api/billing/checkout-session"]["post"]["security"]
    assert paths["/api/billing/status"]["get"]["security"]
    assert paths["/api/billing/portal-session"]["post"]["security"]


@pytest.mark.asyncio
async def test_offer_uses_active_stripe_price_without_exposing_ids(
    billing_settings: StripeBillingSettings,
) -> None:
    client = _fake_client()
    client.v1.prices.retrieve_async.return_value = {
        "id": "price_team",
        "active": True,
        "livemode": False,
        "unit_amount": 4900,
        "currency": "gbp",
        "recurring": {"interval": "month", "interval_count": 1},
        "product": {
            "id": "prod_secret_not_public",
            "active": True,
            "name": "Vorsyghta Team",
            "description": "Team subscription",
        },
    }
    offer = await StripeBillingService(billing_settings, client=client).get_offer()
    assert offer.unit_amount == 4900
    assert offer.currency == "gbp"
    assert offer.trial_days == 14
    assert "price" not in offer.__dict__
    assert "product_id" not in offer.__dict__


@pytest.mark.asyncio
async def test_offer_cache_is_locked_and_expires_after_bounded_ttl(
    billing_settings: StripeBillingSettings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import vorsyghta.integrations.stripe_billing as stripe_billing_module

    client = _fake_client()
    price = {
        "id": "price_team",
        "active": True,
        "livemode": False,
        "unit_amount": 4900,
        "currency": "gbp",
        "recurring": {"interval": "month", "interval_count": 1},
        "product": {"active": True, "name": "Vorsyghta Team"},
    }

    async def retrieve_price(*_args, **_kwargs):
        await asyncio.sleep(0.01)
        return price

    clock = {"value": 100.0}
    monkeypatch.setattr(stripe_billing_module, "monotonic", lambda: clock["value"])
    client.v1.prices.retrieve_async.side_effect = retrieve_price
    service = StripeBillingService(billing_settings, client=client)
    offers = await asyncio.gather(*(service.get_offer() for _ in range(10)))
    assert all(offer.unit_amount == 4900 for offer in offers)
    assert client.v1.prices.retrieve_async.await_count == 1
    clock["value"] = 161.0
    await service.get_offer()
    assert client.v1.prices.retrieve_async.await_count == 2


@pytest.mark.parametrize("product_active", [False, None])
@pytest.mark.asyncio
async def test_offer_requires_product_active_to_be_exactly_true(
    billing_settings: StripeBillingSettings,
    product_active: bool | None,
) -> None:
    client = _fake_client()
    client.v1.prices.retrieve_async.return_value = {
        "id": "price_team",
        "active": True,
        "livemode": False,
        "unit_amount": 4900,
        "currency": "gbp",
        "recurring": {"interval": "month", "interval_count": 1},
        "product": {
            "active": product_active,
            "name": "Vorsyghta Team",
        },
    }
    service = StripeBillingService(billing_settings, client=client)
    with pytest.raises(StripeBillingValidationError, match="inactive"):
        await service.get_offer()


@pytest.mark.asyncio
async def test_provider_exception_details_are_not_exposed(
    billing_settings: StripeBillingSettings,
) -> None:
    client = _fake_client()
    client.v1.prices.retrieve_async.side_effect = stripe.APIConnectionError("upstream detail that must remain private")
    service = StripeBillingService(billing_settings, client=client)
    with pytest.raises(StripeBillingProviderError) as captured:
        await service.get_offer()
    assert str(captured.value) == "Stripe is unavailable"
    assert "upstream detail" not in str(captured.value)


def test_webhook_signature_is_verified_and_mode_is_enforced(
    billing_settings: StripeBillingSettings,
) -> None:
    service = StripeBillingService(billing_settings, client=_SignatureClient())
    event = {
        "id": "evt_signature",
        "object": "event",
        "type": "customer.subscription.updated",
        "livemode": False,
        "data": {"object": {"id": "sub_test_a"}},
    }
    payload = json.dumps(event, separators=(",", ":")).encode()
    signature = stripe.WebhookSignature.generate_signature_header(
        payload.decode(),
        billing_settings.webhook_secret,
    )
    assert service.verify_webhook(payload, signature)["id"] == "evt_signature"
    with pytest.raises(StripeWebhookSignatureError):
        service.verify_webhook(payload, "t=1,v1=invalid")
    event["livemode"] = True
    live_payload = json.dumps(event, separators=(",", ":")).encode()
    live_signature = stripe.WebhookSignature.generate_signature_header(
        live_payload.decode(),
        billing_settings.webhook_secret,
    )
    with pytest.raises(StripeBillingValidationError, match="mode"):
        service.verify_webhook(live_payload, live_signature)


@pytest.mark.asyncio
async def test_webhook_endpoint_returns_controlled_signature_error(
    billing_settings: StripeBillingSettings,
) -> None:
    app = FastAPI()
    app.include_router(router, prefix="/api")
    fake_session = MagicMock()
    fake_session.rollback = AsyncMock()

    async def session_override() -> AsyncIterator[MagicMock]:
        yield fake_session

    service = StripeBillingService(billing_settings, client=_SignatureClient())
    app.dependency_overrides[get_session_dep] = session_override
    app.dependency_overrides[get_billing_service_dep] = lambda: service
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/billing/webhook",
            content=b"{}",
            headers={"stripe-signature": "invalid"},
        )
    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid Stripe webhook signature"}
    fake_session.rollback.assert_awaited_once()


@pytest.mark.asyncio
async def test_duplicate_event_is_a_successful_no_op_and_activation_then_cancellation_apply(
    billing_db: AsyncSession,
) -> None:
    await _seed_pending_subscription(billing_db)
    billing = MagicMock()
    billing.retrieve_subscription = AsyncMock(return_value=_snapshot(BillingStatus.TRIALING))
    activation = _subscription_event("evt_activation")
    first = await _process_webhook_event(billing_db, billing, activation)
    await billing_db.commit()
    assert first.outcome == "processed"
    record = await _load_subscription(billing_db)
    assert record.status == BillingStatus.TRIALING.value
    assert record.trial_consumed_at == _START.replace(tzinfo=None)

    duplicate = await _process_webhook_event(billing_db, billing, activation)
    await billing_db.commit()
    assert duplicate.duplicate is True
    assert billing.retrieve_subscription.await_count == 1
    event_count = await billing_db.scalar(select(func.count(StripeWebhookEventRecord.id)))
    assert event_count == 1

    billing.retrieve_subscription.return_value = _snapshot(BillingStatus.CANCELED)
    cancellation = _subscription_event("evt_cancellation")
    cancellation["type"] = "customer.subscription.deleted"
    canceled = await _process_webhook_event(billing_db, billing, cancellation)
    await billing_db.commit()
    assert canceled.outcome == "processed"
    record = await _load_subscription(billing_db)
    assert record.status == BillingStatus.CANCELED.value
    assert record.cancel_at_period_end is True
    assert (
        subscription_is_entitled(
            record.status,
            record.entitlement_ends_at,
            now=_TRIAL_END,
        )
        is False
    )


@pytest.mark.asyncio
async def test_resubscription_webhook_replaces_terminal_binding_without_resetting_trial(
    billing_db: AsyncSession,
) -> None:
    record = await _seed_pending_subscription(billing_db)
    record.stripe_customer_id = "cus_test_a"
    record.stripe_subscription_id = None
    record.archived_stripe_subscription_id = "sub_old"
    record.trial_consumed_at = _START
    await billing_db.commit()
    replacement = replace(
        _snapshot(BillingStatus.ACTIVE),
        subscription_id="sub_new",
        trial_started_at=None,
        trial_ends_at=None,
    )
    billing = MagicMock()
    billing.retrieve_subscription = AsyncMock(return_value=replacement)
    billing.retrieve_checkout_session = AsyncMock(
        return_value=CheckoutSnapshot(
            session_id="cs_test_a",
            tenant_id="tenant-a",
            billing_owner_user_id="user-a",
            price_id="price_team",
            quantity=1,
            mode="subscription",
            status="complete",
            livemode=False,
            customer_id="cus_test_a",
            subscription_id="sub_new",
            expires_at=datetime.now(timezone.utc),
            url=None,
        )
    )
    event_payload = {
        "id": "evt_replacement",
        "type": "checkout.session.completed",
        "livemode": False,
        "created": int(time.time()),
        "data": {
            "object": {
                "id": "cs_test_a",
                "mode": "subscription",
                "client_reference_id": "tenant-a",
                "metadata": {
                    "tenant_id": "tenant-a",
                    "billing_owner_user_id": "user-a",
                },
            }
        },
    }
    result = await _process_webhook_event(billing_db, billing, event_payload)
    await billing_db.commit()
    assert result.outcome == "processed"
    assert record.stripe_subscription_id == "sub_new"
    assert record.status == BillingStatus.ACTIVE.value
    assert record.trial_consumed_at == _START
    billing.retrieve_subscription.assert_awaited_once_with("sub_new", allow_no_trial=True)


@pytest.mark.asyncio
async def test_expired_replacement_checkout_preserves_archive_and_trial_history(
    billing_db: AsyncSession,
) -> None:
    record = await _seed_pending_subscription(billing_db)
    record.stripe_customer_id = "cus_test_a"
    record.stripe_subscription_id = None
    record.archived_stripe_subscription_id = "sub_old"
    record.trial_consumed_at = _START
    await billing_db.commit()
    billing = MagicMock()
    billing.retrieve_checkout_session = AsyncMock(
        return_value=CheckoutSnapshot(
            session_id="cs_test_a",
            tenant_id="tenant-a",
            billing_owner_user_id="user-a",
            price_id="price_team",
            quantity=1,
            mode="subscription",
            status="expired",
            livemode=False,
            customer_id="cus_test_a",
            subscription_id=None,
            expires_at=datetime.now(timezone.utc),
            url=None,
        )
    )
    event_payload = {
        "id": "evt_replacement_expired",
        "type": "checkout.session.expired",
        "livemode": False,
        "created": int(time.time()),
        "data": {
            "object": {
                "id": "cs_test_a",
                "mode": "subscription",
                "client_reference_id": "tenant-a",
                "metadata": {
                    "tenant_id": "tenant-a",
                    "billing_owner_user_id": "user-a",
                },
            }
        },
    }
    result = await _process_webhook_event(billing_db, billing, event_payload)
    await billing_db.commit()
    assert result.outcome == "processed"
    assert record.status == BillingStatus.INCOMPLETE_EXPIRED.value
    assert record.stripe_checkout_session_id is None
    assert record.archived_stripe_subscription_id == "sub_old"
    assert record.trial_consumed_at == _START


@pytest.mark.asyncio
async def test_late_old_subscription_event_cannot_overwrite_pending_replacement(
    billing_db: AsyncSession,
) -> None:
    record = await _seed_pending_subscription(billing_db)
    record.stripe_customer_id = "cus_test_a"
    record.stripe_subscription_id = None
    record.archived_stripe_subscription_id = "sub_old"
    record.trial_consumed_at = _START
    await billing_db.commit()
    billing = MagicMock()
    billing.retrieve_subscription = AsyncMock()
    old_event = _subscription_event("evt_late_old")
    old_event["data"]["object"]["id"] = "sub_old"
    result = await _process_webhook_event(billing_db, billing, old_event)
    await billing_db.commit()
    assert result.outcome == "ignored"
    assert record.status == BillingStatus.CHECKOUT_PENDING.value
    assert record.stripe_checkout_session_id == "cs_test_a"
    assert record.stripe_subscription_id is None
    billing.retrieve_subscription.assert_not_awaited()


@pytest.mark.asyncio
async def test_expired_replacement_checkout_can_retry_without_trial(
    billing_db: AsyncSession,
    billing_settings: StripeBillingSettings,
) -> None:
    record = await _seed_pending_subscription(billing_db)
    record.status = BillingStatus.INCOMPLETE_EXPIRED.value
    record.stripe_customer_id = "cus_test_a"
    record.stripe_subscription_id = None
    record.archived_stripe_subscription_id = "sub_old"
    record.stripe_checkout_session_id = None
    record.checkout_expires_at = None
    record.trial_consumed_at = _START
    await billing_db.commit()
    billing = MagicMock()
    billing.settings = billing_settings
    billing.create_checkout_session = AsyncMock(
        return_value=HostedSession(
            session_id="cs_retry",
            url="https://checkout.stripe.test/retry",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
    )
    current = CurrentUser(user_id="user-a", tenant_id="tenant-a", role=Role.ADMIN)
    response = await _create_checkout_for_user(billing_db, billing, current)
    assert response.url == "https://checkout.stripe.test/retry"
    assert billing.create_checkout_session.await_args.kwargs["include_trial"] is False
    assert record.stripe_checkout_session_id == "cs_retry"
    assert record.archived_stripe_subscription_id == "sub_old"
    assert record.trial_consumed_at == _START


@pytest.mark.asyncio
async def test_invalid_bound_subscription_revokes_entitlement_and_records_rejection(
    billing_db: AsyncSession,
) -> None:
    record = await _seed_pending_subscription(billing_db)
    record.status = BillingStatus.ACTIVE.value
    record.stripe_customer_id = "cus_test_a"
    record.stripe_subscription_id = "sub_test_a"
    record.entitlement_ends_at = datetime.now(timezone.utc) + timedelta(days=30)
    await billing_db.commit()
    billing = MagicMock()
    billing.retrieve_subscription = AsyncMock(
        side_effect=StripeBillingValidationError("Subscription price validation failed")
    )
    result = await _process_webhook_event(
        billing_db,
        billing,
        _subscription_event("evt_invalid_bound"),
    )
    await billing_db.commit()
    assert result.outcome == "rejected"
    assert record.status == BillingStatus.UNKNOWN.value
    assert record.entitlement_ends_at is None
    receipt = await billing_db.scalar(
        select(StripeWebhookEventRecord).where(StripeWebhookEventRecord.stripe_event_id == "evt_invalid_bound")
    )
    assert receipt is not None
    assert receipt.outcome == "rejected"
    assert receipt.reason == "subscription_validation_failed"


@pytest.mark.asyncio
async def test_subscription_row_lock_precedes_current_stripe_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import vorsyghta.api.routers.billing as billing_router_module
    from sqlalchemy.dialects import postgresql

    order: list[str] = []
    record = TenantSubscriptionRecord(
        tenant_id="tenant-a",
        billing_owner_user_id="user-a",
        status=BillingStatus.CHECKOUT_PENDING.value,
        stripe_price_id="price_team",
        stripe_livemode=False,
        checkout_attempt_number=1,
    )

    tenant = TenantRecord(tenant_id="tenant-a", name="Tenant A", is_active=True)

    class Result:
        def __init__(self, value):
            self.value = value

        def scalar_one_or_none(self):
            return self.value

    class Session:
        async def execute(self, statement):
            compiled = str(statement.compile(dialect=postgresql.dialect()))
            assert "FOR UPDATE" in compiled
            if "FROM tenants" in compiled:
                order.append("tenant_lock")
                return Result(tenant)
            order.append("subscription_lock")
            return Result(record)

    async def retrieve_subscription(_subscription_id: str, **_kwargs):
        assert order == ["tenant_lock", "subscription_lock"]
        order.append("stripe_snapshot")
        return _snapshot(BillingStatus.TRIALING)

    async def apply_snapshot(_session, _snapshot_value, **_kwargs):
        order.append("apply")
        return SimpleNamespace(outcome="processed")

    billing = MagicMock()
    billing.retrieve_subscription = AsyncMock(side_effect=retrieve_subscription)
    monkeypatch.setattr(billing_router_module, "_apply_subscription_snapshot", apply_snapshot)
    reconciliation = await _reconcile_event(
        Session(),
        billing,
        "customer.subscription.updated",
        _subscription_event("evt_same_second")["data"]["object"],
    )
    assert reconciliation.outcome == "processed"
    assert order == ["tenant_lock", "subscription_lock", "stripe_snapshot", "apply"]


@pytest.mark.asyncio
async def test_wrong_tenant_event_is_rejected_without_persistence(
    billing_db: AsyncSession,
) -> None:
    await _seed_pending_subscription(billing_db)
    billing = MagicMock()
    billing.retrieve_subscription = AsyncMock(return_value=_snapshot(BillingStatus.TRIALING))
    with pytest.raises(StripeBillingValidationError, match="tenant"):
        await _process_webhook_event(
            billing_db,
            billing,
            _subscription_event("evt_wrong_tenant", tenant_id="tenant-b"),
        )
    await billing_db.rollback()
    event_count = await billing_db.scalar(select(func.count(StripeWebhookEventRecord.id)))
    assert event_count == 0
    record = await _load_subscription(billing_db)
    assert record.status == BillingStatus.CHECKOUT_PENDING.value


@pytest.mark.parametrize(
    "event_type",
    [
        "invoice.paid",
        "invoice.payment_succeeded",
        "invoice.payment_failed",
        "invoice.payment_action_required",
        "invoice.finalization_failed",
    ],
)
@pytest.mark.asyncio
async def test_supported_invoice_events_reconcile_only_from_current_subscription(
    billing_db: AsyncSession,
    event_type: str,
) -> None:
    record = await _seed_pending_subscription(billing_db)
    record.stripe_customer_id = "cus_test_a"
    record.stripe_subscription_id = "sub_test_a"
    await billing_db.commit()
    billing = MagicMock()
    billing.retrieve_subscription = AsyncMock(return_value=_snapshot(BillingStatus.PAST_DUE))
    result = await _process_webhook_event(
        billing_db,
        billing,
        _invoice_event(f"evt_{event_type.replace('.', '_')}", event_type),
    )
    await billing_db.commit()
    assert result.outcome == "processed"
    billing.retrieve_subscription.assert_awaited_once_with(
        "sub_test_a",
        allow_no_trial=False,
    )
    record = await _load_subscription(billing_db)
    assert record.status == BillingStatus.PAST_DUE.value
    assert subscription_is_entitled(record.status, record.entitlement_ends_at, now=_START) is False


@pytest.mark.asyncio
async def test_unknown_current_checkout_status_cannot_create_a_replacement_session(
    billing_settings: StripeBillingSettings,
) -> None:
    client = _fake_client()
    client.v1.checkout.sessions.retrieve_async.return_value = {
        "id": "cs_test_a",
        "mode": "subscription",
        "status": "unexpected",
        "livemode": False,
        "metadata": {
            "tenant_id": "tenant-a",
            "billing_owner_user_id": "user-a",
        },
        "line_items": {"data": [{"price": "price_team", "quantity": 1}]},
        "expires_at": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
        "url": "https://checkout.stripe.test/session",
    }
    billing = StripeBillingService(billing_settings, client=client)
    record = TenantSubscriptionRecord(
        tenant_id="tenant-a",
        billing_owner_user_id="user-a",
        status=BillingStatus.CHECKOUT_PENDING.value,
        stripe_checkout_session_id="cs_test_a",
        stripe_price_id="price_team",
        stripe_livemode=False,
        checkout_attempt_number=1,
        checkout_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    current_user = CurrentUser(user_id="user-a", tenant_id="tenant-a", role="admin")
    with pytest.raises(StripeBillingValidationError, match="status"):
        await _reuse_pending_checkout(billing, record, current_user)
    client.v1.checkout.sessions.create_async.assert_not_awaited()


@pytest.mark.asyncio
async def test_locally_expired_checkout_reconciles_stripe_before_replacement(
    billing_settings: StripeBillingSettings,
) -> None:
    client = _fake_client()
    client.v1.checkout.sessions.retrieve_async.return_value = {
        "id": "cs_test_a",
        "mode": "subscription",
        "status": "complete",
        "livemode": False,
        "metadata": {
            "tenant_id": "tenant-a",
            "billing_owner_user_id": "user-a",
        },
        "line_items": {"data": [{"price": "price_team", "quantity": 1}]},
        "customer": "cus_test_a",
        "subscription": "sub_test_a",
        "expires_at": int((datetime.now(timezone.utc) - timedelta(minutes=1)).timestamp()),
    }
    billing = StripeBillingService(billing_settings, client=client)
    record = TenantSubscriptionRecord(
        tenant_id="tenant-a",
        billing_owner_user_id="user-a",
        status=BillingStatus.CHECKOUT_PENDING.value,
        stripe_checkout_session_id="cs_test_a",
        stripe_price_id="price_team",
        stripe_livemode=False,
        checkout_attempt_number=1,
        checkout_expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
    )
    current_user = CurrentUser(user_id="user-a", tenant_id="tenant-a", role="admin")

    with pytest.raises(HTTPException) as captured:
        await _reuse_pending_checkout(billing, record, current_user)

    assert captured.value.status_code == 409
    client.v1.checkout.sessions.retrieve_async.assert_awaited_once()
    client.v1.checkout.sessions.create_async.assert_not_awaited()


@pytest.mark.asyncio
async def test_wrong_price_and_checkout_mode_are_rejected(
    billing_settings: StripeBillingSettings,
) -> None:
    client = _fake_client()
    client.v1.subscriptions.retrieve_async.return_value = _subscription_payload(price_id="price_other")
    service = StripeBillingService(billing_settings, client=client)
    with pytest.raises(StripeBillingValidationError, match="price"):
        await service.retrieve_subscription("sub_test_a")

    client.v1.checkout.sessions.retrieve_async.return_value = {
        "id": "cs_test_a",
        "mode": "payment",
        "status": "complete",
        "livemode": False,
        "metadata": {
            "tenant_id": "tenant-a",
            "billing_owner_user_id": "user-a",
        },
        "line_items": {"data": [{"price": "price_team", "quantity": 1}]},
    }
    with pytest.raises(StripeBillingValidationError, match="mode"):
        await service.retrieve_checkout_session(
            "cs_test_a",
            tenant_id="tenant-a",
            billing_owner_user_id="user-a",
        )


@pytest.mark.asyncio
async def test_card_data_and_raw_webhook_payload_are_never_persisted(
    billing_db: AsyncSession,
) -> None:
    event = {
        "id": "evt_card",
        "type": "payment_method.attached",
        "livemode": False,
        "created": int(time.time()),
        "data": {
            "object": {
                "id": "pm_test_a",
                "card": {
                    "number": "4242424242424242",
                    "cvc": "123",
                },
            }
        },
    }
    result = await _process_webhook_event(billing_db, MagicMock(), event)
    await billing_db.commit()
    assert result.outcome == "ignored"
    receipt = await billing_db.scalar(select(StripeWebhookEventRecord))
    assert receipt is not None
    assert receipt.stripe_object_id == "pm_test_a"
    column_names = set(StripeWebhookEventRecord.__table__.columns.keys())
    subscription_columns = set(TenantSubscriptionRecord.__table__.columns.keys())
    assert "raw_payload" not in column_names
    assert all("card" not in name for name in column_names)
    assert all("card" not in name for name in subscription_columns)
    assert "4242424242424242" not in repr(vars(receipt))
    assert "123" not in repr(vars(receipt))


@pytest.mark.asyncio
async def test_billing_owner_must_belong_to_subscription_tenant(
    billing_db: AsyncSession,
) -> None:
    await _seed_pending_subscription(billing_db)
    billing_db.add(TenantRecord(tenant_id="tenant-b", name="Tenant B", is_active=True))
    await billing_db.commit()
    billing_db.add(
        TenantSubscriptionRecord(
            tenant_id="tenant-b",
            billing_owner_user_id="user-a",
            status=BillingStatus.CHECKOUT_PENDING.value,
            stripe_price_id="price_team",
            stripe_livemode=False,
            checkout_attempt_number=1,
        )
    )
    with pytest.raises(IntegrityError):
        await billing_db.commit()
    await billing_db.rollback()
    owner_constraint = next(
        constraint
        for constraint in TenantSubscriptionRecord.__table__.foreign_key_constraints
        if constraint.name == "fk_tenant_subscriptions_owner_tenant"
    )
    assert [column.name for column in owner_constraint.columns] == [
        "billing_owner_user_id",
        "tenant_id",
    ]


async def _load_subscription(session: AsyncSession) -> TenantSubscriptionRecord:
    record = await session.scalar(
        select(TenantSubscriptionRecord).where(TenantSubscriptionRecord.tenant_id == "tenant-a")
    )
    assert record is not None
    return record
