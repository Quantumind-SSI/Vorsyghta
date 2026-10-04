"""SQLAlchemy models for the Stripe billing projection and webhook inbox."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    false,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from vorsyghta.db.base import Base

if TYPE_CHECKING:
    from vorsyghta.db.models.auth import TenantRecord, UserRecord


class BillingStatus(str, Enum):
    """Fail-closed local subscription states, including Stripe's states."""

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


_STATUS_SQL = ", ".join(f"'{status.value}'" for status in BillingStatus)


class TenantSubscriptionRecord(Base):
    """Current Stripe-controlled billing projection for one tenant."""

    __tablename__ = "tenant_subscriptions"
    __table_args__ = (
        UniqueConstraint("tenant_id", name="uq_tenant_subscriptions_tenant_id"),
        UniqueConstraint(
            "stripe_customer_id",
            name="uq_tenant_subscriptions_stripe_customer_id",
        ),
        UniqueConstraint(
            "stripe_subscription_id",
            name="uq_tenant_subscriptions_stripe_subscription_id",
        ),
        UniqueConstraint(
            "stripe_checkout_session_id",
            name="uq_tenant_subscriptions_stripe_checkout_session_id",
        ),
        CheckConstraint(
            f"status IN ({_STATUS_SQL})",
            name="ck_tenant_subscriptions_status",
        ),
        CheckConstraint(
            "checkout_attempt_number >= 0",
            name="ck_tenant_subscriptions_checkout_attempt_number",
        ),
        Index(
            "ix_tenant_subscriptions_billing_owner_user_id",
            "billing_owner_user_id",
        ),
        ForeignKeyConstraint(
            ["billing_owner_user_id", "tenant_id"],
            ["users.user_id", "users.tenant_id"],
            name="fk_tenant_subscriptions_owner_tenant",
            ondelete="RESTRICT",
        ),
    )

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid4()))
    tenant_id: Mapped[str] = mapped_column(
        String,
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
        nullable=False,
    )
    billing_owner_user_id: Mapped[str] = mapped_column(
        String,
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=BillingStatus.CHECKOUT_PENDING.value,
        server_default=BillingStatus.CHECKOUT_PENDING.value,
    )
    stripe_customer_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    stripe_subscription_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    archived_stripe_subscription_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    stripe_checkout_session_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    stripe_price_id: Mapped[str] = mapped_column(String(255), nullable=False)
    stripe_livemode: Mapped[bool] = mapped_column(Boolean, nullable=False)
    checkout_attempt_number: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )
    checkout_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    trial_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    trial_ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    trial_consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    entitlement_ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cancel_at_period_end: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=false(),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    tenant: Mapped[TenantRecord] = relationship("TenantRecord", lazy="select", foreign_keys=[tenant_id])
    billing_owner: Mapped[UserRecord] = relationship(
        "UserRecord",
        lazy="select",
        foreign_keys=[billing_owner_user_id, tenant_id],
        overlaps="tenant",
    )


class StripeWebhookEventRecord(Base):
    """Sanitized, idempotent receipt for one verified Stripe event."""

    __tablename__ = "stripe_webhook_events"
    __table_args__ = (
        UniqueConstraint("stripe_event_id", name="uq_stripe_webhook_events_event_id"),
        CheckConstraint(
            "outcome IN ('processed', 'ignored', 'rejected')",
            name="ck_stripe_webhook_events_outcome",
        ),
        CheckConstraint(
            f"previous_status IS NULL OR previous_status IN ({_STATUS_SQL})",
            name="ck_stripe_webhook_events_previous_status",
        ),
        CheckConstraint(
            f"resulting_status IS NULL OR resulting_status IN ({_STATUS_SQL})",
            name="ck_stripe_webhook_events_resulting_status",
        ),
        Index("ix_stripe_webhook_events_tenant_id", "tenant_id"),
    )

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid4()))
    stripe_event_id: Mapped[str] = mapped_column(String(255), nullable=False)
    tenant_id: Mapped[str | None] = mapped_column(
        String,
        ForeignKey("tenants.tenant_id", ondelete="SET NULL"),
        nullable=True,
    )
    event_type: Mapped[str] = mapped_column(String(255), nullable=False)
    stripe_object_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    livemode: Mapped[bool] = mapped_column(Boolean, nullable=False)
    api_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    previous_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    resulting_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    stripe_created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    processed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    tenant: Mapped[TenantRecord | None] = relationship(
        "TenantRecord",
        lazy="select",
        foreign_keys=[tenant_id],
    )


__all__ = ["BillingStatus", "StripeWebhookEventRecord", "TenantSubscriptionRecord"]
