"""Create Stripe billing projection and webhook inbox tables.

Revision ID: 004_stripe_billing
Revises: 003_persistence_layer
Create Date: 2026-09-14

The lower(email) unique index intentionally fails the migration transaction if
historical users differ only by email case. Operators must resolve those
case-colliding identities before retrying the migration; no record is chosen or
deleted automatically.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "004_stripe_billing"
down_revision: Union[str, None] = "003_persistence_layer"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_BILLING_STATUSES = (
    "checkout_pending",
    "trialing",
    "active",
    "incomplete",
    "incomplete_expired",
    "past_due",
    "unpaid",
    "paused",
    "canceled",
    "unknown",
)
_STATUS_SQL = ", ".join(f"'{status}'" for status in _BILLING_STATUSES)


def upgrade() -> None:
    """Create the tenant billing projection and sanitized event inbox."""
    op.create_index(
        "uq_users_email_lower",
        "users",
        [sa.text("lower(email)")],
        unique=True,
    )
    op.create_unique_constraint(
        "uq_users_user_id_tenant_id",
        "users",
        ["user_id", "tenant_id"],
    )
    op.create_table(
        "tenant_subscriptions",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("billing_owner_user_id", sa.String(), nullable=False),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
            server_default="checkout_pending",
        ),
        sa.Column("stripe_customer_id", sa.String(length=255), nullable=True),
        sa.Column("stripe_subscription_id", sa.String(length=255), nullable=True),
        sa.Column("archived_stripe_subscription_id", sa.String(length=255), nullable=True),
        sa.Column("stripe_checkout_session_id", sa.String(length=255), nullable=True),
        sa.Column("stripe_price_id", sa.String(length=255), nullable=False),
        sa.Column("stripe_livemode", sa.Boolean(), nullable=False),
        sa.Column(
            "checkout_attempt_number",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.Column("checkout_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("trial_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("trial_ends_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("trial_consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("entitlement_ends_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "cancel_at_period_end",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.CheckConstraint(
            f"status IN ({_STATUS_SQL})",
            name="ck_tenant_subscriptions_status",
        ),
        sa.CheckConstraint(
            "checkout_attempt_number >= 0",
            name="ck_tenant_subscriptions_checkout_attempt_number",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.tenant_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["billing_owner_user_id", "tenant_id"],
            ["users.user_id", "users.tenant_id"],
            name="fk_tenant_subscriptions_owner_tenant",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            name="uq_tenant_subscriptions_tenant_id",
        ),
        sa.UniqueConstraint(
            "stripe_customer_id",
            name="uq_tenant_subscriptions_stripe_customer_id",
        ),
        sa.UniqueConstraint(
            "stripe_subscription_id",
            name="uq_tenant_subscriptions_stripe_subscription_id",
        ),
        sa.UniqueConstraint(
            "stripe_checkout_session_id",
            name="uq_tenant_subscriptions_stripe_checkout_session_id",
        ),
    )
    op.create_index(
        "ix_tenant_subscriptions_billing_owner_user_id",
        "tenant_subscriptions",
        ["billing_owner_user_id"],
    )

    op.create_table(
        "stripe_webhook_events",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("stripe_event_id", sa.String(length=255), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=True),
        sa.Column("event_type", sa.String(length=255), nullable=False),
        sa.Column("stripe_object_id", sa.String(length=255), nullable=True),
        sa.Column("livemode", sa.Boolean(), nullable=False),
        sa.Column("api_version", sa.String(length=64), nullable=True),
        sa.Column("outcome", sa.String(length=32), nullable=False),
        sa.Column("reason", sa.String(length=255), nullable=True),
        sa.Column("previous_status", sa.String(length=32), nullable=True),
        sa.Column("resulting_status", sa.String(length=32), nullable=True),
        sa.Column("stripe_created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "processed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.current_timestamp(),
        ),
        sa.CheckConstraint(
            "outcome IN ('processed', 'ignored', 'rejected')",
            name="ck_stripe_webhook_events_outcome",
        ),
        sa.CheckConstraint(
            f"previous_status IS NULL OR previous_status IN ({_STATUS_SQL})",
            name="ck_stripe_webhook_events_previous_status",
        ),
        sa.CheckConstraint(
            f"resulting_status IS NULL OR resulting_status IN ({_STATUS_SQL})",
            name="ck_stripe_webhook_events_resulting_status",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.tenant_id"],
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint(
            "stripe_event_id",
            name="uq_stripe_webhook_events_event_id",
        ),
    )
    op.create_index(
        "ix_stripe_webhook_events_tenant_id",
        "stripe_webhook_events",
        ["tenant_id"],
    )


def downgrade() -> None:
    """Drop billing tables in reverse dependency order."""
    op.drop_index(
        "ix_stripe_webhook_events_tenant_id",
        table_name="stripe_webhook_events",
    )
    op.drop_table("stripe_webhook_events")
    op.drop_index(
        "ix_tenant_subscriptions_billing_owner_user_id",
        table_name="tenant_subscriptions",
    )
    op.drop_table("tenant_subscriptions")
    op.drop_constraint(
        "uq_users_user_id_tenant_id",
        "users",
        type_="unique",
    )
    op.drop_index("uq_users_email_lower", table_name="users")
