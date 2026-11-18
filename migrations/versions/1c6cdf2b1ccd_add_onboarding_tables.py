"""add onboarding tables

Revision ID: 1c6cdf2b1ccd
Revises: 3354c2cf620c
Create Date: 2026-11-08 13:50:47.640229

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '1c6cdf2b1ccd'
down_revision: Union[str, None] = '3354c2cf620c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "onboarding_profiles",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("industry", sa.String(length=80), nullable=False),
        sa.Column("company_size", sa.String(length=16), nullable=False),
        sa.Column("regions", sa.String(length=160), nullable=False),
        sa.Column("security_maturity", sa.String(length=32), nullable=False),
        sa.Column("compliance_frameworks", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_onboarding_profiles_user_id"), "onboarding_profiles", ["user_id"], unique=False)
    op.create_index(op.f("ix_onboarding_profiles_tenant_id"), "onboarding_profiles", ["tenant_id"], unique=False)

    op.create_table(
        "onboarding_use_cases",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("capabilities", sa.JSON(), nullable=False),
        sa.Column("success_criteria", sa.String(length=600), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_onboarding_use_cases_user_id"), "onboarding_use_cases", ["user_id"], unique=False)
    op.create_index(op.f("ix_onboarding_use_cases_tenant_id"), "onboarding_use_cases", ["tenant_id"], unique=False)

    op.create_table(
        "onboarding_environments",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("adapter_categories", sa.JSON(), nullable=False),
        sa.Column("cloud_providers", sa.JSON(), nullable=False),
        sa.Column("sanctioned_targets_only", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_onboarding_environments_user_id"), "onboarding_environments", ["user_id"], unique=False)
    op.create_index(op.f("ix_onboarding_environments_tenant_id"), "onboarding_environments", ["tenant_id"], unique=False)

    op.create_table(
        "onboarding_reviews",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("terms_accepted", sa.Boolean(), nullable=False),
        sa.Column("acceptable_use_accepted", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_onboarding_reviews_user_id"), "onboarding_reviews", ["user_id"], unique=False)
    op.create_index(op.f("ix_onboarding_reviews_tenant_id"), "onboarding_reviews", ["tenant_id"], unique=False)

def downgrade() -> None:
    op.drop_index(op.f("ix_onboarding_reviews_tenant_id"), "onboarding_reviews")
    op.drop_index(op.f("ix_onboarding_reviews_user_id"), "onboarding_reviews")
    op.drop_table("onboarding_reviews")
    op.drop_index(op.f("ix_onboarding_environments_tenant_id"), "onboarding_environments")
    op.drop_index(op.f("ix_onboarding_environments_user_id"), "onboarding_environments")
    op.drop_table("onboarding_environments")
    op.drop_index(op.f("ix_onboarding_use_cases_tenant_id"), "onboarding_use_cases")
    op.drop_index(op.f("ix_onboarding_use_cases_user_id"), "onboarding_use_cases")
    op.drop_table("onboarding_use_cases")
    op.drop_index(op.f("ix_onboarding_profiles_tenant_id"), "onboarding_profiles")
    op.drop_index(op.f("ix_onboarding_profiles_user_id"), "onboarding_profiles")
    op.drop_table("onboarding_profiles")
    pass
