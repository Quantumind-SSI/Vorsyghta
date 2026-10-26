"""add is_verified and reset_token to users

Revision ID: 3fdfac953d72
Revises: 004_stripe_billing
Create Date: 2026-10-25 12:02:19.909005

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '3fdfac953d72'
down_revision: Union[str, None] = '004_stripe_billing'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add is_verified column to users table
    op.add_column(
        "users",
        sa.Column("is_verified", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    # Add reset_token column to users table
    op.add_column(
        "users",
        sa.Column("reset_token", sa.String(), nullable=True),
    )


def downgrade() -> None:
    # Remove reset_token column from users table
    op.drop_column("users", "reset_token")
    # Remove is_verified column from users table
    op.drop_column("users", "is_verified")
