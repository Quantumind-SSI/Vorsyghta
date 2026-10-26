"""add verification_token to users

Revision ID: a7c1e8d94f20
Revises: 3fdfac953d72
Create Date: 2026-10-25 22:20:00.000000

The UserRecord model (vorsyghta/db/models/auth.py) carries a
verification_token column for the email-verification flow, but revision
3fdfac953d72 only added is_verified and reset_token. Any database migrated
from scratch therefore misses the column and every registration fails with
'column "verification_token" of relation "users" does not exist'.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a7c1e8d94f20'
down_revision: Union[str, None] = '3fdfac953d72'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("verification_token", sa.String(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("users", "verification_token")
