"""Database seeder for integration testing and pilot bootstrapping.

Creates the ``default`` tenant and a privileged (analyst) user so that the
integration acceptance gate can log in and run a REAL exercise (which
requires the ``analyst`` role) against a live LLM provider.

Self-registration deliberately only ever creates ``viewer`` accounts, so a
controlled seed step is the sanctioned way to provision an elevated role for
testing. This module is safe to run repeatedly (idempotent).

Usage (inside the API container)::

    python -m vorsyghta.db.seed

Environment variables:
    SEED_ANALYST_EMAIL     — email for the seeded analyst (default: analyst@vorsyghta.local)
    SEED_ANALYST_PASSWORD  — password for the seeded analyst (default: Analyst123!)
    SEED_TENANT_ID         — tenant id (default: default)
    SEED_ANALYST_ROLE      — role to assign (default: analyst)

Owner: Integration harness — Docker network acceptance
"""
from __future__ import annotations

import asyncio
import logging
import os
import sys
from uuid import uuid4

from sqlalchemy import select

from vorsyghta.security.rbac import get_password_hash

logger = logging.getLogger(__name__)


async def seed_analyst() -> dict:
    """Create the default tenant + an analyst user if they don't exist.

    Returns a dict describing what was created/existed.
    """
    from vorsyghta.db.session import get_session
    from vorsyghta.db.models.auth import TenantRecord, UserRecord

    email = os.getenv("SEED_ANALYST_EMAIL", "analyst@vorsyghta.local")
    password = os.getenv("SEED_ANALYST_PASSWORD", "Analyst123!")
    tenant_id = os.getenv("SEED_TENANT_ID", "default")
    role = os.getenv("SEED_ANALYST_ROLE", "analyst")

    created_tenant = False
    created_user = False

    async with get_session() as session:
        # Tenant
        existing_tenant = await session.execute(
            select(TenantRecord).where(TenantRecord.tenant_id == tenant_id)
        )
        if existing_tenant.scalar_one_or_none() is None:
            session.add(
                TenantRecord(
                    id=str(uuid4()),
                    tenant_id=tenant_id,
                    name=tenant_id.replace("_", " ").title(),
                )
            )
            await session.commit()
            created_tenant = True

        # User
        existing_user = await session.execute(
            select(UserRecord).where(UserRecord.email == email)
        )
        user = existing_user.scalar_one_or_none()
        if user is None:
            user_id = f"user_{uuid4().hex[:12]}"
            session.add(
                UserRecord(
                    id=str(uuid4()),
                    user_id=user_id,
                    tenant_id=tenant_id,
                    email=email,
                    hashed_password=get_password_hash(password),
                    role=role,
                    is_active=True,
                )
            )
            await session.commit()
            created_user = True
            final_user_id = user_id
        else:
            # Ensure role/tenant are correct (idempotent upgrade)
            changed = False
            if user.role != role:
                user.role = role
                changed = True
            if user.tenant_id != tenant_id:
                user.tenant_id = tenant_id
                changed = True
            if not user.is_active:
                user.is_active = True
                changed = True
            if changed:
                await session.commit()
            final_user_id = user.user_id

    return {
        "email": email,
        "user_id": final_user_id,
        "tenant_id": tenant_id,
        "role": role,
        "created_tenant": created_tenant,
        "created_user": created_user,
    }


async def _main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    result = await seed_analyst()
    action = "created" if result["created_user"] else "already exists (verified)"
    tenant_action = "created" if result["created_tenant"] else "already exists"
    logger.info(
        "Seed complete: tenant=%s (%s), user=%s role=%s (%s)",
        result["tenant_id"], tenant_action,
        result["email"], result["role"], action,
    )
    print(
        f"SEEDED analyst: email={result['email']} "
        f"user_id={result['user_id']} role={result['role']} tenant={result['tenant_id']} "
        f"({action})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(_main()))
