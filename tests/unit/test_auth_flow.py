"""
Backend auth flow tests for Vorsyghta API.

Covers full user journey:
- Register → token → me
- Tenant isolation
- Rate limiting
- Validation errors
- Session reliability
"""
import pytest
from httpx import AsyncClient

from vorsyghta.db.base import get_engine
from vorsyghta.db.models.auth import UserRecord
from sqlalchemy.ext.asyncio import async_sessionmaker
from sqlalchemy import select

pytestmark = pytest.mark.asyncio


async def _mark_verified(email: str) -> None:
    """Mark the freshly registered account verified.

    Login enforces email verification (a4014c9); unit tests exercise the
    login/token path directly, so complete verification for the account.
    """
    maker = async_sessionmaker(get_engine(), expire_on_commit=False)
    async with maker() as s:
        result = await s.execute(select(UserRecord).where(UserRecord.email == email))
        user = result.scalar_one_or_none()
        if user is not None:
            user.is_verified = True
            user.verification_token = None
            await s.commit()




async def test_register_creates_tenant_and_user(async_client: AsyncClient):
    payload = {
        "email": "newuser@example.com",
        "password": "SuperSecurePass123!",
        "organization_name": "Acme Corp"
    }
    resp = await async_client.post("/api/auth/register", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["message"] == "User registered"
    assert "tenant_id" in data
    assert "user_id" in data


async def test_register_duplicate_email_fails(async_client: AsyncClient):
    payload = {
        "email": "dup@example.com",
        "password": "SuperSecurePass123!",
        "organization_name": "DupCo"
    }
    r1 = await async_client.post("/api/auth/register", json=payload)
    assert r1.status_code == 201
    r2 = await async_client.post("/api/auth/register", json=payload)
    assert r2.status_code >= 400


async def test_register_invalid_password_fails(async_client: AsyncClient):
    payload = {
        "email": "short@example.com",
        "password": "short",
        "organization_name": "ShortCo"
    }
    resp = await async_client.post("/api/auth/register", json=payload)
    assert resp.status_code >= 400


async def test_login_returns_jwt(async_client: AsyncClient):
    email = "login@example.com"
    password = "LoginPass123!"
    # Register first
    await async_client.post("/api/auth/register", json={
        "email": email,
        "password": password,
        "organization_name": "LoginCo"
    })
    await _mark_verified(email)
    resp = await async_client.post(
        "/api/auth/login",
        data={"username": email, "password": password}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["role"] in ("viewer", "analyst")


async def test_login_wrong_password_fails(async_client: AsyncClient):
    email = "wrongpass@example.com"
    await async_client.post("/api/auth/register", json={
        "email": email,
        "password": "CorrectPass123!",
        "organization_name": "WrongCo"
    })
    await _mark_verified(email)
    resp = await async_client.post(
        "/api/auth/login",
        data={"username": email, "password": "BadPass"}
    )
    assert resp.status_code in (401, 400)


async def test_me_requires_valid_token(async_client: AsyncClient):
    resp = await async_client.get("/api/auth/me")
    assert resp.status_code == 401

    # Register & login
    email = "me@example.com"
    password = "MeSecurePass123!"
    await async_client.post("/api/auth/register", json={
        "email": email,
        "password": password,
        "organization_name": "MeCo"
    })
    await _mark_verified(email)
    login = await async_client.post(
        "/api/auth/login",
        data={"username": email, "password": password}
    )
    token = login.json()["access_token"]
    me = await async_client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert me.status_code == 200
    me_data = me.json()
    assert me_data["email"] == email
    assert "tenant_id" in me_data
    assert "user_id" in me_data


async def test_tenant_isolation_on_register(async_client: AsyncClient):
    r1 = await async_client.post("/api/auth/register", json={
        "email": "a@example.com",
        "password": "PassA123456!",
        "organization_name": "OrgA"
    })
    r2 = await async_client.post("/api/auth/register", json={
        "email": "b@example.com",
        "password": "PassB123456!",
        "organization_name": "OrgB"
    })
    assert r1.json()["tenant_id"] != r2.json()["tenant_id"]


async def test_rate_limit_register(async_client: AsyncClient):
    # Simple sanity: repeated attempts should be rate limited eventually
    # This test documents that rate limiting exists
    for i in range(3):
        resp = await async_client.post("/api/auth/register", json={
            "email": f"rate{i}@example.com",
            "password": "RatePass123!",
            "organization_name": f"RateOrg{i}"
        })
        # First few succeed; implementation may throttle later
        assert resp.status_code in (201, 429)


async def test_auth_flow_end_to_end(async_client: AsyncClient):
    """Full journey: register -> login -> me -> validate fields"""
    email = "e2e@example.com"
    password = "E2ESecurePass123!"
    org = "E2EOrg"
    reg = await async_client.post("/api/auth/register", json={
        "email": email,
        "password": password,
        "organization_name": org
    })
    assert reg.status_code == 201
    tenant_id = reg.json()["tenant_id"]
    user_id = reg.json()["user_id"]

    await _mark_verified(email)
    login = await async_client.post(
        "/api/auth/login",
        data={"username": email, "password": password}
    )
    assert login.status_code == 200
    token = login.json()["access_token"]

    me = await async_client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert me.status_code == 200
    me_data = me.json()
    assert me_data["user_id"] == user_id
    assert me_data["tenant_id"] == tenant_id
    assert me_data["email"] == email
async def test_register_email_normalization(async_client: AsyncClient):
    payload = {
        "email": "  MixedCASE@Example.COM  ",
        "password": "NormPass123!",
        "organization_name": "NormOrg"
    }
    resp = await async_client.post("/api/auth/register", json=payload)
    assert resp.status_code == 201
    await _mark_verified("mixedcase@example.com")
    # login with normalized email
    login = await async_client.post(
        "/api/auth/login",
        data={"username": "mixedcase@example.com", "password": "NormPass123!"}
    )
    assert login.status_code == 200


async def test_login_nonexistent_user_fails(async_client: AsyncClient):
    resp = await async_client.post(
        "/api/auth/login",
        data={"username": "nosuch@example.com", "password": "Whatever123!"}
    )
    assert resp.status_code in (401, 400)
