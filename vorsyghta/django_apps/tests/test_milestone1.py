"""pytest-django suite for the Vorsyghta rewrite (milestone 1).

Contract tests: register→viewer (privilege escalation closed), JWT login,
health/readiness, audit hash-chain invariant.
"""

import pytest
from django.test import Client

pytestmark = pytest.mark.django_db


def test_health_ok(client: Client):
    resp = client.get("/health/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "healthy"


def test_ready_ok(client: Client):
    resp = client.get("/ready/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ready"
    assert body["checks"]["database"] == "ready"


def test_register_forces_viewer_role(client: Client):
    """Self-registration must never grant analyst/admin (AUDIT C2 control)."""
    resp = client.post(
        "/auth/register/",
        data={"email": "attacker@example.com", "password": "S3curePassphrase!x", "role": "admin"},
        content_type="application/json",
    )
    assert resp.status_code == 201
    assert resp.json()["role"] == "viewer"


def test_register_duplicate_email_conflict(client: Client):
    payload = {"email": "dupe@example.com", "password": "S3curePassphrase!x"}
    assert client.post("/auth/register/", data=payload, content_type="application/json").status_code == 201
    resp = client.post("/auth/register/", data=payload, content_type="application/json")
    assert resp.status_code == 409


def test_jwt_login_and_me(client: Client):
    client.post(
        "/auth/register/",
        data={"email": "user@example.com", "password": "S3curePassphrase!x"},
        content_type="application/json",
    )
    resp = client.post(
        "/auth/token/",
        data={"email": "user@example.com", "password": "S3curePassphrase!x"},
        content_type="application/json",
    )
    assert resp.status_code == 200
    token = resp.json()["access"]
    auth = {"HTTP_AUTHORIZATION": f"Bearer {token}"}
    events = client.get("/audit/events/", **auth)
    assert events.status_code == 200


def test_audit_hash_chain_invariant(client: Client, django_user_model):
    """Two audit events must chain: second.prev_hash == first.event_hash."""
    from vorsyghta.django_apps.audit.models import AuditEvent

    user = django_user_model.objects.create_user(email="a@x.com", password="S3curePassphrase!x")
    first = AuditEvent.objects.create(
        event_type="test.event",
        category="test",
        severity="info",
        actor={"id": str(user.pk)},
        target={"resource": "test"},
        context={"ip": "127.0.0.1"},
        description="first",
    )
    second = AuditEvent.objects.create(
        event_type="test.event",
        category="test",
        severity="info",
        actor={"id": str(user.pk)},
        target={"resource": "test"},
        context={"ip": "127.0.0.1"},
        description="second",
    )
    assert second.prev_hash == first.event_hash
    assert first.verify_chain()
    assert second.verify_chain()


def test_audit_events_require_auth(client: Client):
    """Unauthenticated audit reads must be rejected (fail-closed)."""
    resp = client.get("/audit/events/")
    assert resp.status_code == 401


def test_weak_registration_password_rejected(client: Client):
    resp = client.post(
        "/auth/register/",
        data={"email": "weak@example.com", "password": "short"},
        content_type="application/json",
    )
    assert resp.status_code == 400
