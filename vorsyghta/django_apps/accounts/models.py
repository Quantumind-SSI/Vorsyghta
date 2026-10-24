"""Accounts app: custom user model for the Vorsyghta rewrite.

Parity with FastAPI stack: TenantRecord + UserRecord
(`vorsyghta/db/models/auth.py`).
Roles are enforced at the app layer (`viewer` default; self-registration
privilege escalation is closed — same control as the FastAPI stack).
"""

import uuid

from django.contrib.auth.base_user import BaseUserManager as DjangoUserManager
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.hashers import make_password
from django.db import models


class Tenant(models.Model):
    """Multi-tenancy root; mirrors TenantRecord."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "tenants"
        ordering = ["-created_at"]

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


class UserManager(DjangoUserManager):
    """Manager for email-first user model (username optional)."""

    def _create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError("Email is required")
        email = self.normalize_email(email)
        extra_fields.setdefault("username", None)
        user = self.model(email=email, **extra_fields)
        user.password = make_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("role", "admin")
        return self._create_user(email, password, **extra_fields)


class User(AbstractUser):
    """Vorsyghta user; mirrors UserRecord (bcrypt via Django hasher)."""

    ROLES = (
        ("viewer", "viewer"),
        ("analyst", "analyst"),
        ("admin", "admin"),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    objects = UserManager()
    email = models.EmailField(unique=True, null=False, blank=False)
    tenant = models.ForeignKey(
        Tenant, on_delete=models.PROTECT, related_name="users", null=True, blank=True
    )
    role = models.CharField(max_length=20, choices=ROLES, default="viewer")
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    # Username is not the identity primitive here; email is.
    username = models.CharField(max_length=150, unique=True, null=True, blank=True)
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS: list[str] = []

    class Meta:
        db_table = "users"
        ordering = ["-created_at"]

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.email or str(self.pk)
