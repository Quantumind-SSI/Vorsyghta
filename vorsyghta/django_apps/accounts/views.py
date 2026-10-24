"""Accounts API: register endpoint (parity with FastAPI /auth/register).

Security controls carried over (AUDIT C2, self-registration escalation):
- Role is forced to `viewer`; never taken from request payload.
- Email is the identity primitive; username is auto-derived.
"""

import re

from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import User


class RegisterSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(min_length=12, write_only=True)
    tenant_id = serializers.UUIDField(required=False, allow_null=True)

    def validate_password(self, value: str) -> str:
        from django.contrib.auth.password_validation import validate_password

        validate_password(value)
        return value


class RegisterView(APIView):
    """POST /auth/register — create a viewer-scoped user (no auth required)."""

    permission_classes: list = []
    authentication_classes: list = []

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        email = data["email"].strip().lower()
        if User.objects.filter(email__iexact=email).exists():
            return Response(
                {"detail": "Email already registered."},
                status=status.HTTP_409_CONFLICT,
            )

        user = User(
            email=email,
            username=re.sub(r"[^a-z0-9]+", "-", email.split("@")[0])[:140] or None,
            role="viewer",  # forced; self-registration never grants privilege
        )
        user.set_password(data["password"])  # bcrypt via Django hashers
        if data.get("tenant_id"):
            from .models import Tenant

            user.tenant_id = str(data["tenant_id"])
        user.save()

        return Response(
            {"id": str(user.pk), "email": user.email, "role": user.role},
            status=status.HTTP_201_CREATED,
        )
