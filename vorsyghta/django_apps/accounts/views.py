"""Accounts API: register endpoint (parity with FastAPI /auth/register).

Security controls carried over (AUDIT C2, self-registration escalation):
- Role is forced to `viewer`; never taken from request payload.
- Email is the identity primitive; username is auto-derived.
"""

import re
import uuid
import secrets
from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.throttling import UserRateThrottle, AnonRateThrottle
from django.core.mail import send_mail
from django.conf import settings
from .models import User, Tenant
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)
        user = self.user
        # Ensure user has required fields
        tenant = getattr(user, "tenant", None)
        tenant_id = str(tenant.id) if tenant and getattr(tenant, "id", None) else ""
        data.update({
            "user_id": getattr(user, "user_id", str(user.pk)),
            "role": getattr(user, "role", "viewer"),
            "tenant_id": tenant_id,
            "requires_email_verification": not getattr(user, "is_verified", True),
        })
        # Frontend expects access_token / token_type instead of access / refresh
        data["access_token"] = data.pop("access")
        data["token_type"] = "bearer"
        # Keep refresh for compatibility
        return data


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer


class MeView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    def get(self, request):
        # For demo, assume token is already validated by middleware or we use session
        # Return current user from request.user if authenticated via JWT
        user = request.user
        if not user or not user.is_authenticated:
            return Response({"detail": "Authentication required"}, status=status.HTTP_401_UNAUTHORIZED)
        tenant = getattr(user, "tenant", None)
        data = {
            "user_id": getattr(user, "user_id", str(user.pk)),
            "tenant_id": str(tenant.id) if tenant and getattr(tenant, "id", None) else "",
            "role": getattr(user, "role", "viewer"),
            "email": user.email,
            "is_verified": getattr(user, "is_verified", False),
            "onboarding_complete": getattr(user, "onboarding_complete", False),
            "tenant": {"name": tenant.name} if tenant else None,
        }
        return Response(data, status=status.HTTP_200_OK)

import re
import uuid
import secrets
from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.throttling import UserRateThrottle, AnonRateThrottle
from django.core.mail import send_mail
from django.conf import settings
from .models import User, Tenant


class RegisterSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(min_length=12, write_only=True)
    organization_name = serializers.CharField(min_length=2, max_length=120)
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
        email = serializer.validated_data["email"].strip().lower()
        password = serializer.validated_data["password"]
        org_name = serializer.validated_data["organization_name"]

        if User.objects.filter(email__iexact=email).exists():
            return Response({"detail": "Email already registered."}, status=status.HTTP_409_CONFLICT)

        tenant, _ = Tenant.objects.get_or_create(
            name=org_name,
            defaults={
                "tenant_id": str(uuid.uuid4()),
                "is_active": True,
            }
        )
        # ensure tenant id exists
        # tenant has id field only

        user = User(
            email=email,
            username=re.sub(r"[^a-z0-9]+", "-", email.split("@")[0])[:140] or None,
            role="viewer",
            tenant=tenant,
            onboarding_complete=False,
            is_verified=False,
        )
        user.set_password(password)
        user.verification_token = secrets.token_urlsafe(32)
        user.save()

        verify_url = f"{settings.FRONTEND_URL or 'http://localhost:3000'}/verify-email?token={user.verification_token}"
        send_mail(
            subject="Verify your Vorsyghta email",
            message=f"Click to verify: {verify_url}",
            from_email=settings.DEFAULT_FROM_EMAIL or "no-reply@vorsyghta.local",
            recipient_list=[email],
            fail_silently=True,
        )

        return Response(
            {"id": str(user.pk), "email": user.email, "user_id": str(user.pk), "tenant_id": str(tenant.id), "role": user.role, "requires_email_verification": True, "message": "User registered"},
            status=status.HTTP_201_CREATED,
        )

class VerifyEmailView(APIView):
    permission_classes = []
    authentication_classes = []

    def post(self, request):
        token = request.data.get("token")
        if not token:
            return Response({"detail": "token required"}, status=status.HTTP_400_BAD_REQUEST)
        user = User.objects.filter(verification_token=token).first()
        if not user:
            return Response({"detail": "invalid token"}, status=status.HTTP_400_BAD_REQUEST)
        user.is_verified = True
        user.verification_token = ""
        user.save(update_fields=["is_verified", "verification_token"])
        return Response({"verified": True}, status=status.HTTP_200_OK)

class CompleteOnboardingView(APIView):
    permission_classes = []
    authentication_classes = []

    def post(self, request):
        token = request.data.get("token")
        if not token:
            return Response({"detail": "token required"}, status=status.HTTP_400_BAD_REQUEST)
        return Response({"completed": True, "message": "Onboarding completed"}, status=status.HTTP_200_OK)
class RequestResetView(APIView):
    permission_classes = []
    authentication_classes = []
    def post(self, request):
        email = request.data.get("email")
        if not email:
            return Response({"detail": "email required"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(email__iexact=email)
        except User.DoesNotExist:
            # Don't leak existence
            return Response({"message": "If an account exists, a reset link has been sent."}, status=status.HTTP_200_OK)
        token = secrets.token_urlsafe(32)
        user.reset_token = token
        user.save(update_fields=["reset_token"])
        reset_url = f"{settings.FRONTEND_URL or 'http://localhost:3000'}/reset-password?token={token}"
        send_mail(
            subject="Reset your Vorsyghta password",
            message=f"Click to reset: {reset_url}",
            from_email=settings.DEFAULT_FROM_EMAIL or "no-reply@vorsyghta.local",
            recipient_list=[email],
            fail_silently=True,
        )
        return Response({"message": "If an account exists, a reset link has been sent."}, status=status.HTTP_200_OK)

class ResetPasswordView(APIView):
    permission_classes = []
    authentication_classes = []
    def post(self, request):
        token = request.data.get("token")
        password = request.data.get("new_password") or request.data.get("password")
        if not token or not password:
            return Response({"detail": "token and password required"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(reset_token=token)
        except User.DoesNotExist:
            return Response({"detail": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)
        user.set_password(password)
        user.reset_token = None
        user.save(update_fields=["password", "reset_token"])
        return Response({"message": "Password reset successfully."}, status=status.HTTP_200_OK)
