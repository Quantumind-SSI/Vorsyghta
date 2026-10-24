"""URL configuration for the Vorsyghta Django app (milestone 1)."""

from django.contrib import admin
from django.urls import include, path
from django.conf import settings
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenVerifyView

from vorsyghta.django_apps.accounts.views import RegisterView
from vorsyghta.django_apps.api_health.views import HealthView, ReadinessView

urlpatterns = [
    path(settings.ADMIN_URL + "/", admin.site.urls),
    # Health / readiness (parity with FastAPI /health and /ready)
    path("health/", HealthView.as_view(), name="health"),
    path("ready/", ReadinessView.as_view(), name="ready"),
    # Auth parity with FastAPI /auth/*
    path("auth/token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("auth/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("auth/token/verify/", TokenVerifyView.as_view(), name="token_verify"),
    path("auth/register/", RegisterView.as_view(), name="auth_register"),
    # Audit trail parity (read-only, authed)
    path("audit/", include("vorsyghta.django_apps.audit.urls")),
]
