"""URL configuration for the Vorsyghta Django app (milestone 1)."""

from django.contrib import admin
from django.urls import include, path
from django.conf import settings
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView

from vorsyghta.django_apps.accounts.views import RegisterView, VerifyEmailView, CompleteOnboardingView, RequestResetView, ResetPasswordView, CustomTokenObtainPairView, MeView
from vorsyghta.django_apps.api_health.views import HealthView, ReadinessView


urlpatterns = [
    path(settings.ADMIN_URL + "/", admin.site.urls),
    path("health/", HealthView.as_view(), name="health"),
    path("ready/", ReadinessView.as_view(), name="ready"),
    path("auth/token/", CustomTokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("auth/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("auth/token/verify/", TokenVerifyView.as_view(), name="token_verify"),
    path("auth/me/", MeView.as_view(), name="auth_me"),
    path("auth/verify-email/", VerifyEmailView.as_view(), name="auth_verify_email"),
    path("auth/request-reset/", RequestResetView.as_view(), name="auth_request_reset"),
    path("auth/reset-password/", ResetPasswordView.as_view(), name="auth_reset_password"),
    path("api/operations/", include("vorsyghta.django_apps.operations.urls")),
    path("api/knowledge/", include("vorsyghta.django_apps.knowledge.urls")),
    path("api/threat-intel/", include("vorsyghta.django_apps.threat_intel.urls")),
    path("api/exercises/", include("vorsyghta.django_apps.exercises.urls")),
    path("teams/", include("vorsyghta.django_apps.teams.urls")),
    path("audit/", include("vorsyghta.django_apps.audit.urls")),
]
