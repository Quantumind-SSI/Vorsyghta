"""
Django settings for the Vorsyghta rewrite (milestone 1).

Production rules (AGENTS.md / AUDIT C1):
- SECRET_KEY is fail-closed: env VORSYGHTA_SECRET_KEY, no default.
- DEBUG is env-driven, never default-on.
- DATABASE_URL respected to stay aligned with the FastAPI stack (Postgres).
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# --- Security (fail-closed, C1) -------------------------------------------
SECRET_KEY = os.environ.get("VORSYGHTA_SECRET_KEY", "")
if not SECRET_KEY:
    raise RuntimeError(
        "VORSYGHTA_SECRET_KEY is required for the Django app "
        "(fail-closed; no default signing key is allowed)."
    )

DEBUG = os.environ.get("DJANGO_DEBUG", "false").lower() in {"1", "true", "yes"}

ALLOWED_HOSTS = [
    h.strip()
    for h in os.environ.get("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
    if h.strip()
]

# --- Applications ----------------------------------------------------------
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "rest_framework_simplejwt",
    "corsheaders",
    # Vorsyghta rewrite apps (strangler-fig migration target)
    "vorsyghta.django_apps.accounts",
    "vorsyghta.django_apps.audit",
    "vorsyghta.django_apps.api_health",
]
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

CORS_ALLOWED_ORIGINS = [o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "").split(",") if o.strip()]
CORS_ALLOW_CREDENTIALS = True
SECURE_SSL_REDIRECT = os.environ.get("SECURE_SSL_REDIRECT", "true").lower() in {"1","true","yes"}
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True

ADMIN_URL = os.environ.get("ADMIN_URL", "admin")
ADMIN_SITE_HEADER = "Vorsyghta Admin"
ADMIN_SITE_TITLE = "Vorsyghta Administration"
ROOT_URLCONF = "server.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "server.wsgi.application"

# --- Database ---------------------------------------------------------------
# Align with the existing stack: DATABASE_URL (Postgres in docker-compose).
# Fallback for local/test: SQLite so `migrate` and pytest run green anywhere.


def _database_from_url(url: str) -> dict:
    """Map a DATABASE_URL to Django's DATABASES entry (postgres or sqlite)."""
    if url.startswith("postgres"):
        from urllib.parse import urlparse

        parsed = urlparse(url)
        return {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": parsed.path.lstrip("/"),
            "USER": parsed.username or "",
            "PASSWORD": parsed.password or "",
            "HOST": parsed.hostname or "localhost",
            "PORT": str(parsed.port or 5432),
        }
    if url.startswith("sqlite"):
        path = url.split("///", 1)[-1] or "vorsyghta_django.db"
        return {"ENGINE": "django.db.backends.sqlite3", "NAME": path}
    raise ValueError(f"Unsupported DATABASE_URL scheme: {url!r}")


_env_url = os.environ.get("DATABASE_URL", "sqlite:///vorsyghta_django.db")

DATABASES = {
    "default": _database_from_url(_env_url),
}

# --- Auth -------------------------------------------------------------------
AUTH_USER_MODEL = "accounts.User"

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 12}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# --- DRF / JWT ---------------------------------------------------------------
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": (
        "rest_framework.permissions.IsAuthenticated",
    ),
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 50,
}

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": __import__("datetime").timedelta(
        minutes=int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
    ),
    "REFRESH_TOKEN_LIFETIME": __import__("datetime").timedelta(days=7),
    "ROTATE_REFRESH_TOKENS": True,
    "AUD": "vorsyghta",
    "USER_ID_FIELD": "id",
    "USER_ID_CLAIM": "user_id",
}

# --- i18n / static ------------------------------------------------------------
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
