"""AWS Secrets Manager credential provider.

Reads secrets from AWS Secrets Manager. Two backends are supported:

1. ``boto3`` — used when available (preferred, handles SigV4 signing,
   retries, and credential resolution automatically).
2. A minimal ``httpx``-based fallback that performs AWS Signature V4
   signing manually. This keeps the provider usable even when boto3
   is not installed.
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import hmac
import json
import logging
from typing import Optional

import httpx

from ciicerone.client_data.config import SecretRef
from .base import CredentialProvider

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# AWS SigV4 helpers (minimal implementation)
# ---------------------------------------------------------------------------
_SERVICE = "secretsmanager"
_HOST_SUFFIX = ".secretsmanager.amazonaws.com"


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _derive_signing_key(secret: str, date_stamp: str, region: str, service: str) -> bytes:
    k_date = _sign(("AWS4" + secret).encode("utf-8"), date_stamp)
    k_region = _sign(k_date, region)
    k_service = _sign(k_region, service)
    return _sign(k_service, "aws4_request")


def _canonical_request(method, uri, query, headers, payload_hash) -> str:
    canonical_headers = ""
    signed_headers = ""
    for key in sorted(headers.keys()):
        canonical_headers += f"{key}:{headers[key].strip()}\n"
        signed_headers += f"{key};"
    signed_headers = signed_headers.rstrip(";")
    return (
        f"{method}\n{uri}\n{query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    )


def _string_to_sign(amz_date, credential_scope, canonical_request) -> str:
    return (
        "AWS4-HMAC-SHA256\n"
        f"{amz_date}\n{credential_scope}\n"
        f"{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
    )


def _build_signed_request(
    *,
    method: str,
    host: str,
    region: str,
    access_key_id: str,
    secret_access_key: str,
    body: dict,
) -> httpx.Request:
    """Build an httpx Request with an AWS SigV4 Authorization header."""
    amz_date = _dt.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    date_stamp = _dt.datetime.utcnow().strftime("%Y%m%d")
    payload = json.dumps(body, separators=(",", ":"))
    payload_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    headers = {
        "host": host,
        "x-amz-date": amz_date,
        "x-amz-target": f"{_SERVICE}.GetSecretValue",
        "content-type": "application/x-amz-json-1.1",
        "content-length": str(len(payload)),
        "x-amz-content-sha256": payload_hash,
    }

    canonical_request = _canonical_request(
        method, "/", "", headers, payload_hash
    )
    credential_scope = f"{date_stamp}/{region}/{_SERVICE}/aws4_request"
    string_to_sign = _string_to_sign(amz_date, credential_scope, canonical_request)
    signing_key = _derive_signing_key(
        secret_access_key, date_stamp, region, _SERVICE
    )
    signature = hmac.new(
        signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    signed_headers = ";".join(sorted(headers.keys()))
    authorization = (
        f"AWS4-HMAC-SHA256 "
        f"Credential={access_key_id}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    request = httpx.Request(
        method,
        f"https://{host}/",
        headers={
            "Authorization": authorization,
            "x-amz-date": amz_date,
            "x-amz-target": headers["x-amz-target"],
            "content-type": headers["content-type"],
            "x-amz-content-sha256": payload_hash,
        },
        content=payload.encode("utf-8"),
    )
    return request


# ---------------------------------------------------------------------------
# Provider
# ---------------------------------------------------------------------------
class AWSSecretsManagerProvider(CredentialProvider):
    """Resolve secrets from AWS Secrets Manager.

    Parameters
    ----------
    region:
        AWS region, e.g. ``us-east-1``.
    access_key_id:
        AWS access key id.
    secret_access_key:
        AWS secret access key.
    """

    provider_name = "aws_secrets_manager"

    def __init__(
        self,
        region: str,
        access_key_id: str,
        secret_access_key: str,
    ) -> None:
        self.region = region
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self._host = f"secretsmanager.{region}.amazonaws.com"
        self._client = httpx.AsyncClient(timeout=30.0)
        self._boto_client = None
        self._boto_checked = False

    # ------------------------------------------------------------------
    # boto3 backend (preferred when available)
    # ------------------------------------------------------------------
    def _get_boto_client(self):
        """Lazily build a boto3 client, or return None if boto3 missing."""
        if self._boto_checked:
            return self._boto_client
        self._boto_checked = True
        try:
            import boto3  # type: ignore
        except ImportError:
            logger.info(
                "boto3 not installed; AWS Secrets Manager provider will use "
                "the httpx SigV4 fallback"
            )
            return None
        try:
            self._boto_client = boto3.client(
                "secretsmanager",
                region_name=self.region,
                aws_access_key_id=self.access_key_id,
                aws_secret_access_key=self.secret_access_key,
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Failed to construct boto3 client: %s", exc)
            self._boto_client = None
        return self._boto_client

    # ------------------------------------------------------------------
    # CredentialProvider interface
    # ------------------------------------------------------------------
    async def get_secret(self, ref: SecretRef) -> Optional[str]:
        name = ref.name
        version_id = ref.version
        logger.debug(
            "AWS SM provider requesting secret: name=%s version=%s",
            name,
            version_id or "latest",
        )

        boto_client = self._get_boto_client()
        if boto_client is not None:
            return await self._get_via_boto(boto_client, name, version_id)
        return await self._get_via_httpx(name, version_id)

    async def _get_via_boto(self, client, name: str, version_id: Optional[str]):
        """Use boto3 (synchronous) to fetch the secret."""
        try:
            kwargs = {"SecretId": name}
            if version_id:
                kwargs["VersionId"] = version_id
            # boto3 is synchronous; run in a thread to avoid blocking the
            # event loop. We import here to keep the dependency optional.
            import asyncio

            response = await asyncio.to_thread(client.get_secret_value, **kwargs)
        except Exception as exc:
            # ResourceNotFoundException is common — log metadata only.
            logger.info("AWS SM secret not accessible: name=%s (%s)", name, type(exc).__name__)
            return None

        if "SecretString" in response and response["SecretString"] is not None:
            return self._extract_value(response["SecretString"], name)
        if "SecretBinary" in response and response["SecretBinary"] is not None:
            try:
                decoded = base64.b64decode(response["SecretBinary"]).decode("utf-8")
                return self._extract_value(decoded, name)
            except Exception:
                logger.warning("AWS SM binary secret %s could not be decoded", name)
                return None
        logger.info("AWS SM secret %s contained no value", name)
        return None

    async def _get_via_httpx(self, name: str, version_id: Optional[str]):
        """Fallback path using httpx + manual SigV4 signing."""
        body: dict = {"SecretId": name}
        if version_id:
            body["VersionId"] = version_id

        request = _build_signed_request(
            method="POST",
            host=self._host,
            region=self.region,
            access_key_id=self.access_key_id,
            secret_access_key=self.secret_access_key,
            body=body,
        )
        try:
            response = await self._client.send(request)
        except httpx.HTTPError as exc:
            logger.warning("AWS SM request failed for name=%s: %s", name, exc)
            return None

        if response.status_code == 404:
            logger.info("AWS SM secret not found: name=%s", name)
            return None
        if response.status_code >= 400:
            logger.warning(
                "AWS SM returned HTTP %s for name=%s", response.status_code, name
            )
            return None

        try:
            payload = response.json()
        except ValueError:
            logger.warning("AWS SM response was not valid JSON for name=%s", name)
            return None

        if "SecretString" in payload and payload["SecretString"] is not None:
            return self._extract_value(payload["SecretString"], name)
        if "SecretBinary" in payload and payload["SecretBinary"] is not None:
            try:
                decoded = base64.b64decode(payload["SecretBinary"]).decode("utf-8")
                return self._extract_value(decoded, name)
            except Exception:
                logger.warning("AWS SM binary secret %s could not be decoded", name)
                return None
        logger.info("AWS SM secret %s contained no value", name)
        return None

    @staticmethod
    def _extract_value(raw: str, name: str) -> Optional[str]:
        """Extract a string value from a Secrets Manager response.

        AWS Secrets Manager stores secrets as either a plain string or a
        JSON object of key/value pairs. For JSON objects we prefer a
        ``value`` key, otherwise the first value.
        """
        try:
            parsed = json.loads(raw)
        except (ValueError, TypeError):
            return raw
        if isinstance(parsed, dict):
            if "value" in parsed:
                return parsed["value"]
            if parsed:
                return next(iter(parsed.values()))
            logger.info("AWS SM secret %s JSON object was empty", name)
            return None
        if isinstance(parsed, str):
            return parsed
        return raw

    async def close(self) -> None:
        await self._client.aclose()
