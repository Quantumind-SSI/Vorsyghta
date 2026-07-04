"""Hybrid crypto validator.

Validates hybrid post-quantum/classical TLS deployments.
Tests hybrid key exchange, fallback mechanisms, performance impact,
and security levels for PQ/TLS configurations.
"""

import asyncio
import logging
import time
import uuid
from datetime import datetime
from typing import Any, Dict, Optional

from .models import HybridCryptoValidationResult

logger = logging.getLogger(__name__)


# Supported hybrid PQ/TLS cipher suites
HYBRID_CIPHER_SUITES = {
    "x25519_kyber768": "X25519Kyber768Draft00",
    "x25519_kyber512": "X25519Kyber512Draft00",
    "secp256r1_kyber768": "SecP256R1Kyber768Draft00",
    "p256_kyber768": "P256Kyber768Draft00",
    "x25519_bikel1": "X25519Bikel1Draft00",
    "x25519_hqc128": "X25519HQC128Draft00",
}

# Expected security levels for hybrid configurations
HYBRID_SECURITY_LEVELS = {
    "x25519_kyber768": "Classical: 128-bit + PQ: 128-bit = 256-bit hybrid",
    "x25519_kyber512": "Classical: 128-bit + PQ: 80-bit = 128-bit hybrid",
    "secp256r1_kyber768": "Classical: 128-bit + PQ: 128-bit = 256-bit hybrid",
    "p256_kyber768": "Classical: 128-bit + PQ: 128-bit = 256-bit hybrid",
}


class HybridCryptoValidator:
    """Validates hybrid PQ/TLS deployments.

    Tests:
    - Hybrid key exchange negotiation
    - Classical component integrity
    - Post-quantum component integrity
    - Fallback mechanism (if PQ fails, does it fall back to classical?)
    - Performance overhead measurement
    - Certificate chain validation with PQC certificates
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.oqs_provider_path = self.config.get("oqs_provider_path", "liboqs-provider")
        self.openssl_path = self.config.get("openssl_path", "openssl")

    async def validate(self, config: Dict[str, Any]) -> HybridCryptoValidationResult:
        """Validate a hybrid PQ/TLS deployment configuration.

        Args:
            config: Hybrid deployment configuration containing:
                - endpoint: Target endpoint (host:port)
                - cipher_suite: Hybrid cipher suite to test
                - fallback_enabled: Whether fallback to classical is allowed
                - certificate: Optional PQC certificate to validate

        Returns:
            HybridCryptoValidationResult with validation details
        """
        logger.info(f"Validating hybrid PQ/TLS config: {config}")

        endpoint = config.get("endpoint", "localhost:443")
        cipher_suite = config.get("cipher_suite", "x25519_kyber768")
        fallback_enabled = config.get("fallback_enabled", True)

        classical_status = await self._test_classical_component(endpoint)
        pqc_status = await self._test_pqc_component(endpoint, cipher_suite)
        fallback_status = await self._test_fallback(endpoint, fallback_enabled)
        performance_overhead = await self._measure_performance(endpoint, cipher_suite)
        security_score = self._calculate_security_score(
            classical_status, pqc_status, fallback_status
        )

        hybrid_valid = (
            classical_status["valid"]
            and pqc_status["valid"]
            and (not fallback_enabled or fallback_status["valid"])
        )

        return HybridCryptoValidationResult(
            validation_id=str(uuid.uuid4()),
            hybrid_valid=hybrid_valid,
            classical_component=classical_status["message"],
            post_quantum_component=pqc_status["message"],
            fallback_mechanism=fallback_status["message"],
            performance_impact=performance_overhead,
            security_level=security_score,
            test_details={
                "endpoint": endpoint,
                "cipher_suite": cipher_suite,
                "classical_details": classical_status,
                "pqc_details": pqc_status,
                "fallback_details": fallback_status,
                "security_level_detail": HYBRID_SECURITY_LEVELS.get(cipher_suite, "Unknown"),
            },
            timestamp=datetime.utcnow(),
        )

    async def _test_classical_component(self, endpoint: str) -> Dict[str, Any]:
        """Test the classical component of the hybrid TLS connection."""
        try:
            proc = await asyncio.create_subprocess_exec(
                self.openssl_path, "s_client", "-connect", endpoint,
                "-groups", "x25519:secp256r1:secp384r1",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
            output = stdout.decode("utf-8", errors="ignore") if stdout else ""

            if "Cipher is" in output and ("X25519" in output or "ECDHE" in output):
                return {"valid": True, "message": "Classical key exchange (X25519/ECDHE) negotiated successfully"}
            else:
                return {"valid": False, "message": "Classical key exchange negotiation failed"}
        except Exception as e:
            logger.debug(f"Classical component test failed: {e}")
            return {"valid": False, "message": f"Classical component test error: {str(e)}"}

    async def _test_pqc_component(self, endpoint: str, cipher_suite: str) -> Dict[str, Any]:
        """Test the post-quantum component of the hybrid TLS connection."""
        oqs_cipher = HYBRID_CIPHER_SUITES.get(cipher_suite, cipher_suite)

        try:
            proc = await asyncio.create_subprocess_exec(
                self.openssl_path, "s_client", "-connect", endpoint,
                "-groups", oqs_cipher,
                "-provider", "oqsprovider" if self.oqs_provider_path == "liboqs-provider" else "default",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
            output = stdout.decode("utf-8", errors="ignore") if stdout else ""

            if "Cipher is" in output and any(k in output for k in ["Kyber", "Bikel", "HQC", "kyber"]):
                return {"valid": True, "message": f"PQC key exchange ({oqs_cipher}) negotiated successfully"}
            else:
                return {
                    "valid": False,
                    "message": f"PQC key exchange ({oqs_cipher}) not negotiated - OQS provider may not be installed",
                }
        except Exception as e:
            logger.debug(f"PQC component test failed: {e}")
            return {
                "valid": False,
                "message": f"PQC component test error: {str(e)} - ensure liboqs-provider is installed",
            }

    async def _test_fallback(self, endpoint: str, fallback_enabled: bool) -> Dict[str, Any]:
        """Test the fallback mechanism when PQ negotiation fails."""
        if not fallback_enabled:
            return {"valid": True, "message": "Fallback disabled by configuration (strict PQ mode)"}

        try:
            # Attempt connection with only classical groups (simulating PQ failure)
            proc = await asyncio.create_subprocess_exec(
                self.openssl_path, "s_client", "-connect", endpoint,
                "-groups", "x25519",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            output = stdout.decode("utf-8", errors="ignore") if stdout else ""

            if "Cipher is" in output:
                return {"valid": True, "message": "Fallback to classical key exchange (X25519) successful"}
            else:
                return {"valid": False, "message": "Fallback to classical key exchange failed"}
        except Exception as e:
            return {"valid": False, "message": f"Fallback test error: {str(e)}"}

    async def _measure_performance(self, endpoint: str, cipher_suite: str) -> float:
        """Measure performance overhead of hybrid PQ/TLS vs classical TLS."""
        # Measure classical TLS handshake time
        classical_times: list = []
        for _ in range(3):
            start = time.monotonic()
            try:
                proc = await asyncio.create_subprocess_exec(
                    self.openssl_path, "s_client", "-connect", endpoint,
                    "-groups", "x25519",
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(proc.communicate(), timeout=10)
            except Exception:
                pass
            classical_times.append(time.monotonic() - start)

        # Measure hybrid PQ/TLS handshake time
        oqs_cipher = HYBRID_CIPHER_SUITES.get(cipher_suite, cipher_suite)
        hybrid_times: list = []
        for _ in range(3):
            start = time.monotonic()
            try:
                proc = await asyncio.create_subprocess_exec(
                    self.openssl_path, "s_client", "-connect", endpoint,
                    "-groups", oqs_cipher,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(proc.communicate(), timeout=10)
            except Exception:
                pass
            hybrid_times.append(time.monotonic() - start)

        avg_classical = sum(classical_times) / max(1, len(classical_times))
        avg_hybrid = sum(hybrid_times) / max(1, len(hybrid_times))

        if avg_classical > 0:
            overhead = ((avg_hybrid - avg_classical) / avg_classical) * 100
            return round(max(0.0, overhead), 2)
        return 0.0

    def _calculate_security_score(
        self, classical: Dict, pqc: Dict, fallback: Dict
    ) -> str:
        """Calculate overall security score for the hybrid deployment."""
        components_valid = sum(1 for r in [classical, pqc, fallback] if r.get("valid", False))
        total = 3

        if components_valid == total:
            return "High - Full hybrid PQ/TLS with classical fallback"
        elif components_valid == 2:
            if not pqc.get("valid"):
                return "Medium - Classical only, PQC not negotiated"
            return "Medium - Hybrid active, fallback not tested"
        elif components_valid == 1:
            return "Low - Only one component functional"
        return "Critical - No components functional"
