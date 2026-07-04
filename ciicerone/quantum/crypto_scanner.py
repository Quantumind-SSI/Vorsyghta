"""Crypto inventory scanner.

Scans target environments for quantum-vulnerable cryptographic implementations.
Detects RSA, ECC, DSA, Diffie-Hellman, AES, SHA, HMAC and maps them to
algorithm types and key sizes for quantum vulnerability analysis.
"""

import asyncio
import logging
import re
from typing import Any, Dict, List, Optional

from .models import CryptoAlgorithmType, CryptoInventoryItem

logger = logging.getLogger(__name__)


# Algorithm detection patterns
ALGORITHM_PATTERNS: Dict[str, re.Pattern] = {
    "RSA": re.compile(r"\bRSA[\s-]*(\d+)\b", re.IGNORECASE),
    "ECC": re.compile(r"\b(?:ECC|ECDSA|ECDH|EC)[\s-]*(?:P)?(\d+)\b", re.IGNORECASE),
    "DSA": re.compile(r"\bDSA[\s-]*(\d+)\b", re.IGNORECASE),
    "Diffie-Hellman": re.compile(r"\b(?:DH|DHE|Diffie[\s-]*Hellman)[\s-]*(\d+)\b", re.IGNORECASE),
    "AES": re.compile(r"\bAES[\s-]*(\d+)\b", re.IGNORECASE),
    "SHA": re.compile(r"\bSHA[\s-]*[\d]+(?:[\s-]*\d+)?\b", re.IGNORECASE),
    "HMAC": re.compile(r"\bHMAC[\s-]*(?:SHA)?[\s-]*\d+\b", re.IGNORECASE),
    "ChaCha20": re.compile(r"\bChaCha20[\s-]*(\d+)?\b", re.IGNORECASE),
    "Poly1305": re.compile(r"\bPoly1305\b", re.IGNORECASE),
    "Ed25519": re.compile(r"\bEd25519\b", re.IGNORECASE),
    "Ed448": re.compile(r"\bEd448\b", re.IGNORECASE),
    "X25519": re.compile(r"\bX25519\b", re.IGNORECASE),
    "X448": re.compile(r"\bX448\b", re.IGNORECASE),
}

# Algorithm type mapping
ALGORITHM_TYPE_MAP: Dict[str, CryptoAlgorithmType] = {
    "RSA": CryptoAlgorithmType.ENCRYPTION,
    "ECC": CryptoAlgorithmType.KEY_EXCHANGE,
    "ECDSA": CryptoAlgorithmType.SIGNATURE,
    "ECDH": CryptoAlgorithmType.KEY_EXCHANGE,
    "DSA": CryptoAlgorithmType.SIGNATURE,
    "Diffie-Hellman": CryptoAlgorithmType.KEY_EXCHANGE,
    "AES": CryptoAlgorithmType.SYMMETRIC,
    "SHA": CryptoAlgorithmType.HASH,
    "HMAC": CryptoAlgorithmType.HASH,
    "ChaCha20": CryptoAlgorithmType.SYMMETRIC,
    "Poly1305": CryptoAlgorithmType.SYMMETRIC,
    "Ed25519": CryptoAlgorithmType.SIGNATURE,
    "Ed448": CryptoAlgorithmType.SIGNATURE,
    "X25519": CryptoAlgorithmType.KEY_EXCHANGE,
    "X448": CryptoAlgorithmType.KEY_EXCHANGE,
}

# Default key sizes when not explicitly found
DEFAULT_KEY_SIZES: Dict[str, int] = {
    "Ed25519": 256,
    "Ed448": 448,
    "X25519": 256,
    "X448": 448,
    "ChaCha20": 256,
    "Poly1305": 256,
}

# SHA variants and their bit sizes
SHA_BITS: Dict[str, int] = {
    "SHA-1": 160,
    "SHA1": 160,
    "SHA-224": 224,
    "SHA224": 224,
    "SHA-256": 256,
    "SHA256": 256,
    "SHA-384": 384,
    "SHA384": 384,
    "SHA-512": 512,
    "SHA512": 512,
    "SHA-3": 256,
    "SHA3": 256,
}


class CryptoInventoryScanner:
    """Scans targets for quantum-vulnerable cryptographic implementations.

    Can scan:
    - Text output from commands (e.g., openssl s_client, ssh -Q)
    - Certificate data (PEM/DER parsed)
    - Configuration files (sshd_config, openssl.cnf)
    - Service banners
    - VM command output via VMOperator
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}

    async def scan(self, target: str, vm_operator: Any = None) -> List[CryptoInventoryItem]:
        """Scan a target for cryptographic implementations.

        Args:
            target: Target identifier (URL, IP, hostname, or VM ID)
            vm_operator: Optional VMOperator for scanning VMs

        Returns:
            List of detected crypto inventory items
        """
        logger.info(f"Starting crypto inventory scan for target: {target}")

        if vm_operator:
            items = await self._scan_vm(target, vm_operator)
        elif target.startswith(("http://", "https://")):
            items = await self._scan_tls_endpoint(target)
        else:
            items = await self._scan_hostname(target)

        logger.info(f"Crypto scan complete: {len(items)} implementations found")
        return items

    async def scan_text(self, text: str, location: str = "unknown") -> List[CryptoInventoryItem]:
        """Scan arbitrary text for cryptographic algorithm references.

        Args:
            text: Text to scan (command output, config file, certificate)
            location: Source location label

        Returns:
            List of detected crypto items
        """
        items: List[CryptoInventoryItem] = []
        seen: set = set()

        for algo_name, pattern in ALGORITHM_PATTERNS.items():
            for match in pattern.finditer(text):
                algo_key = algo_name.lower().replace("-", "").replace("_", "")

                key_size = self._extract_key_size(algo_name, match)
                dedup_key = f"{algo_name}:{key_size}:{location}"

                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                algo_type = ALGORITHM_TYPE_MAP.get(algo_name, CryptoAlgorithmType.UNKNOWN)

                items.append(CryptoInventoryItem(
                    algorithm=algo_name,
                    algorithm_type=algo_type,
                    key_size=key_size,
                    location=location,
                    protocol=self._detect_protocol(text),
                    metadata={"raw_match": match.group(0)},
                ))

        return items

    async def _scan_vm(self, vm_id: str, vm_operator: Any) -> List[CryptoInventoryItem]:
        """Scan a VM for crypto implementations using VMOperator."""
        items: List[CryptoInventoryItem] = []

        scan_commands = [
            ("TLS certificates", "openssl x509 -in /etc/ssl/certs/*.pem -text -noout 2>/dev/null || true"),
            ("SSH config", "cat /etc/ssh/sshd_config 2>/dev/null || true"),
            ("SSH host keys", "ssh-keygen -l -f /etc/ssh/ssh_host_* 2>/dev/null || true"),
            ("OpenSSL ciphers", "openssl ciphers -v 2>/dev/null || true"),
            ("Installed crypto libs", "dpkg -l 2>/dev/null | grep -iE 'openssl|gnutls|libsodium|liboqs' || true"),
        ]

        for label, cmd in scan_commands:
            try:
                result = await vm_operator.execute_command(vm_id, cmd, timeout_seconds=30)
                if result.exit_code == 0 and result.stdout:
                    found = await self.scan_text(result.stdout, f"vm:{vm_id}:{label}")
                    items.extend(found)
            except Exception as e:
                logger.warning(f"Failed to scan {label} on VM {vm_id}: {e}")

        return items

    async def _scan_tls_endpoint(self, url: str) -> List[CryptoInventoryItem]:
        """Scan a TLS endpoint for crypto implementations."""
        items: List[CryptoInventoryItem] = []

        try:
            proc = await asyncio.create_subprocess_exec(
                "openssl", "s_client", "-connect", url.split("//")[1].split("/")[0],
                "-showcerts", "-2>/dev/null",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            if stdout:
                output = stdout.decode("utf-8", errors="ignore")
                items = await self.scan_text(output, f"tls:{url}")
        except Exception as e:
            logger.warning(f"TLS scan failed for {url}: {e}")

        return items

    async def _scan_hostname(self, hostname: str) -> List[CryptoInventoryItem]:
        """Scan a hostname for SSH and TLS crypto."""
        items: List[CryptoInventoryItem] = []

        # Try SSH scan
        try:
            proc = await asyncio.create_subprocess_exec(
                "ssh-keyscan", "-T", "5", hostname,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            if stdout:
                output = stdout.decode("utf-8", errors="ignore")
                items.extend(await self.scan_text(output, f"ssh:{hostname}"))
        except Exception as e:
            logger.debug(f"SSH keyscan failed for {hostname}: {e}")

        # Try TLS scan
        try:
            proc = await asyncio.create_subprocess_exec(
                "openssl", "s_client", "-connect", f"{hostname}:443",
                "-showcerts",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            if stdout:
                output = stdout.decode("utf-8", errors="ignore")
                items.extend(await self.scan_text(output, f"tls:{hostname}:443"))
        except Exception as e:
            logger.debug(f"TLS scan failed for {hostname}: {e}")

        return items

    def _extract_key_size(self, algo_name: str, match: re.Match) -> int:
        """Extract key size from regex match."""
        if algo_name in DEFAULT_KEY_SIZES:
            return DEFAULT_KEY_SIZES[algo_name]

        if match.groups():
            try:
                return int(match.group(1))
            except (ValueError, IndexError):
                pass

        if algo_name.startswith("SHA"):
            raw = match.group(0).upper().replace("-", "").replace("_", "").replace(" ", "")
            for sha_variant, bits in SHA_BITS.items():
                if sha_variant.upper().replace("-", "") in raw:
                    return bits
            return 256  # Default SHA size

        if algo_name == "HMAC":
            raw = match.group(0)
            for sha_variant, bits in SHA_BITS.items():
                if sha_variant in raw:
                    return bits
            return 256

        return 0

    def _detect_protocol(self, text: str) -> Optional[str]:
        """Detect the protocol context from text."""
        text_lower = text.lower()
        if "tls" in text_lower or "ssl" in text_lower:
            return "TLS"
        if "ssh" in text_lower:
            return "SSH"
        if "ipsec" in text_lower:
            return "IPsec"
        if "openvpn" in text_lower:
            return "OpenVPN"
        return None
