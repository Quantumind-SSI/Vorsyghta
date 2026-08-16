"""
Crash Collection Pipeline

Collects, deduplicates, triages, and prioritizes crashes from fuzzing
campaigns. This is the central pipeline that turns raw fuzzer output
into actionable vulnerability findings.

Workflow:
    1. Collect: Scan fuzzing output dirs for crash files
    2. Deduplicate: Group crashes by stack trace signature
    3. Triage: Reproduce under GDB, classify crash type
    4. Prioritize: Rank by exploitability and severity
    5. Report: Generate structured vulnerability reports

Usage:
    from vorsyghta.research.crash_pipeline import CrashPipeline

    pipeline = CrashPipeline()
    catalog = await pipeline.collect_and_triage(
        findings_dir="/tmp/afl_findings",
        target_binary="/tmp/target",
        attacker_vm_ip="10.0.100.5",
    )
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import shlex
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class CrashType(str, Enum):
    """Classification of crash types."""
    SEGFAULT = "segfault"
    ABORT = "abort"
    FPE = "floating_point_exception"
    BUS_ERROR = "bus_error"
    ILLEGAL_INSTRUCTION = "illegal_instruction"
    STACK_OVERFLOW = "stack_overflow"
    TIMEOUT = "timeout"
    OOM = "out_of_memory"
    ASSERTION = "assertion_failure"
    UNKNOWN = "unknown"


class Exploitability(str, Enum):
    """Exploitability assessment."""
    HIGH = "high"               # Likely exploitable (e.g., write-what-where)
    MEDIUM = "medium"           # Potentially exploitable (e.g., heap overflow)
    LOW = "low"                 # Crash only, unlikely to exploit (e.g., null deref read)
    INFO_LEAK = "info_leak"     # Information disclosure
    DENIAL_OF_SERVICE = "dos"   # Crash only, no code execution
    UNKNOWN = "unknown"         # Needs further analysis


class CrashStatus(str, Enum):
    """Lifecycle status of a crash entry."""
    NEW = "new"
    TRIAGED = "triaged"
    CONFIRMED = "confirmed"
    DUPLICATE = "duplicate"
    FIXED = "fixed"
    REJECTED = "rejected"


@dataclass
class CrashEntry:
    """A single crash discovered during fuzzing."""
    id: str = ""
    file_path: str = ""
    input_hash: str = ""
    input_size: int = 0
    input_b64: str = ""             # Base64-encoded crash input (for small inputs)
    crash_type: CrashType = CrashType.UNKNOWN
    exploitability: Exploitability = Exploitability.UNKNOWN
    status: CrashStatus = CrashStatus.NEW
    stack_trace: str = ""
    stack_signature: str = ""       # Dedup key derived from stack trace
    registers: str = ""
    faulting_instruction: str = ""
    target_binary: str = ""
    fuzzer: str = ""                # afl, libfuzzer, honggfuzz, network
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    triaged_at: Optional[str] = None
    notes: str = ""
    cwe_id: Optional[str] = None    # e.g., "CWE-121" for stack overflow
    cvss_score: Optional[float] = None

    def __post_init__(self):
        if not self.id:
            self.id = hashlib.sha256(
                f"{self.input_hash}:{self.stack_signature}:{self.target_binary}".encode()
            ).hexdigest()[:16]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["crash_type"] = self.crash_type.value
        d["exploitability"] = self.exploitability.value
        d["status"] = self.status.value
        return d


@dataclass
class CrashCatalog:
    """A catalog of deduplicated, triaged crashes."""
    target_binary: str = ""
    total_raw_crashes: int = 0
    unique_crashes: int = 0
    crashes: List[CrashEntry] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    summary: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "target_binary": self.target_binary,
            "total_raw_crashes": self.total_raw_crashes,
            "unique_crashes": self.unique_crashes,
            "created_at": self.created_at,
            "summary": self.summary,
            "crashes": [c.to_dict() for c in self.crashes],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def save(self, path: str):
        with open(path, "w") as f:
            f.write(self.to_json())
        logger.info(f"Crash catalog saved to {path} ({self.unique_crashes} unique crashes)")


class CrashPipeline:
    """
    Orchestrates crash collection, deduplication, triage, and reporting.

    This pipeline runs on the Vorsyghta server (not on the attacker VM).
    It uses SSH to interact with the attacker VM where the fuzzer ran.
    """

    def __init__(self, ssh_username: str = "root", ssh_password: str = ""):
        """
        Args:
            ssh_username: SSH username for attacker VM
            ssh_password: SSH password for attacker VM
        """
        self.ssh_username = ssh_username
        self.ssh_password = ssh_password

    async def collect_and_triage(
        self,
        findings_dir: str,
        target_binary: str,
        attacker_vm_ip: str,
        fuzzer: str = "afl",
        max_triage: int = 50,
        ssh_timeout: int = 300,
    ) -> CrashCatalog:
        """Full pipeline: collect → dedup → triage → prioritize.

        Args:
            findings_dir: Path on the attacker VM containing crash files
            target_binary: Path on the attacker VM to the target binary
            attacker_vm_ip: IP of the attacker VM
            fuzzer: Which fuzzer produced the crashes (afl, libfuzzer, honggfuzz)
            max_triage: Maximum number of unique crashes to triage with GDB
            ssh_timeout: SSH command timeout

        Returns:
            CrashCatalog with deduplicated and triaged crashes
        """
        logger.info(f"Starting crash pipeline: {findings_dir} on {attacker_vm_ip}")

        # Step 1: Collect raw crash files
        raw_crashes = await self._collect_crash_files(
            findings_dir, attacker_vm_ip, fuzzer, ssh_timeout
        )
        logger.info(f"Collected {len(raw_crashes)} raw crash files")

        if not raw_crashes:
            return CrashCatalog(target_binary=target_binary)

        # Step 2: Deduplicate by stack signature
        unique = await self._deduplicate(
            raw_crashes, target_binary, attacker_vm_ip, ssh_timeout
        )
        logger.info(f"Deduplicated to {len(unique)} unique crashes")

        # Step 3: Triage top N unique crashes
        triaged = []
        for i, entry in enumerate(unique[:max_triage]):
            logger.info(f"Triaging crash {i+1}/{min(len(unique), max_triage)}: {entry.id}")
            triaged_entry = await self._triage_crash(
                entry, target_binary, attacker_vm_ip, ssh_timeout
            )
            triaged.append(triaged_entry)

        # Include remaining untriaged crashes
        for entry in unique[max_triage:]:
            entry.status = CrashStatus.NEW
            triaged.append(entry)

        # Step 4: Build catalog with summary
        catalog = CrashCatalog(
            target_binary=target_binary,
            total_raw_crashes=len(raw_crashes),
            unique_crashes=len(unique),
            crashes=triaged,
        )
        catalog.summary = self._build_summary(triaged)

        logger.info(
            f"Pipeline complete: {catalog.unique_crashes} unique, "
            f"{catalog.summary.get('triaged', 0)} triaged"
        )
        return catalog

    async def _collect_crash_files(
        self,
        findings_dir: str,
        vm_ip: str,
        fuzzer: str,
        timeout: int,
    ) -> List[dict]:
        """Find all crash files in the findings directory on the VM."""
        from vorsyghta.mcp.tools.vm_execute import execute_ssh_command

        # Fuzzer-specific crash file patterns
        patterns = {
            "afl": [
                f"find {findings_dir} -path '*/crashes/*' -type f",
                f"find {findings_dir} -path '*/hangs/*' -type f",
            ],
            "libfuzzer": [
                f"find {findings_dir} -maxdepth 1 -name 'crash-*' -type f",
                f"find {findings_dir} -maxdepth 1 -name 'leak-*' -type f",
            ],
            "honggfuzz": [
                f"find {findings_dir} -name '*.fuzz' -type f",
                f"find {findings_dir} -name 'crash*' -type f",
            ],
            "network": [
                f"cat /tmp/netfuzz_results.json 2>/dev/null",
            ],
        }

        cmds = patterns.get(fuzzer, patterns["afl"])
        all_files = []

        for cmd in cmds:
            result = await execute_ssh_command(
                host=vm_ip,
                command=cmd,
                username=self.ssh_username,
                password=self.ssh_password,
                timeout=timeout,
            )
            if result["exit_code"] == 0 and result["stdout"].strip():
                for line in result["stdout"].strip().split("\n"):
                    line = line.strip()
                    if line and not line.startswith("find "):
                        all_files.append({"file_path": line})

        # For network fuzzer, parse JSON results
        if fuzzer == "network" and all_files:
            try:
                data = json.loads(all_files[0]["file_path"])
                return [
                    {
                        "file_path": f"/tmp/netfuzz_crash_{c.get('iteration', i)}",
                        "input_b64": c.get("input", ""),
                        "error": c.get("error", ""),
                    }
                    for i, c in enumerate(data.get("crashes", []))
                ]
            except (json.JSONDecodeError, KeyError):
                pass

        return all_files

    async def _deduplicate(
        self,
        raw_crashes: List[dict],
        target_binary: str,
        vm_ip: str,
        timeout: int,
    ) -> List[CrashEntry]:
        """Deduplicate crashes by stack trace signature."""
        from vorsyghta.mcp.tools.vm_execute import execute_ssh_command

        entries: List[CrashEntry] = []
        seen_signatures: Dict[str, CrashEntry] = {}

        for raw in raw_crashes:
            file_path = raw.get("file_path", "")
            input_b64 = raw.get("input_b64", "")

            # Read crash input and compute hash
            # Skip if this is the netfuzz results JSON or if input_b64 is already provided
            if file_path and not input_b64 and os.path.basename(file_path) != "netfuzz_results.json":
                hash_cmd = f"sha256sum {shlex.quote(file_path)} 2>/dev/null | cut -d' ' -f1"
                size_cmd = f"stat -c %s {shlex.quote(file_path)} 2>/dev/null || wc -c < {shlex.quote(file_path)}"
                hash_result = await execute_ssh_command(
                    vm_ip, hash_cmd, self.ssh_username, self.ssh_password, timeout=10
                )
                size_result = await execute_ssh_command(
                    vm_ip, size_cmd, self.ssh_username, self.ssh_password, timeout=10
                )
                input_hash = hash_result["stdout"].strip()
                input_size = int(size_result["stdout"].strip() or 0)

                # For small inputs, base64-encode them
                if input_size < 4096:
                    b64_cmd = f"base64 -w0 {shlex.quote(file_path)} 2>/dev/null"
                    b64_result = await execute_ssh_command(
                        vm_ip, b64_cmd, self.ssh_username, self.ssh_password, timeout=10
                    )
                    input_b64 = b64_result["stdout"].strip()
            else:
                input_hash = hashlib.sha256(input_b64.encode()).hexdigest()
                input_size = len(base64.b64decode(input_b64)) if input_b64 else 0

            # Get quick stack signature for dedup
            stack_sig = ""
            if file_path and target_binary:
                gdb_cmd = (
                    f"gdb -batch -q -ex 'set pagination off' "
                    f"-ex 'run < {shlex.quote(file_path)}' "
                    f"-ex 'bt 3' "
                    f"-ex 'quit' {shlex.quote(target_binary)} 2>&1 | "
                    f"grep '^#' | head -3"
                )
                gdb_result = await execute_ssh_command(
                    vm_ip, gdb_cmd, self.ssh_username, self.ssh_password, timeout=15
                )
                stack_sig = hashlib.sha256(
                    gdb_result["stdout"].strip().encode()
                ).hexdigest()[:16]

            # Dedup
            dedup_key = stack_sig or input_hash
            if dedup_key in seen_signatures:
                existing = seen_signatures[dedup_key]
                existing.notes += f"\nDuplicate: {file_path}"
                continue

            entry = CrashEntry(
                file_path=file_path,
                input_hash=input_hash,
                input_size=input_size,
                input_b64=input_b64[:10000] if input_b64 else "",
                stack_signature=stack_sig,
                target_binary=target_binary,
                fuzzer=raw.get("fuzzer", ""),
            )
            seen_signatures[dedup_key] = entry
            entries.append(entry)

        return entries

    async def _triage_crash(
        self,
        entry: CrashEntry,
        target_binary: str,
        vm_ip: str,
        timeout: int,
    ) -> CrashEntry:
        """Triage a single crash with GDB for full analysis."""
        from vorsyghta.mcp.tools.vm_execute import execute_ssh_command

        if not entry.file_path:
            entry.status = CrashStatus.TRIAGED
            return entry

        gdb_cmd = (
            f"gdb -batch -q -ex 'set pagination off' "
            f"-ex 'run < {shlex.quote(entry.file_path)}' "
            f"-ex 'bt full' "
            f"-ex 'info registers' "
            f"-ex 'x/i $pc' "
            f"-ex 'quit' {shlex.quote(target_binary)} 2>&1"
        )

        result = await execute_ssh_command(
            vm_ip, gdb_cmd, self.ssh_username, self.ssh_password, timeout=30
        )

        output = result["stdout"]
        entry.stack_trace = output[:10000]

        # Classify crash type
        entry.crash_type = self._classify_crash(output)

        # Assess exploitability
        entry.exploitability = self._assess_exploitability(output, entry.crash_type)

        # Extract faulting instruction
        for line in output.split("\n"):
            if "=>" in line and "0x" in line:
                entry.faulting_instruction = line.strip()
                break

        # Map to CWE
        entry.cwe_id = self._map_to_cwe(entry.crash_type, entry.exploitability)

        # Calculate CVSS
        entry.cvss_score = self._estimate_cvss(entry.crash_type, entry.exploitability)

        entry.status = CrashStatus.TRIAGED
        entry.triaged_at = datetime.utcnow().isoformat()

        return entry

    def _classify_crash(self, gdb_output: str) -> CrashType:
        """Classify crash type from GDB output."""
        output_lower = gdb_output.lower()
        if "sigsegv" in output_lower:
            if "stack overflow" in output_lower or "stack smashing" in output_lower:
                return CrashType.STACK_OVERFLOW
            return CrashType.SEGFAULT
        elif "sigabrt" in output_lower:
            if "assert" in output_lower:
                return CrashType.ASSERTION
            return CrashType.ABORT
        elif "sigfpe" in output_lower:
            return CrashType.FPE
        elif "sigbus" in output_lower:
            return CrashType.BUS_ERROR
        elif "sigill" in output_lower:
            return CrashType.ILLEGAL_INSTRUCTION
        elif "timeout" in output_lower or "timed out" in output_lower:
            return CrashType.TIMEOUT
        elif "out of memory" in output_lower or "oom" in output_lower:
            return CrashType.OOM
        return CrashType.UNKNOWN

    def _assess_exploitability(
        self, gdb_output: str, crash_type: CrashType
    ) -> Exploitability:
        """Assess exploitability from GDB output and crash type."""
        output_lower = gdb_output.lower()

        # High exploitability indicators
        if any(kw in output_lower for kw in [
            "write", "heap overflow", "buffer overflow",
            "use-after-free", "double free", "format string",
            "arbitrary write", "what-where",
        ]):
            return Exploitability.HIGH

        # Medium exploitability
        if crash_type in [CrashType.SEGFAULT, CrashType.ABORT]:
            if "heap" in output_lower or "malloc" in output_lower:
                return Exploitability.MEDIUM
            if "overflow" in output_lower:
                return Exploitability.MEDIUM

        # Info leak
        if "read" in output_lower and ("uninitialized" in output_lower or "leak" in output_lower):
            return Exploitability.INFO_LEAK

        # DoS only
        if crash_type in [CrashType.TIMEOUT, CrashType.OOM, CrashType.ASSERTION]:
            return Exploitability.DENIAL_OF_SERVICE

        # Low: null deref read
        if "0x0" in output_lower and "read" in output_lower:
            return Exploitability.LOW

        return Exploitability.UNKNOWN

    def _map_to_cwe(
        self, crash_type: CrashType, exploitability: Exploitability
    ) -> Optional[str]:
        """Map crash type to CWE ID."""
        cwe_map = {
            CrashType.SEGFAULT: {
                Exploitability.HIGH: "CWE-787",   # Out-of-bounds write
                Exploitability.MEDIUM: "CWE-122", # Heap overflow
                Exploitability.LOW: "CWE-476",    # NULL pointer deref
            },
            CrashType.STACK_OVERFLOW: "CWE-121",  # Stack overflow
            CrashType.ABORT: "CWE-755",           # Abnormal termination
            CrashType.FPE: "CWE-369",             # Divide by zero
            CrashType.ASSERTION: "CWE-617",       # Reachable assertion
        }

        if crash_type == CrashType.SEGFAULT and isinstance(cwe_map.get(crash_type), dict):
            return cwe_map[crash_type].get(exploitability, "CWE-119")
        return cwe_map.get(crash_type)

    def _estimate_cvss(
        self, crash_type: CrashType, exploitability: Exploitability
    ) -> float:
        """Rough CVSS score estimate based on crash type and exploitability."""
        base_scores = {
            Exploitability.HIGH: 9.0,
            Exploitability.MEDIUM: 7.0,
            Exploitability.LOW: 4.0,
            Exploitability.INFO_LEAK: 5.3,
            Exploitability.DENIAL_OF_SERVICE: 6.5,
            Exploitability.UNKNOWN: 5.0,
        }
        return base_scores.get(exploitability, 5.0)

    def _build_summary(self, crashes: List[CrashEntry]) -> Dict[str, int]:
        """Build summary statistics from triaged crashes."""
        summary = {
            "total": len(crashes),
            "triaged": sum(1 for c in crashes if c.status == CrashStatus.TRIAGED),
            "new": sum(1 for c in crashes if c.status == CrashStatus.NEW),
            "high_exploitability": sum(1 for c in crashes if c.exploitability == Exploitability.HIGH),
            "medium_exploitability": sum(1 for c in crashes if c.exploitability == Exploitability.MEDIUM),
            "low_exploitability": sum(1 for c in crashes if c.exploitability == Exploitability.LOW),
            "dos": sum(1 for c in crashes if c.exploitability == Exploitability.DENIAL_OF_SERVICE),
            "info_leak": sum(1 for c in crashes if c.exploitability == Exploitability.INFO_LEAK),
        }
        # By crash type
        for ct in CrashType:
            count = sum(1 for c in crashes if c.crash_type == ct)
            if count > 0:
                summary[f"type_{ct.value}"] = count
        return summary
