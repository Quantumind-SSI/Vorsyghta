"""
Discovery Tools — Zero-Day Vulnerability Research Toolchain

MCP tools for vulnerability discovery, fuzzing, static analysis, and binary
analysis. These tools extend Ciicerone beyond known-vulnerability scanning
into zero-day research: finding *new* vulnerabilities in client targets.

Tool categories:
    - Fuzzing: AFL++, libFuzzer, honggfuzz, network protocol fuzzing
    - SAST: Semgrep, CodeQL, Bandit static analysis
    - Binary analysis: Ghidra headless, radare2, binary diffing
    - API fuzzing: ffuf, kiterunner, RESTler-style grammar fuzzing
    - Crash triage: collect, deduplicate, and prioritize crashes

All tools execute on attacker VMs via SSH and pass through the safety
controller. Fuzzing targets must be in the allowed attack network.
"""

import json
import logging
import shlex
from typing import Any, List

try:
    from mcp.types import Tool, TextContent
except ImportError:
    Tool = Any
    TextContent = Any

from ..providers.proxmox import ProxmoxClient
from ..config import MCPConfig
from ..safety import SafetyController
from .vm_execute import execute_ssh_command

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Tool Definitions
# ---------------------------------------------------------------------------

DISCOVERY_TOOLS: List[Tool] = [
    # --- Fuzzing -----------------------------------------------------------
    Tool(
        name="discovery_afl_fuzz",
        description="""Run AFL++ (American Fuzzy Lop++) coverage-guided fuzzer.

Launches a fuzzing campaign against a binary on the attacker VM.
AFL++ mutates inputs based on code coverage feedback to discover
new code paths and crashes.

Modes:
- binary: Fuzz a standalone binary (AFL_NO_AFFINITY=1 afl-fuzz -i corpus -o findings -- ./target @@)
- stdin:  Fuzz via stdin (afl-fuzz -i corpus -o findings -- ./target)
- network: Fuzz a network service via afl-network-proxy

Requires AFL++ installed on the attacker VM.

SAFETY: Target must be in the allowed attack network. Fuzzing is
resource-intensive; use timeout to limit campaign duration.""",
        inputSchema={
            "type": "object",
            "properties": {
                "attacker_vm_id": {
                    "type": "string",
                    "description": "Attacker VM ID running AFL++"
                },
                "target_binary": {
                    "type": "string",
                    "description": "Path to target binary on the attacker VM"
                },
                "corpus_dir": {
                    "type": "string",
                    "description": "Path to seed corpus directory",
                    "default": "/tmp/afl_corpus"
                },
                "output_dir": {
                    "type": "string",
                    "description": "Path to store fuzzing results",
                    "default": "/tmp/afl_findings"
                },
                "mode": {
                    "type": "string",
                    "enum": ["binary", "stdin", "network"],
                    "default": "binary",
                    "description": "Fuzzing mode"
                },
                "timeout_seconds": {
                    "type": "integer",
                    "description": "Campaign duration in seconds (default: 3600)",
                    "default": 3600
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional AFL++ arguments (e.g., '-m 500 -t 1000')"
                }
            },
            "required": ["attacker_vm_id", "target_binary"]
        }
    ),
    Tool(
        name="discovery_libfuzzer",
        description="""Run libFuzzer (LLVM in-process fuzzer).

Executes a libFuzzer-instrumented harness for coverage-guided
fuzzing. The target must be compiled with -fsanitize=fuzzer.

Returns crash inputs, coverage stats, and corpus size.

Requires clang/llvm with libFuzzer support on the attacker VM.""",
        inputSchema={
            "type": "object",
            "properties": {
                "attacker_vm_id": {
                    "type": "string",
                    "description": "Attacker VM ID"
                },
                "harness_binary": {
                    "type": "string",
                    "description": "Path to libFuzzer harness binary"
                },
                "corpus_dir": {
                    "type": "string",
                    "description": "Path to seed corpus directory",
                    "default": "/tmp/libfuzzer_corpus"
                },
                "timeout_seconds": {
                    "type": "integer",
                    "description": "Campaign duration in seconds (default: 1800)",
                    "default": 1800
                },
                "max_len": {
                    "type": "integer",
                    "description": "Maximum input length (default: 4096)",
                    "default": 4096
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional libFuzzer arguments"
                }
            },
            "required": ["attacker_vm_id", "harness_binary"]
        }
    ),
    Tool(
        name="discovery_honggfuzz",
        description="""Run honggfuzz for coverage-guided or hardware-based fuzzing.

Honggfuzz supports software (coverage) and hardware (Perf/BTS)
feedback. Useful for fuzzing closed-source binaries where source
instrumentation is not possible.

Modes:
- coverage: Coverage-guided using -p (perf) feedback
- sw: Software-only feedback (code coverage via pin/blocks)
- hw: Hardware-based (Intel BTS / Intel PT)

Requires honggfuzz installed on the attacker VM.""",
        inputSchema={
            "type": "object",
            "properties": {
                "attacker_vm_id": {
                    "type": "string",
                    "description": "Attacker VM ID"
                },
                "target_binary": {
                    "type": "string",
                    "description": "Path to target binary"
                },
                "corpus_dir": {
                    "type": "string",
                    "description": "Path to seed corpus",
                    "default": "/tmp/hf_corpus"
                },
                "output_dir": {
                    "type": "string",
                    "description": "Path to store findings",
                    "default": "/tmp/hf_findings"
                },
                "mode": {
                    "type": "string",
                    "enum": ["coverage", "sw", "hw"],
                    "default": "coverage"
                },
                "timeout_seconds": {
                    "type": "integer",
                    "description": "Campaign duration (default: 3600)",
                    "default": 3600
                }
            },
            "required": ["attacker_vm_id", "target_binary"]
        }
    ),
    Tool(
        name="discovery_network_fuzz",
        description="""Fuzz a network service with mutated protocol inputs.

Sends mutated network packets to a target service to discover
parsing vulnerabilities, buffer overflows, and protocol confusion
bugs. Uses a combination of radamsa mutation and custom mutators.

Supports TCP and UDP targets. Useful for fuzzing proprietary
protocols, IoT devices, and network services.

SAFETY: Target must be in the allowed attack network.""",
        inputSchema={
            "type": "object",
            "properties": {
                "attacker_vm_id": {
                    "type": "string",
                    "description": "Attacker VM ID"
                },
                "target_ip": {
                    "type": "string",
                    "description": "Target service IP (must be in allowed network)"
                },
                "target_port": {
                    "type": "integer",
                    "description": "Target service port"
                },
                "protocol": {
                    "type": "string",
                    "enum": ["tcp", "udp"],
                    "default": "tcp"
                },
                "seed_input": {
                    "type": "string",
                    "description": "Base64-encoded seed input or capture (pcap path on VM)"
                },
                "iterations": {
                    "type": "integer",
                    "description": "Number of mutation iterations (default: 10000)",
                    "default": 10000
                },
                "timeout_seconds": {
                    "type": "integer",
                    "description": "Campaign timeout (default: 1800)",
                    "default": 1800
                }
            },
            "required": ["attacker_vm_id", "target_ip", "target_port"]
        }
    ),

    # --- API Fuzzing -------------------------------------------------------
    Tool(
        name="discovery_ffuf",
        description="""Run ffuf for web fuzzing — directories, files, parameters, and vhosts.

High-speed web fuzzer for content discovery and parameter brute-forcing.
Supports recursion, rate limiting, and multiple wordlists.

Modes:
- dir: Directory/file enumeration
- param: Parameter name discovery
- vhost: Virtual host discovery
- fuzz: Full URL fuzzing with keyword injection (FUZZ keyword)""",
        inputSchema={
            "type": "object",
            "properties": {
                "attacker_vm_id": {
                    "type": "string",
                    "description": "Attacker VM ID"
                },
                "target_url": {
                    "type": "string",
                    "description": "Target URL with FUZZ keyword (e.g., http://10.0.100.10/FUZZ)"
                },
                "wordlist": {
                    "type": "string",
                    "description": "Path to wordlist on attacker VM",
                    "default": "/usr/share/wordlists/dirb/common.txt"
                },
                "mode": {
                    "type": "string",
                    "enum": ["dir", "param", "vhost", "fuzz"],
                    "default": "dir"
                },
                "rate": {
                    "type": "integer",
                    "description": "Requests per second (0 = unlimited)",
                    "default": 0
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional ffuf arguments"
                }
            },
            "required": ["attacker_vm_id", "target_url"]
        }
    ),
    Tool(
        name="discovery_api_fuzz",
        description="""Grammar-based API fuzzing using OpenAPI/Swagger specifications.

Parses an OpenAPI spec and sends mutated, type-aware requests to
each endpoint. Detects:
- 5xx errors (server crashes, unhandled exceptions)
- Unexpected response codes
- Schema validation failures
- Injection points (SQLi, NoSQLi, command injection)

Requires the target API's OpenAPI spec (URL or file path on VM).""",
        inputSchema={
            "type": "object",
            "properties": {
                "attacker_vm_id": {
                    "type": "string",
                    "description": "Attacker VM ID"
                },
                "target_url": {
                    "type": "string",
                    "description": "Base URL of the target API"
                },
                "openapi_spec": {
                    "type": "string",
                    "description": "URL or file path to OpenAPI/Swagger spec"
                },
                "duration_seconds": {
                    "type": "integer",
                    "description": "Fuzzing duration (default: 600)",
                    "default": 600
                },
                "auth_header": {
                    "type": "string",
                    "description": "Optional Authorization header value"
                }
            },
            "required": ["attacker_vm_id", "target_url", "openapi_spec"]
        }
    ),

    # --- SAST (Static Analysis) -------------------------------------------
    Tool(
        name="discovery_semgrep",
        description="""Run Semgrep static analysis on source code.

Scans source code for security vulnerabilities, code smells, and
anti-patterns using custom or community rulesets. Supports 30+
languages.

Rulepacks:
- p/owasp-top-ten: OWASP Top 10 vulnerabilities
- p/security-audit: Broad security audit
- p/cwe-top-25: CWE Top 25
- custom: User-provided rules file

Requires semgrep installed on the attacker VM.""",
        inputSchema={
            "type": "object",
            "properties": {
                "attacker_vm_id": {
                    "type": "string",
                    "description": "Attacker VM ID"
                },
                "source_path": {
                    "type": "string",
                    "description": "Path to source code on the attacker VM"
                },
                "ruleset": {
                    "type": "string",
                    "description": "Semgrep ruleset (e.g., 'p/owasp-top-ten') or path to custom rules",
                    "default": "p/security-audit"
                },
                "output_format": {
                    "type": "string",
                    "enum": ["json", "text", "sarif"],
                    "default": "json"
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional semgrep arguments"
                }
            },
            "required": ["attacker_vm_id", "source_path"]
        }
    ),
    Tool(
        name="discovery_codeql",
        description="""Run GitHub CodeQL static analysis queries on a codebase.

Executes CodeQL queries against a database built from the target
source code. Supports custom queries for vulnerability patterns.

Workflow:
1. Build CodeQL database from source (create-database)
2. Run queries (database analyze)
3. Interpret results (bqrs decode)

Requires CodeQL CLI installed on the attacker VM.""",
        inputSchema={
            "type": "object",
            "properties": {
                "attacker_vm_id": {
                    "type": "string",
                    "description": "Attacker VM ID"
                },
                "source_path": {
                    "type": "string",
                    "description": "Path to source code on the attacker VM"
                },
                "language": {
                    "type": "string",
                    "enum": ["cpp", "csharp", "go", "java", "javascript", "python", "ruby"],
                    "description": "Target language for CodeQL database"
                },
                "query_suite": {
                    "type": "string",
                    "description": "CodeQL query suite (e.g., 'codeql/cpp-queries:security')",
                    "default": "security"
                },
                "database_path": {
                    "type": "string",
                    "description": "Path to store/load CodeQL database",
                    "default": "/tmp/codeql_db"
                }
            },
            "required": ["attacker_vm_id", "source_path", "language"]
        }
    ),
    Tool(
        name="discovery_bandit",
        description="""Run Bandit static analysis on Python source code.

Scans Python code for common security issues (assert statements,
hardcoded passwords, unsafe YAML loads, shell injection, etc.).

Fast and lightweight — good for quick triage of Python codebases.
Requires bandit installed on the attacker VM.""",
        inputSchema={
            "type": "object",
            "properties": {
                "attacker_vm_id": {
                    "type": "string",
                    "description": "Attacker VM ID"
                },
                "source_path": {
                    "type": "string",
                    "description": "Path to Python source code on the attacker VM"
                },
                "severity_level": {
                    "type": "string",
                    "enum": ["low", "medium", "high"],
                    "default": "medium",
                    "description": "Minimum severity to report"
                },
                "output_format": {
                    "type": "string",
                    "enum": ["json", "txt", "xml"],
                    "default": "json"
                }
            },
            "required": ["attacker_vm_id", "source_path"]
        }
    ),

    # --- Binary Analysis ---------------------------------------------------
    Tool(
        name="discovery_ghidra_headless",
        description="""Run Ghidra headless analysis on a binary.

Performs automated decompilation, function discovery, and
vulnerability pattern detection using Ghidra scripts.

Modes:
- decompile: Decompile all functions and export to C
- strings: Extract and analyze strings
- functions: List all discovered functions with signatures
- vuln_scan: Run vulnerability detection scripts (buffer overflow patterns, format strings, etc.)
- custom: Run a user-provided Ghidra script

Requires Ghidra installed on the attacker VM.""",
        inputSchema={
            "type": "object",
            "properties": {
                "attacker_vm_id": {
                    "type": "string",
                    "description": "Attacker VM ID"
                },
                "target_binary": {
                    "type": "string",
                    "description": "Path to target binary on the attacker VM"
                },
                "mode": {
                    "type": "string",
                    "enum": ["decompile", "strings", "functions", "vuln_scan", "custom"],
                    "default": "decompile"
                },
                "project_dir": {
                    "type": "string",
                    "description": "Ghidra project directory",
                    "default": "/tmp/ghidra_project"
                },
                "custom_script": {
                    "type": "string",
                    "description": "Path to custom Ghidra script (for mode=custom)"
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional Ghidra headless arguments"
                }
            },
            "required": ["attacker_vm_id", "target_binary"]
        }
    ),
    Tool(
        name="discovery_radare2",
        description="""Run radare2 binary analysis commands.

Executes radare2 commands for reverse engineering, vulnerability
analysis, and exploit development support.

Modes:
- info: Binary metadata (architecture, sections, imports)
- functions: List functions with sizes
- strings: Extract strings
- xrefs: Cross-references for a specific address/symbol
- decompile: Decompile function at address (requires r2ghidra/retdec)
- security: Check security mitigations (NX, PIE, RELRO, canary, RPATH)
- rop: Find ROP gadgets
- custom: Run arbitrary r2 command string""",
        inputSchema={
            "type": "object",
            "properties": {
                "attacker_vm_id": {
                    "type": "string",
                    "description": "Attacker VM ID"
                },
                "target_binary": {
                    "type": "string",
                    "description": "Path to target binary on the attacker VM"
                },
                "mode": {
                    "type": "string",
                    "enum": ["info", "functions", "strings", "xrefs", "decompile", "security", "rop", "custom"],
                    "default": "info"
                },
                "address": {
                    "type": "string",
                    "description": "Address or symbol for xrefs/decompile modes (e.g., 'main', '0x401000')"
                },
                "custom_command": {
                    "type": "string",
                    "description": "Raw r2 command string (for mode=custom)"
                }
            },
            "required": ["attacker_vm_id", "target_binary"]
        }
    ),
    Tool(
        name="discovery_binary_diff",
        description="""Diff two versions of a binary to find patched vulnerabilities.

Compares two binary versions using BinDiff-style analysis to
identify functions that changed between versions. Changed functions
often correspond to security patches — analyzing the diff reveals
the vulnerability that was fixed.

Requires radare2 with r2diff or bindiff plugin on the attacker VM.""",
        inputSchema={
            "type": "object",
            "properties": {
                "attacker_vm_id": {
                    "type": "string",
                    "description": "Attacker VM ID"
                },
                "binary_old": {
                    "type": "string",
                    "description": "Path to the older binary version"
                },
                "binary_new": {
                    "type": "string",
                    "description": "Path to the newer binary version"
                },
                "output_dir": {
                    "type": "string",
                    "description": "Directory to store diff results",
                    "default": "/tmp/bindiff_results"
                }
            },
            "required": ["attacker_vm_id", "binary_old", "binary_new"]
        }
    ),

    # --- Crash Triage ------------------------------------------------------
    Tool(
        name="discovery_crash_collect",
        description="""Collect and catalog crashes from a fuzzing campaign.

Scans a fuzzing output directory for crash files, extracts metadata
(crash type, stack trace, input hash), and produces a structured
catalog. Deduplicates crashes by stack trace signature.

Use after discovery_afl_fuzz, discovery_libfuzzer, or
discovery_honggfuzz to triage results.""",
        inputSchema={
            "type": "object",
            "properties": {
                "attacker_vm_id": {
                    "type": "string",
                    "description": "Attacker VM ID"
                },
                "findings_dir": {
                    "type": "string",
                    "description": "Path to fuzzing findings directory (e.g., /tmp/afl_findings)"
                },
                "target_binary": {
                    "type": "string",
                    "description": "Path to the target binary (for reproducing crashes)"
                },
                "output_file": {
                    "type": "string",
                    "description": "Path to write crash catalog JSON",
                    "default": "/tmp/crash_catalog.json"
                }
            },
            "required": ["attacker_vm_id", "findings_dir"]
        }
    ),
    Tool(
        name="discovery_crash_triage",
        description="""Triage a specific crash — root cause analysis with GDB.

Reproduces a crash under GDB, captures the full stack trace,
register state, and faulting instruction. Classifies the crash
type (buffer overflow, use-after-free, null deref, etc.) and
assesses exploitability.

Requires GDB installed on the attacker VM.""",
        inputSchema={
            "type": "object",
            "properties": {
                "attacker_vm_id": {
                    "type": "string",
                    "description": "Attacker VM ID"
                },
                "target_binary": {
                    "type": "string",
                    "description": "Path to the target binary"
                },
                "crash_input": {
                    "type": "string",
                    "description": "Path to the crash-triggering input file"
                },
                "gdb_script": {
                    "type": "string",
                    "description": "Optional custom GDB script path. If omitted, a default triage script is used."
                }
            },
            "required": ["attacker_vm_id", "target_binary", "crash_input"]
        }
    ),
]


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

async def handle_discovery_tools(
    name: str,
    arguments: dict,
    proxmox: ProxmoxClient,
    config: MCPConfig,
    safety: SafetyController
) -> list:
    """Handle discovery tool calls.

    Args:
        name: Tool name
        arguments: Tool arguments
        proxmox: Proxmox client
        config: MCP configuration
        safety: Safety controller

    Returns:
        List of TextContent responses
    """
    if name == "discovery_afl_fuzz":
        return await _handle_afl_fuzz(arguments, proxmox, safety)
    elif name == "discovery_libfuzzer":
        return await _handle_libfuzzer(arguments, proxmox, safety)
    elif name == "discovery_honggfuzz":
        return await _handle_honggfuzz(arguments, proxmox, safety)
    elif name == "discovery_network_fuzz":
        return await _handle_network_fuzz(arguments, proxmox, safety)
    elif name == "discovery_ffuf":
        return await _handle_ffuf(arguments, proxmox, safety)
    elif name == "discovery_api_fuzz":
        return await _handle_api_fuzz(arguments, proxmox, safety)
    elif name == "discovery_semgrep":
        return await _handle_semgrep(arguments, proxmox, safety)
    elif name == "discovery_codeql":
        return await _handle_codeql(arguments, proxmox, safety)
    elif name == "discovery_bandit":
        return await _handle_bandit(arguments, proxmox, safety)
    elif name == "discovery_ghidra_headless":
        return await _handle_ghidra(arguments, proxmox, safety)
    elif name == "discovery_radare2":
        return await _handle_radare2(arguments, proxmox, safety)
    elif name == "discovery_binary_diff":
        return await _handle_binary_diff(arguments, proxmox, safety)
    elif name == "discovery_crash_collect":
        return await _handle_crash_collect(arguments, proxmox, safety)
    elif name == "discovery_crash_triage":
        return await _handle_crash_triage(arguments, proxmox, safety)
    else:
        return [TextContent(
            type="text",
            text=json.dumps({"error": f"Unknown discovery tool: {name}"})
        )]


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

async def _get_vm_ip_and_validate(
    vm_id_str: str,
    proxmox: ProxmoxClient,
    safety: SafetyController,
    target_ip: str = None,
) -> tuple:
    """Get VM IP, validate it, and return (ip_address, error_textcontent_or_none)."""
    vm_id = int(vm_id_str)
    ip_address = await proxmox.get_vm_ip(vm_id)
    if not ip_address:
        return None, [TextContent(
            type="text",
            text=json.dumps({"error": f"Could not get IP for VM {vm_id}"})
        )]

    is_allowed, reason = safety.validate_network(ip_address)
    if not is_allowed:
        return None, [TextContent(
            type="text",
            text=json.dumps({"error": "Attacker VM IP blocked", "reason": reason})
        )]

    if target_ip:
        is_allowed, reason = safety.validate_network(target_ip)
        if not is_allowed:
            return None, [TextContent(
                type="text",
                text=json.dumps({"error": "Target blocked by safety controller", "reason": reason})
            )]

    return ip_address, None


# ---------------------------------------------------------------------------
# Fuzzing Handlers
# ---------------------------------------------------------------------------

async def _handle_afl_fuzz(arguments, proxmox, safety) -> list:
    vm_id = arguments["attacker_vm_id"]
    target_binary = arguments["target_binary"]
    corpus_dir = arguments.get("corpus_dir", "/tmp/afl_corpus")
    output_dir = arguments.get("output_dir", "/tmp/afl_findings")
    mode = arguments.get("mode", "binary")
    timeout = arguments.get("timeout_seconds", 3600)
    extra_args = arguments.get("extra_args", "")

    ip_address, err = await _get_vm_ip_and_validate(vm_id, proxmox, safety)
    if err:
        return err

    # Prepare corpus and output dirs (shlex.quote to prevent shell injection)
    await execute_ssh_command(ip_address, f"mkdir -p {shlex.quote(corpus_dir)} {shlex.quote(output_dir)}", timeout=10)

    # Build command based on mode
    if mode == "network":
        afl_cmd = (
            f"AFL_NO_AFFINITY=1 timeout {timeout} afl-fuzz "
            f"-i {shlex.quote(corpus_dir)} -o {shlex.quote(output_dir)} {extra_args} "
            f"-- {shlex.quote(target_binary)}"
        )
    elif mode == "stdin":
        afl_cmd = (
            f"AFL_NO_AFFINITY=1 timeout {timeout} afl-fuzz "
            f"-i {shlex.quote(corpus_dir)} -o {shlex.quote(output_dir)} {extra_args} "
            f"-- {shlex.quote(target_binary)}"
        )
    else:  # binary
        afl_cmd = (
            f"AFL_NO_AFFINITY=1 timeout {timeout} afl-fuzz "
            f"-i {shlex.quote(corpus_dir)} -o {shlex.quote(output_dir)} {extra_args} "
            f"-- {shlex.quote(target_binary)} @@"
        )

    is_safe, reason = safety.validate_command(afl_cmd)
    if not is_safe:
        return [TextContent(type="text", text=json.dumps({"error": "Command blocked", "reason": reason}))]

    result = await execute_ssh_command(ip_address, afl_cmd, timeout=timeout + 30)

    # Collect stats
    stats_cmd = f"afl-whatsup -s {shlex.quote(output_dir)} 2>/dev/null || true"
    stats_result = await execute_ssh_command(ip_address, stats_cmd, timeout=15)

    crash_count_cmd = f"find {shlex.quote(output_dir)}/default/crashes -type f 2>/dev/null | wc -l"
    crash_count = await execute_ssh_command(ip_address, crash_count_cmd, timeout=10)

    return [TextContent(
        type="text",
        text=json.dumps({
            "tool": "afl_fuzz",
            "target_binary": target_binary,
            "mode": mode,
            "duration_seconds": timeout,
            "stdout": result["stdout"][-5000:],
            "stderr": result["stderr"][-2000:],
            "exit_code": result["exit_code"],
            "stats": stats_result["stdout"][:3000],
            "crash_count": int(crash_count["stdout"].strip() or 0),
            "findings_dir": output_dir
        }, indent=2)
    )]


async def _handle_libfuzzer(arguments, proxmox, safety) -> list:
    vm_id = arguments["attacker_vm_id"]
    harness = arguments["harness_binary"]
    corpus_dir = arguments.get("corpus_dir", "/tmp/libfuzzer_corpus")
    timeout = arguments.get("timeout_seconds", 1800)
    max_len = arguments.get("max_len", 4096)
    extra_args = arguments.get("extra_args", "")

    ip_address, err = await _get_vm_ip_and_validate(vm_id, proxmox, safety)
    if err:
        return err

    await execute_ssh_command(ip_address, f"mkdir -p {shlex.quote(corpus_dir)}", timeout=10)

    cmd = (
        f"timeout {timeout} {shlex.quote(harness)} {shlex.quote(corpus_dir)} "
        f"-max_len={max_len} -timeout=30 {extra_args} 2>&1"
    )

    is_safe, reason = safety.validate_command(cmd)
    if not is_safe:
        return [TextContent(type="text", text=json.dumps({"error": "Command blocked", "reason": reason}))]

    result = await execute_ssh_command(ip_address, cmd, timeout=timeout + 30)

    # Count crash artifacts
    crash_cmd = f"ls -1 crash-* leak-* 2>/dev/null | wc -l"
    crash_count = await execute_ssh_command(ip_address, crash_cmd, timeout=10)

    return [TextContent(
        type="text",
        text=json.dumps({
            "tool": "libfuzzer",
            "harness": harness,
            "max_len": max_len,
            "duration_seconds": timeout,
            "stdout": result["stdout"][-5000:],
            "stderr": result["stderr"][-2000:],
            "exit_code": result["exit_code"],
            "crash_artifact_count": int(crash_count["stdout"].strip() or 0)
        }, indent=2)
    )]


async def _handle_honggfuzz(arguments, proxmox, safety) -> list:
    vm_id = arguments["attacker_vm_id"]
    target_binary = arguments["target_binary"]
    corpus_dir = arguments.get("corpus_dir", "/tmp/hf_corpus")
    output_dir = arguments.get("output_dir", "/tmp/hf_findings")
    mode = arguments.get("mode", "coverage")
    timeout = arguments.get("timeout_seconds", 3600)

    ip_address, err = await _get_vm_ip_and_validate(vm_id, proxmox, safety)
    if err:
        return err

    await execute_ssh_command(ip_address, f"mkdir -p {shlex.quote(corpus_dir)} {shlex.quote(output_dir)}", timeout=10)

    mode_flags = {
        "coverage": "-p",
        "sw": "--linux_symbols --noinst",
        "hw": "-p",
    }
    flags = mode_flags.get(mode, "-p")

    cmd = (
        f"timeout {timeout} honggfuzz -i {shlex.quote(corpus_dir)} -W {shlex.quote(output_dir)} "
        f"{flags} -- {shlex.quote(target_binary)} ___FILE___ 2>&1"
    )

    is_safe, reason = safety.validate_command(cmd)
    if not is_safe:
        return [TextContent(type="text", text=json.dumps({"error": "Command blocked", "reason": reason}))]

    result = await execute_ssh_command(ip_address, cmd, timeout=timeout + 30)

    crash_cmd = f"find {shlex.quote(output_dir)} -name 'hf*.fuzz' -o -name 'crash*' 2>/dev/null | wc -l"
    crash_count = await execute_ssh_command(ip_address, crash_cmd, timeout=10)

    return [TextContent(
        type="text",
        text=json.dumps({
            "tool": "honggfuzz",
            "target_binary": target_binary,
            "mode": mode,
            "duration_seconds": timeout,
            "stdout": result["stdout"][-5000:],
            "stderr": result["stderr"][-2000:],
            "exit_code": result["exit_code"],
            "crash_count": int(crash_count["stdout"].strip() or 0),
            "findings_dir": output_dir
        }, indent=2)
    )]


async def _handle_network_fuzz(arguments, proxmox, safety) -> list:
    vm_id = arguments["attacker_vm_id"]
    target_ip = arguments["target_ip"]
    target_port = arguments["target_port"]
    protocol = arguments.get("protocol", "tcp")
    seed_input = arguments.get("seed_input", "")
    iterations = arguments.get("iterations", 10000)
    timeout = arguments.get("timeout_seconds", 1800)

    ip_address, err = await _get_vm_ip_and_validate(vm_id, proxmox, safety, target_ip)
    if err:
        return err

    # Build a Python network fuzzer script that uses radamsa for mutation
    # Use json.dumps for safe string interpolation into the generated script
    _target_ip_js = json.dumps(target_ip)
    _protocol_js = json.dumps(protocol)
    _seed_input_js = json.dumps(seed_input)
    fuzzer_script = f'''#!/usr/bin/env python3
import socket, base64, subprocess, random, sys, time

TARGET = {_target_ip_js}
PORT = {target_port}
PROTOCOL = {_protocol_js}
ITERATIONS = {iterations}
SEED = base64.b64decode({_seed_input_js}) if {_seed_input_js} else b"GET / HTTP/1.0\\r\\n\\r\\n"

crashes = []
start = time.time()

for i in range(ITERATIONS):
    if time.time() - start > {timeout}:
        break
    # Mutate seed with radamsa
    try:
        mutated = subprocess.check_output(
            ["radamsa", "-n", "1", "-"],
            input=SEED, timeout=5
        )
    except Exception:
        mutated = SEED + bytes(random.randint(0, 255) for _ in range(random.randint(0, 256)))

    try:
        sock_type = socket.SOCK_DGRAM if PROTOCOL == "udp" else socket.SOCK_STREAM
        s = socket.socket(socket.AF_INET, sock_type)
        s.settimeout(3)
        s.connect((TARGET, PORT))
        s.sendall(mutated)
        if PROTOCOL == "tcp":
            try:
                resp = s.recv(4096)
            except socket.timeout:
                pass
        s.close()
    except ConnectionRefusedError:
        print(f"[{{i}}] Connection refused — service may have crashed", flush=True)
        crashes.append({{"iteration": i, "input": base64.b64encode(mutated).decode(), "error": "connection_refused"}})
    except Exception as e:
        crashes.append({{"iteration": i, "input": base64.b64encode(mutated).decode(), "error": str(e)}})

    if i % 1000 == 0:
        print(f"[{{i}}/{{ITERATIONS}}] crashes={{len(crashes)}}", flush=True)

print(f"\\n=== CAMPAIGN COMPLETE ===")
print(f"Iterations: {{i+1}}")
print(f"Crashes/anomalies: {{len(crashes)}}")
import json
with open("/tmp/netfuzz_results.json", "w") as f:
    json.dump({{"iterations": i+1, "crashes": crashes[:100]}}, f, indent=2)
print("Results saved to /tmp/netfuzz_results.json")
'''

    # Upload and run the fuzzer script
    upload_cmd = f"cat > /tmp/ciicerone_netfuzz.py << 'CIICERONE_EOF'\n{fuzzer_script}\nCIICERONE_EOF"
    await execute_ssh_command(ip_address, upload_cmd, timeout=15)

    run_cmd = f"timeout {timeout + 60} python3 /tmp/ciicerone_netfuzz.py 2>&1"
    is_safe, reason = safety.validate_command(run_cmd)
    if not is_safe:
        return [TextContent(type="text", text=json.dumps({"error": "Command blocked", "reason": reason}))]

    result = await execute_ssh_command(ip_address, run_cmd, timeout=timeout + 90)

    # Fetch results JSON
    results_json = await execute_ssh_command(ip_address, "cat /tmp/netfuzz_results.json 2>/dev/null", timeout=10)

    return [TextContent(
        type="text",
        text=json.dumps({
            "tool": "network_fuzz",
            "target": f"{target_ip}:{target_port}/{protocol}",
            "iterations": iterations,
            "stdout": result["stdout"][-5000:],
            "stderr": result["stderr"][-2000:],
            "exit_code": result["exit_code"],
            "results": results_json["stdout"][:5000] if results_json["stdout"] else None
        }, indent=2)
    )]


# ---------------------------------------------------------------------------
# API Fuzzing Handlers
# ---------------------------------------------------------------------------

async def _handle_ffuf(arguments, proxmox, safety) -> list:
    vm_id = arguments["attacker_vm_id"]
    target_url = arguments["target_url"]
    wordlist = arguments.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
    mode = arguments.get("mode", "dir")
    rate = arguments.get("rate", 0)
    extra_args = arguments.get("extra_args", "")

    ip_address, err = await _get_vm_ip_and_validate(vm_id, proxmox, safety)
    if err:
        return err

    rate_arg = f"-rate {rate}" if rate > 0 else ""
    cmd = f"ffuf -u {shlex.quote(target_url)} -w {shlex.quote(wordlist)} {rate_arg} {extra_args} -o /tmp/ffuf_results.json -of json 2>&1"

    is_safe, reason = safety.validate_command(cmd)
    if not is_safe:
        return [TextContent(type="text", text=json.dumps({"error": "Command blocked", "reason": reason}))]

    result = await execute_ssh_command(ip_address, cmd, timeout=300)
    results_json = await execute_ssh_command(ip_address, "cat /tmp/ffuf_results.json 2>/dev/null", timeout=10)

    return [TextContent(
        type="text",
        text=json.dumps({
            "tool": "ffuf",
            "target_url": target_url,
            "mode": mode,
            "stdout": result["stdout"][-5000:],
            "stderr": result["stderr"][-1000:],
            "exit_code": result["exit_code"],
            "results": results_json["stdout"][:5000] if results_json["stdout"] else None
        }, indent=2)
    )]


async def _handle_api_fuzz(arguments, proxmox, safety) -> list:
    vm_id = arguments["attacker_vm_id"]
    target_url = arguments["target_url"]
    openapi_spec = arguments["openapi_spec"]
    duration = arguments.get("duration_seconds", 600)
    auth_header = arguments.get("auth_header", "")

    ip_address, err = await _get_vm_ip_and_validate(vm_id, proxmox, safety)
    if err:
        return err

    auth_arg = f"-H 'Authorization: {shlex.quote(auth_header)}'" if auth_header else ""

    # Use schemathesis for OpenAPI-based fuzzing if available, fallback to ffuf
    cmd = (
        f"timeout {duration} schemathesis run --base-url {shlex.quote(target_url)} "
        f"--checks all {auth_arg} {shlex.quote(openapi_spec)} 2>&1 || "
        f"echo 'schemathesis not found, trying ffuf fallback' && "
        f"ffuf -u {shlex.quote(target_url + '/FUZZ')} -w /usr/share/wordlists/api-endpoints.txt "
        f"-mc all -o /tmp/api_fuzz_results.json -of json 2>&1"
    )

    is_safe, reason = safety.validate_command(cmd)
    if not is_safe:
        return [TextContent(type="text", text=json.dumps({"error": "Command blocked", "reason": reason}))]

    result = await execute_ssh_command(ip_address, cmd, timeout=duration + 60)

    return [TextContent(
        type="text",
        text=json.dumps({
            "tool": "api_fuzz",
            "target_url": target_url,
            "openapi_spec": openapi_spec,
            "duration_seconds": duration,
            "stdout": result["stdout"][-8000:],
            "stderr": result["stderr"][-2000:],
            "exit_code": result["exit_code"]
        }, indent=2)
    )]


# ---------------------------------------------------------------------------
# SAST Handlers
# ---------------------------------------------------------------------------

async def _handle_semgrep(arguments, proxmox, safety) -> list:
    vm_id = arguments["attacker_vm_id"]
    source_path = arguments["source_path"]
    ruleset = arguments.get("ruleset", "p/security-audit")
    output_format = arguments.get("output_format", "json")
    extra_args = arguments.get("extra_args", "")

    ip_address, err = await _get_vm_ip_and_validate(vm_id, proxmox, safety)
    if err:
        return err

    output_file = f"/tmp/semgrep_results.{output_format}"
    cmd = (
        f"semgrep --config {shlex.quote(ruleset)} --{output_format} "
        f"-o {shlex.quote(output_file)} {extra_args} {shlex.quote(source_path)} 2>&1"
    )

    is_safe, reason = safety.validate_command(cmd)
    if not is_safe:
        return [TextContent(type="text", text=json.dumps({"error": "Command blocked", "reason": reason}))]

    result = await execute_ssh_command(ip_address, cmd, timeout=300)
    results_content = await execute_ssh_command(ip_address, f"cat {shlex.quote(output_file)} 2>/dev/null | head -c 50000", timeout=15)

    return [TextContent(
        type="text",
        text=json.dumps({
            "tool": "semgrep",
            "source_path": source_path,
            "ruleset": ruleset,
            "stdout": result["stdout"][-3000:],
            "stderr": result["stderr"][-1000:],
            "exit_code": result["exit_code"],
            "results": results_content["stdout"][:50000] if results_content["stdout"] else None
        }, indent=2)
    )]


async def _handle_codeql(arguments, proxmox, safety) -> list:
    vm_id = arguments["attacker_vm_id"]
    source_path = arguments["source_path"]
    language = arguments["language"]
    query_suite = arguments.get("query_suite", "security")
    db_path = arguments.get("database_path", "/tmp/codeql_db")

    ip_address, err = await _get_vm_ip_and_validate(vm_id, proxmox, safety)
    if err:
        return err

    # Step 1: Create database
    create_cmd = f"codeql database create {shlex.quote(db_path)} --language={language} --source-root={shlex.quote(source_path)} --overwrite 2>&1"
    is_safe, reason = safety.validate_command(create_cmd)
    if not is_safe:
        return [TextContent(type="text", text=json.dumps({"error": "Command blocked", "reason": reason}))]

    create_result = await execute_ssh_command(ip_address, create_cmd, timeout=300)

    # Step 2: Run queries
    results_dir = "/tmp/codeql_results"
    query_suite_full = f"codeql/{language}-queries:{query_suite}" if "/" not in query_suite else query_suite
    analyze_cmd = (
        f"codeql database analyze {shlex.quote(db_path)} {shlex.quote(query_suite_full)} "
        f"--format=sarif-latest --output={shlex.quote(results_dir)}/results.sarif 2>&1"
    )
    is_safe, reason = safety.validate_command(analyze_cmd)
    if not is_safe:
        return [TextContent(type="text", text=json.dumps({"error": "Command blocked", "reason": reason}))]

    await execute_ssh_command(ip_address, f"mkdir -p {results_dir}", timeout=10)
    analyze_result = await execute_ssh_command(ip_address, analyze_cmd, timeout=600)

    # Fetch results
    results_content = await execute_ssh_command(ip_address, f"cat {results_dir}/results.sarif 2>/dev/null | head -c 50000", timeout=15)

    return [TextContent(
        type="text",
        text=json.dumps({
            "tool": "codeql",
            "source_path": source_path,
            "language": language,
            "query_suite": query_suite_full,
            "database_creation": {
                "stdout": create_result["stdout"][-2000:],
                "exit_code": create_result["exit_code"]
            },
            "analysis": {
                "stdout": analyze_result["stdout"][-3000:],
                "exit_code": analyze_result["exit_code"]
            },
            "results": results_content["stdout"][:50000] if results_content["stdout"] else None
        }, indent=2)
    )]


async def _handle_bandit(arguments, proxmox, safety) -> list:
    vm_id = arguments["attacker_vm_id"]
    source_path = arguments["source_path"]
    severity = arguments.get("severity_level", "medium")
    output_format = arguments.get("output_format", "json")

    ip_address, err = await _get_vm_ip_and_validate(vm_id, proxmox, safety)
    if err:
        return err

    severity_map = {"low": "-l", "medium": "-ll", "high": "-lll"}
    sev_flag = severity_map.get(severity, "-ll")

    output_file = f"/tmp/bandit_results.{output_format}"
    cmd = f"bandit {sev_flag} -f {output_format} -o {shlex.quote(output_file)} -r {shlex.quote(source_path)} 2>&1"

    is_safe, reason = safety.validate_command(cmd)
    if not is_safe:
        return [TextContent(type="text", text=json.dumps({"error": "Command blocked", "reason": reason}))]

    result = await execute_ssh_command(ip_address, cmd, timeout=120)
    results_content = await execute_ssh_command(ip_address, f"cat {output_file} 2>/dev/null", timeout=10)

    return [TextContent(
        type="text",
        text=json.dumps({
            "tool": "bandit",
            "source_path": source_path,
            "severity_level": severity,
            "stdout": result["stdout"][-2000:],
            "stderr": result["stderr"][-1000:],
            "exit_code": result["exit_code"],
            "results": results_content["stdout"][:50000] if results_content["stdout"] else None
        }, indent=2)
    )]


# ---------------------------------------------------------------------------
# Binary Analysis Handlers
# ---------------------------------------------------------------------------

async def _handle_ghidra(arguments, proxmox, safety) -> list:
    vm_id = arguments["attacker_vm_id"]
    target_binary = arguments["target_binary"]
    mode = arguments.get("mode", "decompile")
    project_dir = arguments.get("project_dir", "/tmp/ghidra_project")
    custom_script = arguments.get("custom_script", "")
    extra_args = arguments.get("extra_args", "")

    ip_address, err = await _get_vm_ip_and_validate(vm_id, proxmox, safety)
    if err:
        return err

    # Find Ghidra installation
    ghidra_path_cmd = "which analyzeHeadless 2>/dev/null || find /opt -name analyzeHeadless -type f 2>/dev/null | head -1"
    ghidra_path_result = await execute_ssh_command(ip_address, ghidra_path_cmd, timeout=10)
    ghidra_bin = ghidra_path_result["stdout"].strip()
    if not ghidra_bin:
        return [TextContent(
            type="text",
            text=json.dumps({"error": "Ghidra not found on attacker VM. Install Ghidra and ensure analyzeHeadless is in PATH."})
        )]

    await execute_ssh_command(ip_address, f"mkdir -p {project_dir}", timeout=10)

    # Select postScript based on mode
    script_map = {
        "decompile": "DecompileAllFunctions.java",
        "strings": "ExtractStrings.java",
        "functions": "ListFunctions.java",
        "vuln_scan": "VulnerabilityScan.java",
    }

    if mode == "custom" and custom_script:
        script_args = f"-postScript {custom_script}"
    else:
        script_name = script_map.get(mode, "DecompileAllFunctions.java")
        script_args = f"-postScript {script_name}"

    project_name = "ciicerone_analysis"
    cmd = (
        f"{shlex.quote(ghidra_bin)} {shlex.quote(project_dir)} {project_name} "
        f"-import {shlex.quote(target_binary)} -overwrite {script_args} "
        f"-scriptPath /opt/ghidra/Ghidra/Features/Decompiler/ghidra_scripts "
        f"{extra_args} 2>&1"
    )

    is_safe, reason = safety.validate_command(cmd)
    if not is_safe:
        return [TextContent(type="text", text=json.dumps({"error": "Command blocked", "reason": reason}))]

    result = await execute_ssh_command(ip_address, cmd, timeout=600)

    return [TextContent(
        type="text",
        text=json.dumps({
            "tool": "ghidra_headless",
            "target_binary": target_binary,
            "mode": mode,
            "stdout": result["stdout"][-8000:],
            "stderr": result["stderr"][-2000:],
            "exit_code": result["exit_code"]
        }, indent=2)
    )]


async def _handle_radare2(arguments, proxmox, safety) -> list:
    vm_id = arguments["attacker_vm_id"]
    target_binary = arguments["target_binary"]
    mode = arguments.get("mode", "info")
    address = arguments.get("address", "main")
    custom_command = arguments.get("custom_command", "")

    ip_address, err = await _get_vm_ip_and_validate(vm_id, proxmox, safety)
    if err:
        return err

    mode_commands = {
        "info": "iI",
        "functions": "afl",
        "strings": "iz~...",
        "xrefs": f"axt @ {address}",
        "decompile": f"pdg @ {address}",
        "security": "iI~canary,nx,pic,relro,crypto",
        "rop": "/R",
        "custom": custom_command,
    }

    r2_cmd = mode_commands.get(mode, "iI")
    cmd = f"r2 -q -c {shlex.quote(r2_cmd)} {shlex.quote(target_binary)} 2>&1"

    is_safe, reason = safety.validate_command(cmd)
    if not is_safe:
        return [TextContent(type="text", text=json.dumps({"error": "Command blocked", "reason": reason}))]

    result = await execute_ssh_command(ip_address, cmd, timeout=120)

    return [TextContent(
        type="text",
        text=json.dumps({
            "tool": "radare2",
            "target_binary": target_binary,
            "mode": mode,
            "r2_command": r2_cmd,
            "stdout": result["stdout"][:10000],
            "stderr": result["stderr"][-1000:],
            "exit_code": result["exit_code"]
        }, indent=2)
    )]


async def _handle_binary_diff(arguments, proxmox, safety) -> list:
    vm_id = arguments["attacker_vm_id"]
    binary_old = arguments["binary_old"]
    binary_new = arguments["binary_new"]
    output_dir = arguments.get("output_dir", "/tmp/bindiff_results")

    ip_address, err = await _get_vm_ip_and_validate(vm_id, proxmox, safety)
    if err:
        return err

    await execute_ssh_command(ip_address, f"mkdir -p {shlex.quote(output_dir)}", timeout=10)

    # Use rabin2/r2 for binary diffing (shlex.quote all user-provided paths)
    cmd = (
        f"rabin2 -s {shlex.quote(binary_old)} > {shlex.quote(output_dir)}/old_symbols.txt 2>&1; "
        f"rabin2 -s {shlex.quote(binary_new)} > {shlex.quote(output_dir)}/new_symbols.txt 2>&1; "
        f"diff {shlex.quote(output_dir)}/old_symbols.txt {shlex.quote(output_dir)}/new_symbols.txt > {shlex.quote(output_dir)}/symbol_diff.txt 2>&1; "
        f"r2 -q -c 'afl' {shlex.quote(binary_old)} > {shlex.quote(output_dir)}/old_functions.txt 2>&1; "
        f"r2 -q -c 'afl' {shlex.quote(binary_new)} > {shlex.quote(output_dir)}/new_functions.txt 2>&1; "
        f"diff {shlex.quote(output_dir)}/old_functions.txt {shlex.quote(output_dir)}/new_functions.txt > {shlex.quote(output_dir)}/function_diff.txt 2>&1; "
        f"echo '=== DIFF COMPLETE ==='; "
        f"wc -l {shlex.quote(output_dir)}/*_diff.txt"
    )

    is_safe, reason = safety.validate_command(cmd)
    if not is_safe:
        return [TextContent(type="text", text=json.dumps({"error": "Command blocked", "reason": reason}))]

    result = await execute_ssh_command(ip_address, cmd, timeout=120)

    # Fetch the function diff
    func_diff = await execute_ssh_command(ip_address, f"cat {shlex.quote(output_dir)}/function_diff.txt 2>/dev/null | head -200", timeout=10)

    return [TextContent(
        type="text",
        text=json.dumps({
            "tool": "binary_diff",
            "binary_old": binary_old,
            "binary_new": binary_new,
            "stdout": result["stdout"],
            "exit_code": result["exit_code"],
            "function_diff": func_diff["stdout"][:10000],
            "output_dir": output_dir
        }, indent=2)
    )]


# ---------------------------------------------------------------------------
# Crash Triage Handlers
# ---------------------------------------------------------------------------

async def _handle_crash_collect(arguments, proxmox, safety) -> list:
    vm_id = arguments["attacker_vm_id"]
    findings_dir = arguments["findings_dir"]
    target_binary = arguments.get("target_binary", "")
    output_file = arguments.get("output_file", "/tmp/crash_catalog.json")

    ip_address, err = await _get_vm_ip_and_validate(vm_id, proxmox, safety)
    if err:
        return err

    # Script to collect and deduplicate crashes
    collect_script = f'''#!/usr/bin/env python3
import os, json, hashlib, subprocess, glob

findings_dir = "{findings_dir}"
target_binary = "{target_binary}"
output_file = "{output_file}"

# Find all crash files (AFL: crashes/, hang/; libFuzzer: crash-*, leak-*; honggfuzz: *.fuzz)
crash_patterns = [
    os.path.join(findings_dir, "**", "crashes", "*"),
    os.path.join(findings_dir, "**", "hangs", "*"),
    os.path.join(findings_dir, "crash-*"),
    os.path.join(findings_dir, "leak-*"),
    os.path.join(findings_dir, "**", "*.fuzz"),
]

crash_files = set()
for pattern in crash_patterns:
    crash_files.update(glob.glob(pattern, recursive=True))

crash_files = [f for f in crash_files if os.path.isfile(f)]

catalog = []
seen_signatures = set()

for cf in crash_files:
    try:
        with open(cf, "rb") as f:
            content = f.read()
        input_hash = hashlib.sha256(content).hexdigest()

        # If we have a target binary, try to get a stack trace
        stack_sig = ""
        crash_type = "unknown"
        if target_binary:
            try:
                gdb_cmd = f"echo 'run\\nbt\\nquit' | gdb -batch -q -ex 'set pagination off' -ex 'run < {shlex.quote(cf)}' {shlex.quote(target_binary)} 2>&1"
                gdb_out = subprocess.check_output(gdb_cmd, shell=True, timeout=10, stderr=subprocess.STDOUT).decode(errors="replace")
                # Extract crash type from signal
                if "SIGSEGV" in gdb_out:
                    crash_type = "segfault"
                elif "SIGABRT" in gdb_out:
                    crash_type = "abort"
                elif "SIGFPE" in gdb_out:
                    crash_type = "fpe"
                # Stack signature = first 3 frames
                lines = [l.strip() for l in gdb_out.split("\\n") if "#" in l and "in" in l]
                stack_sig = "|".join(lines[:3])
            except Exception:
                pass

        dedup_key = stack_sig if stack_sig else input_hash
        if dedup_key in seen_signatures:
            continue
        seen_signatures.add(dedup_key)

        catalog.append({{
            "file": cf,
            "input_hash": input_hash,
            "size": len(content),
            "crash_type": crash_type,
            "stack_signature": stack_sig,
        }})
    except Exception as e:
        catalog.append({{"file": cf, "error": str(e)}})

result = {{
    "total_crash_files": len(crash_files),
    "unique_crashes": len(catalog),
    "crashes": catalog[:500],
}}

with open(output_file, "w") as f:
    json.dump(result, f, indent=2)

print(json.dumps(result, indent=2))
'''

    upload_cmd = f"cat > /tmp/ciicerone_crash_collect.py << 'CIICERONE_EOF'\n{collect_script}\nCIICERONE_EOF"
    await execute_ssh_command(ip_address, upload_cmd, timeout=15)

    run_cmd = f"python3 /tmp/ciicerone_crash_collect.py 2>&1"
    is_safe, reason = safety.validate_command(run_cmd)
    if not is_safe:
        return [TextContent(type="text", text=json.dumps({"error": "Command blocked", "reason": reason}))]

    result = await execute_ssh_command(ip_address, run_cmd, timeout=120)

    return [TextContent(
        type="text",
        text=json.dumps({
            "tool": "crash_collect",
            "findings_dir": findings_dir,
            "stdout": result["stdout"][:10000],
            "stderr": result["stderr"][-1000:],
            "exit_code": result["exit_code"],
            "catalog_file": output_file
        }, indent=2)
    )]


async def _handle_crash_triage(arguments, proxmox, safety) -> list:
    vm_id = arguments["attacker_vm_id"]
    target_binary = arguments["target_binary"]
    crash_input = arguments["crash_input"]
    gdb_script = arguments.get("gdb_script", "")

    ip_address, err = await _get_vm_ip_and_validate(vm_id, proxmox, safety)
    if err:
        return err

    # Default GDB triage script
    default_script = '''set pagination off
set confirm off
run < $crash_input
bt full
info registers
x/i $pc
x/16xw $sp
quit
'''

    if gdb_script:
        # Use custom script
        triage_cmd = (
            f"gdb -batch -q -ex 'set pagination off' "
            f"-ex 'run < {shlex.quote(crash_input)}' "
            f"-ex 'bt full' "
            f"-ex 'info registers' "
            f"-ex 'x/i \\$pc' "
            f"-ex 'x/16xw \\$sp' "
            f"-ex 'quit' {shlex.quote(target_binary)} 2>&1"
        )
    else:
        triage_cmd = (
            f"gdb -batch -q -ex 'set pagination off' "
            f"-ex 'run < {shlex.quote(crash_input)}' "
            f"-ex 'bt full' "
            f"-ex 'info registers' "
            f"-ex 'x/i \\$pc' "
            f"-ex 'x/16xw \\$sp' "
            f"-ex 'quit' {shlex.quote(target_binary)} 2>&1"
        )

    is_safe, reason = safety.validate_command(triage_cmd)
    if not is_safe:
        return [TextContent(type="text", text=json.dumps({"error": "Command blocked", "reason": reason}))]

    result = await execute_ssh_command(ip_address, triage_cmd, timeout=60)

    # Classify crash type
    output = result["stdout"]
    crash_type = "unknown"
    if "SIGSEGV" in output:
        crash_type = "segfault"
    elif "SIGABRT" in output:
        crash_type = "abort"
    elif "SIGFPE" in output:
        crash_type = "floating_point_exception"
    elif "SIGBUS" in output:
        crash_type = "bus_error"
    elif "SIGILL" in output:
        crash_type = "illegal_instruction"

    # Assess exploitability
    exploitability = "unknown"
    if crash_type == "segfault":
        if "write" in output.lower() and "access" in output.lower():
            exploitability = "potentially_exploitable"
        elif "read" in output.lower() and "access" in output.lower():
            exploitability = "info_leak_or_crash"
        else:
            exploitability = "requires_analysis"

    return [TextContent(
        type="text",
        text=json.dumps({
            "tool": "crash_triage",
            "target_binary": target_binary,
            "crash_input": crash_input,
            "crash_type": crash_type,
            "exploitability": exploitability,
            "gdb_output": output[:15000],
            "stderr": result["stderr"][-1000:],
            "exit_code": result["exit_code"]
        }, indent=2)
    )]
