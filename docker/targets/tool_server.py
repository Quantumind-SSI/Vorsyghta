"""Vorsyghta sandbox tool server — containerized edition.

A minimal FastAPI service that exposes an allowlisted set of offensive
security tools (nmap, nikto, sqlmap, dirb, hydra, curl, ...) over a small
HTTP contract so the Vorsyghta AttackOrchestrator can drive real tool
execution against a sanctioned target from inside the Docker network.

Contract (matches vorsyghta/core/tool_server_client.py):
    GET  /health   -> {"status": "ok"}
    GET  /tools    -> {"tools": [...]}
    POST /execute  -> {"stdout":..., "stderr":..., "returncode":...}
                     body: {"command": "...", "timeout": 300}

This is the same tool server that scripts/azure_provision.sh deploys onto
the Phantom Kali sandbox VM, packaged here as a container so the Docker
integration harness can run a fully self-contained pentest demo without
provisioning an external Kali VM.

Authorization: this server listens on the internal Docker network only
(no host port published by default). It must NOT be exposed to untrusted
networks — it shells out to offensive tools on request.
"""
from __future__ import annotations

import shlex
import subprocess

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Vorsyghta Tool Server", version="1.0.0")

# Allowlist mirrors the Azure Kali VM deployment. Adding a tool here does
# NOT grant it — the binary must also be installed in the image (see
# Dockerfile.tool-server).
ALLOWED = [
    "nmap", "nikto", "dirb", "gobuster", "hydra", "sqlmap",
    "curl", "wget", "whatweb", "ffuf", "nuclei",
    "whois", "dig", "ping", "traceroute",
]


class CmdReq(BaseModel):
    command: str
    timeout: int = 300


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/tools")
async def tools():
    return {"tools": ALLOWED}


@app.post("/execute")
async def execute(req: CmdReq):
    parts = shlex.split(req.command)
    if not parts or parts[0] not in ALLOWED:
        return {
            "error": f"Tool not allowed: {parts[0] if parts else '(empty)'}. "
                     f"Available: {ALLOWED}",
            "returncode": -1,
            "stdout": "",
            "stderr": "",
        }
    try:
        result = subprocess.run(
            parts,
            capture_output=True,
            text=True,
            timeout=req.timeout,
        )
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {
            "error": f"Command timed out after {req.timeout}s",
            "returncode": -1,
            "stdout": "",
            "stderr": "",
        }
    except Exception as e:
        return {
            "error": str(e),
            "returncode": -1,
            "stdout": "",
            "stderr": "",
        }
