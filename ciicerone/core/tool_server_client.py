"""Tool Server Client — HTTP client for the Ciicerone sandbox tool server.

This client connects to the Phantom Kali sandbox tool server running on
the attack VM. It provides a safe, allowlisted interface for executing
security tools (nmap, nikto, sqlmap, etc.) during attack simulations.

The tool server runs on the sandbox VM at port 9090 (moved from 8080
to avoid conflict with the attack platform's REST API).

Usage::

    from ciicerone.core.tool_server_client import ToolServerClient

    client = ToolServerClient(url="http://20.242.43.111:9090")
    tools = await client.list_tools()
    result = await client.execute("nmap -sV -p 1-1000 172.17.0.2")

Owner: Ciicerone Core Team
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import uuid4

import httpx

logger = logging.getLogger(__name__)

# Default tool server URL (sandbox VM, port 9090)
DEFAULT_TOOL_SERVER_URL = "http://20.242.43.111:9090"

# Also update the ALLOWED list to match the tool server v2.0


class ToolExecutionResult:
    """Result of a tool execution via the tool server."""

    def __init__(
        self,
        success: bool,
        returncode: int = -1,
        stdout: str = "",
        stderr: str = "",
        error: Optional[str] = None,
        duration_seconds: float = 0.0,
        timed_out: bool = False,
    ):
        self.success = success
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.error = error
        self.duration_seconds = duration_seconds
        self.timed_out = timed_out

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "error": self.error,
            "duration_seconds": self.duration_seconds,
            "timed_out": self.timed_out,
        }


class ToolServerClient:
    """HTTP client for the Ciicerone sandbox tool server.

    The tool server provides:
      - GET /health  — health check
      - GET /tools   — list allowed tools
      - POST /execute — execute an allowlisted command
    """

    def __init__(
        self,
        url: str = DEFAULT_TOOL_SERVER_URL,
        timeout: float = 300.0,
        api_token: Optional[str] = None,
    ):
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.api_token = api_token
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            headers = {}
            if self.api_token:
                headers["Authorization"] = f"Bearer {self.api_token}"
            self._client = httpx.AsyncClient(
                base_url=self.url,
                timeout=self.timeout,
                headers=headers,
            )
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def health_check(self) -> bool:
        """Check if the tool server is reachable and healthy."""
        try:
            client = await self._get_client()
            resp = await client.get("/health", timeout=10.0)
            return resp.status_code == 200
        except Exception as e:
            logger.warning(f"Tool server health check failed: {e}")
            return False

    async def list_tools(self) -> List[str]:
        """Get the list of allowed tools from the tool server."""
        try:
            client = await self._get_client()
            resp = await client.get("/tools", timeout=10.0)
            resp.raise_for_status()
            data = resp.json()
            return data.get("tools", [])
        except Exception as e:
            logger.error(f"Failed to list tools: {e}")
            return []

    async def execute(
        self,
        command: str,
        timeout: int = 300,
    ) -> ToolExecutionResult:
        """Execute a command on the tool server.

        Args:
            command: The command string (e.g., "nmap -sV 172.17.0.2")
            timeout: Execution timeout in seconds

        Returns:
            ToolExecutionResult with stdout, stderr, returncode
        """
        start = datetime.utcnow()
        try:
            client = await self._get_client()
            resp = await client.post(
                "/execute",
                json={"command": command, "timeout": timeout},
                timeout=float(timeout) + 30,  # extra for HTTP overhead
            )
            duration = (datetime.utcnow() - start).total_seconds()

            if resp.status_code != 200:
                return ToolExecutionResult(
                    success=False,
                    error=f"HTTP {resp.status_code}: {resp.text}",
                    duration_seconds=duration,
                )

            data = resp.json()

            # Check for tool server error
            if "error" in data and "returncode" not in data:
                return ToolExecutionResult(
                    success=False,
                    error=data["error"],
                    duration_seconds=duration,
                    timed_out="timed out" in data.get("error", "").lower(),
                )

            returncode = data.get("returncode", -1)
            stdout = data.get("stdout", "")
            stderr = data.get("stderr", "")

            return ToolExecutionResult(
                success=returncode == 0,
                returncode=returncode,
                stdout=stdout,
                stderr=stderr,
                duration_seconds=duration,
            )

        except httpx.TimeoutException:
            duration = (datetime.utcnow() - start).total_seconds()
            return ToolExecutionResult(
                success=False,
                error="HTTP request timed out",
                duration_seconds=duration,
                timed_out=True,
            )
        except Exception as e:
            duration = (datetime.utcnow() - start).total_seconds()
            logger.error(f"Tool execution failed: {e}")
            return ToolExecutionResult(
                success=False,
                error=str(e),
                duration_seconds=duration,
            )

    async def execute_and_track(
        self,
        command: str,
        tool_name: str,
        tenant_id: str,
        exercise_id: Optional[str] = None,
        simulation_id: Optional[str] = None,
        sequence_step_id: Optional[str] = None,
        invoked_by: str = "system",
        invocation_source: str = "api",
        mitre_technique_id: Optional[str] = None,
        attack_phase: Optional[str] = None,
        target: Optional[str] = None,
        timeout: int = 300,
    ) -> Dict[str, Any]:
        """Execute a command and persist the result to the tool_usage table.

        This is the main entry point for simulation orchestration — it
        executes a tool via the tool server and records the usage in
        the database for tracking and metrics.

        Returns a dict with the execution result and the usage_id.
        """
        from ciicerone.db.session import get_session
        from ciicerone.db.models.tool_tracking import ToolUsageRecord

        usage_id = f"tu_{uuid4().hex[:12]}"
        started_at = datetime.utcnow()

        # Execute
        result = await self.execute(command, timeout=timeout)
        completed_at = datetime.utcnow()

        # Persist
        try:
            async with get_session() as session:
                record = ToolUsageRecord(
                    usage_id=usage_id,
                    tenant_id=tenant_id,
                    exercise_id=exercise_id,
                    simulation_id=simulation_id,
                    sequence_step_id=sequence_step_id,
                    tool_name=tool_name,
                    command=command,
                    target=target,
                    return_code=result.returncode,
                    stdout=result.stdout[:10000] if result.stdout else None,  # cap at 10KB
                    stderr=result.stderr[:5000] if result.stderr else None,
                    success=result.success,
                    error_message=result.error,
                    duration_seconds=result.duration_seconds,
                    timeout_seconds=timeout,
                    timed_out=result.timed_out,
                    mitre_technique_id=mitre_technique_id,
                    attack_phase=attack_phase,
                    invoked_by=invoked_by,
                    invocation_source=invocation_source,
                    tool_server_url=self.url,
                    output_size_bytes=len(result.stdout.encode()) if result.stdout else 0,
                    started_at=started_at,
                    completed_at=completed_at,
                )
                session.add(record)
                await session.commit()
        except Exception as e:
            logger.error(f"Failed to persist tool usage: {e}")

        return {
            "usage_id": usage_id,
            "success": result.success,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "error": result.error,
            "duration_seconds": result.duration_seconds,
            "timed_out": result.timed_out,
        }


# Singleton instance
_tool_server_client: Optional[ToolServerClient] = None


def get_tool_server_client() -> ToolServerClient:
    """Get the singleton tool server client instance."""
    global _tool_server_client
    if _tool_server_client is None:
        import os
        url = os.environ.get("CIICERONE_TOOL_SERVER_URL", DEFAULT_TOOL_SERVER_URL)
        token = os.environ.get("CIICERONE_TOOL_SERVER_TOKEN")
        _tool_server_client = ToolServerClient(url=url, api_token=token)
    return _tool_server_client
