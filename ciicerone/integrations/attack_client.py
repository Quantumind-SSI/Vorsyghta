"""Ciicerone Attack API Client.

Async client for Ciicerone Attack REST and GraphQL APIs.
Handles flow creation, monitoring, reporting, and steering.
"""

import asyncio
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

import aiohttp

logger = logging.getLogger(__name__)


@dataclass
class AttackFlow:
    """Represents a Ciicerone Attack pentesting flow."""
    flow_id: str
    name: str
    description: str
    status: str  # active, completed, failed, queued
    target: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    tasks: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class AttackTask:
    """Represents a task within a Ciicerone Attack flow."""
    task_id: str
    flow_id: str
    name: str
    description: str
    status: str  # pending, running, done, failed
    agent_type: str  # researcher, developer, executor
    result: Optional[Dict[str, Any]] = None
    subtasks: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class AttackReport:
    """Represents a Ciicerone Attack vulnerability report."""
    flow_id: str
    report_markdown: str
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    executive_summary: str = ""
    mitre_techniques: List[str] = field(default_factory=list)
    generated_at: Optional[str] = None


@dataclass
class AttackArtifact:
    """Represents an artifact from a Ciicerone Attack flow."""
    artifact_id: str
    flow_id: str
    type: str  # file, report, log, screenshot
    path: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: Optional[str] = None


@dataclass
class AttackMemoryEntry:
    """Represents a memory entry from Ciicerone Attack's vector store."""
    entry_id: str
    content: str
    embedding_score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: Optional[str] = None


class AttackClient:
    """Async client for Ciicerone Attack REST and GraphQL APIs.

    Ciicerone Attack provides:
        - REST API on port 8080
        - GraphQL API on port 8081
        - Web UI on port 3000

    Authentication via Bearer token.

    Example:
        client = AttackClient(
            base_url="http://ciicerone-attack.example.com:8080",
            api_token="your-token",
        )
        flow = await client.create_flow(
            name="Web App Pentest",
            description="Full pentest of DVWA",
            target="http://10.0.100.10",
        )
        status = await client.get_flow_status(flow.flow_id)
        report = await client.get_flow_report(flow.flow_id)
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_token: Optional[str] = None,
        graphql_url: Optional[str] = None,
        timeout: int = 300,
    ):
        self.base_url = (base_url or os.environ.get("CIICERONE_ATTACK_API_URL", "")).rstrip("/")
        self.api_token = api_token or os.environ.get("CIICERONE_ATTACK_API_TOKEN", "")
        self.graphql_url = (graphql_url or os.environ.get("CIICERONE_ATTACK_GRAPHQL_URL", "")).rstrip("/")
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self._jwt_token: Optional[str] = None

        # Login credentials for session-based auth
        self.login_email = os.environ.get("CIICERONE_ATTACK_LOGIN_EMAIL", "admin@ciicerone.com")
        self.login_password = os.environ.get("CIICERONE_ATTACK_LOGIN_PASSWORD", "admin")

        if not self.base_url:
            logger.warning("Ciicerone Attack base URL not configured. Set CIICERONE_ATTACK_API_URL.")

        if not self.api_token:
            logger.warning("Ciicerone Attack API token not configured. Set CIICERONE_ATTACK_API_TOKEN.")

    async def _ensure_auth(self) -> None:
        """Ensure we have a valid auth token, logging in if needed."""
        if self._jwt_token:
            return
        await self._login()

    async def _login(self) -> None:
        """Login to Ciicerone Attack and extract the session token from the auth cookie."""
        login_url = self._rest_url("/api/v1/auth/login")
        creds = {"mail": self.login_email, "password": self.login_password}
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(login_url, json=creds) as resp:
                    if resp.status != 200:
                        raise Exception(f"Ciicerone Attack login failed: {resp.status} - {await resp.text()}")
                    # Extract auth cookie from Set-Cookie header
                    set_cookies = resp.headers.getall("Set-Cookie", [])
                    for sc in set_cookies:
                        if sc.startswith("auth="):
                            self._jwt_token = sc.split(";")[0].split("=", 1)[1]
                            logger.info("Ciicerone Attack login successful, session token acquired")
                            return
                    raise Exception("Ciicerone Attack login succeeded but no auth cookie found")
        except Exception as e:
            logger.error(f"Ciicerone Attack login error: {e}")
            raise

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        token = self._jwt_token or self.api_token
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if self._jwt_token:
            headers["Cookie"] = f"auth={self._jwt_token}"
        return headers

    def _rest_url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    async def health_check(self) -> Dict[str, Any]:
        """Check if Ciicerone Attack API is reachable."""
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(
                    self._rest_url("/api/v1/swagger/doc.json"),
                    headers=self._headers(),
                    allow_redirects=False,
                ) as resp:
                    if resp.status == 200:
                        return {"status": "ok", "api": "ciicerone-attack", "version": "2.1.0"}
                    if resp.status == 401:
                        return {"status": "ok", "api": "ciicerone-attack", "note": "auth required"}
                    return {"status": "error", "code": resp.status}
        except Exception as e:
            logger.error(f"Ciicerone Attack health check failed: {e}")
            return {"status": "error", "message": str(e)}

    async def create_flow(
        self,
        input_text: str,
        provider: str = "openai",
        functions: Optional[Dict[str, Any]] = None,
        resource_ids: Optional[List[int]] = None,
    ) -> AttackFlow:
        """Create a new pentesting flow.

        Args:
            input_text: Natural language input for the first task in the flow
            provider: LLM provider name (openai, azure, etc.)
            functions: Optional tool functions configuration
            resource_ids: Optional resource IDs to attach

        Returns:
            AttackFlow with the created flow ID
        """
        await self._ensure_auth()

        payload: Dict[str, Any] = {
            "input": input_text,
            "provider": provider,
        }
        if functions:
            payload["functions"] = functions
        if resource_ids:
            payload["resource_ids"] = resource_ids

        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    self._rest_url("/api/v1/flows"),
                    headers=self._headers(),
                    json=payload,
                ) as resp:
                    data = await resp.json()
                    if resp.status not in (200, 201):
                        raise Exception(f"Create flow failed: {data}")

                    flow_data = data.get("data", data)
                    return AttackFlow(
                        flow_id=str(flow_data.get("id", flow_data.get("flow_id", ""))),
                        name=flow_data.get("title", flow_data.get("name", "")),
                        description=flow_data.get("description", input_text[:200]),
                        status=flow_data.get("status", "queued"),
                        target=flow_data.get("target", ""),
                        parameters=flow_data.get("parameters", {}),
                        created_at=flow_data.get("created_at"),
                        updated_at=flow_data.get("updated_at"),
                    )
        except aiohttp.ClientError as e:
            logger.error(f"Failed to create Ciicerone Attack flow: {e}")
            raise

    async def get_flow_status(self, flow_id: str) -> AttackFlow:
        """Get real-time flow execution status.

        Args:
            flow_id: The flow ID to check

        Returns:
            AttackFlow with current status and task information
        """
        await self._ensure_auth()
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(
                    self._rest_url(f"/api/v1/flows/{flow_id}"),
                    headers=self._headers(),
                ) as resp:
                    data = await resp.json()
                    if resp.status != 200:
                        raise Exception(f"Get flow failed: {data}")

                    return AttackFlow(
                        flow_id=data.get("id", flow_id),
                        name=data.get("name", ""),
                        description=data.get("description", ""),
                        status=data.get("status", "unknown"),
                        target=data.get("target", ""),
                        parameters=data.get("parameters", {}),
                        created_at=data.get("created_at"),
                        updated_at=data.get("updated_at"),
                        tasks=data.get("tasks", []),
                    )
        except aiohttp.ClientError as e:
            logger.error(f"Failed to get flow status: {e}")
            raise

    async def list_flows(self, limit: int = 50) -> List[AttackFlow]:
        """List all pentesting flows.

        Args:
            limit: Maximum number of flows to return

        Returns:
            List of AttackFlow objects
        """
        await self._ensure_auth()
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(
                    self._rest_url(f"/api/v1/flows?limit={limit}"),
                    headers=self._headers(),
                ) as resp:
                    data = await resp.json()
                    if resp.status != 200:
                        raise Exception(f"List flows failed: {data}")

                    flows = []
                    for item in data.get("flows", data) if isinstance(data, dict) else data:
                        flows.append(AttackFlow(
                            flow_id=item.get("id", ""),
                            name=item.get("name", ""),
                            description=item.get("description", ""),
                            status=item.get("status", "unknown"),
                            target=item.get("target", ""),
                            created_at=item.get("created_at"),
                            updated_at=item.get("updated_at"),
                        ))
                    return flows
        except aiohttp.ClientError as e:
            logger.error(f"Failed to list flows: {e}")
            raise

    async def get_flow_report(self, flow_id: str) -> AttackReport:
        """Get detailed vulnerability report for a completed flow.

        Args:
            flow_id: The flow ID

        Returns:
            AttackReport with full vulnerability report
        """
        await self._ensure_auth()
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(
                    self._rest_url(f"/api/v1/flows/{flow_id}/report"),
                    headers=self._headers(),
                ) as resp:
                    data = await resp.json()
                    if resp.status != 200:
                        raise Exception(f"Get report failed: {data}")

                    return AttackReport(
                        flow_id=flow_id,
                        report_markdown=data.get("report", data.get("markdown", "")),
                        vulnerabilities=data.get("vulnerabilities", []),
                        recommendations=data.get("recommendations", []),
                        executive_summary=data.get("executive_summary", ""),
                        mitre_techniques=data.get("mitre_techniques", []),
                        generated_at=data.get("generated_at"),
                    )
        except aiohttp.ClientError as e:
            logger.error(f"Failed to get flow report: {e}")
            raise

    async def steer_flow(self, flow_id: str, instruction: str) -> bool:
        """Send a steering instruction to an active flow (assistant mode).

        Args:
            flow_id: The active flow ID
            instruction: Natural language instruction for the agent

        Returns:
            True if instruction was accepted
        """
        await self._ensure_auth()
        payload = {"instruction": instruction}

        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    self._rest_url(f"/api/v1/flows/{flow_id}/steer"),
                    headers=self._headers(),
                    json=payload,
                ) as resp:
                    if resp.status in (200, 202):
                        return True
                    data = await resp.json()
                    raise Exception(f"Steer flow failed: {data}")
        except aiohttp.ClientError as e:
            logger.error(f"Failed to steer flow: {e}")
            raise

    async def get_flow_artifacts(self, flow_id: str) -> List[AttackArtifact]:
        """Get artifacts (files, logs, screenshots) from a flow.

        Args:
            flow_id: The flow ID

        Returns:
            List of AttackArtifact objects
        """
        await self._ensure_auth()
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(
                    self._rest_url(f"/api/v1/flows/{flow_id}/artifacts"),
                    headers=self._headers(),
                ) as resp:
                    data = await resp.json()
                    if resp.status != 200:
                        raise Exception(f"Get artifacts failed: {data}")

                    artifacts = []
                    for item in data.get("artifacts", data) if isinstance(data, dict) else data:
                        artifacts.append(AttackArtifact(
                            artifact_id=item.get("id", ""),
                            flow_id=flow_id,
                            type=item.get("type", "file"),
                            path=item.get("path", ""),
                            metadata=item.get("metadata", {}),
                            created_at=item.get("created_at"),
                        ))
                    return artifacts
        except aiohttp.ClientError as e:
            logger.error(f"Failed to get flow artifacts: {e}")
            raise

    async def stop_flow(self, flow_id: str) -> bool:
        """Stop a running flow.

        Args:
            flow_id: The flow ID to stop

        Returns:
            True if flow was stopped
        """
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    self._rest_url(f"/api/v1/flows/{flow_id}/stop"),
                    headers=self._headers(),
                ) as resp:
                    if resp.status in (200, 202):
                        return True
                    data = await resp.json()
                    raise Exception(f"Stop flow failed: {data}")
        except aiohttp.ClientError as e:
            logger.error(f"Failed to stop flow: {e}")
            raise

    async def delete_flow(self, flow_id: str) -> bool:
        """Delete a flow and all associated data.

        Args:
            flow_id: The flow ID to delete

        Returns:
            True if flow was deleted
        """
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.delete(
                    self._rest_url(f"/api/v1/flows/{flow_id}"),
                    headers=self._headers(),
                ) as resp:
                    if resp.status in (200, 204):
                        return True
                    data = await resp.json()
                    raise Exception(f"Delete flow failed: {data}")
        except aiohttp.ClientError as e:
            logger.error(f"Failed to delete flow: {e}")
            raise

    async def search_memory(self, query: str, limit: int = 10) -> List[AttackMemoryEntry]:
        """Search Ciicerone Attack's vector store for past attack patterns.

        Uses the GraphQL API to query the memory/knowledge base.

        Args:
            query: Natural language search query
            limit: Maximum results

        Returns:
            List of AttackMemoryEntry objects
        """
        graphql_query = {
            "query": """
                query SearchMemory($query: String!, $limit: Int!) {
                    searchMemory(query: $query, limit: $limit) {
                        id
                        content
                        score
                        metadata
                        createdAt
                    }
                }
            """,
            "variables": {"query": query, "limit": limit},
        }

        url = self.graphql_url or self.base_url
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.post(
                    f"{url}/api/v1/graphql",
                    headers=self._headers(),
                    json=graphql_query,
                ) as resp:
                    data = await resp.json()
                    if resp.status != 200:
                        raise Exception(f"Memory search failed: {data}")

                    entries = data.get("data", {}).get("searchMemory", [])
                    return [
                        AttackMemoryEntry(
                            entry_id=e.get("id", ""),
                            content=e.get("content", ""),
                            embedding_score=e.get("score", 0.0),
                            metadata=e.get("metadata", {}),
                            created_at=e.get("createdAt"),
                        )
                        for e in entries
                    ]
        except aiohttp.ClientError as e:
            logger.error(f"Failed to search Ciicerone Attack memory: {e}")
            raise

    async def wait_for_flow_completion(
        self,
        flow_id: str,
        poll_interval: int = 10,
        timeout: int = 3600,
    ) -> AttackFlow:
        """Poll flow status until completion or timeout.

        Args:
            flow_id: The flow ID to monitor
            poll_interval: Seconds between status checks
            timeout: Maximum wait time in seconds

        Returns:
            Final AttackFlow state
        """
        elapsed = 0
        while elapsed < timeout:
            flow = await self.get_flow_status(flow_id)

            if flow.status in ("completed", "failed", "cancelled"):
                logger.info(f"Flow {flow_id} finished with status: {flow.status}")
                return flow

            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

        logger.warning(f"Flow {flow_id} timed out after {timeout}s")
        return await self.get_flow_status(flow_id)
