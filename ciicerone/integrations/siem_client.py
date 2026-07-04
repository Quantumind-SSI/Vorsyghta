"""SIEM Client Integration.

Async client for connecting to real SIEM platforms:
    - Splunk (REST API)
    - Elastic Security (Elasticsearch API)
    - Microsoft Sentinel (Azure Log Analytics)
    - IBM QRadar (REST API)
    - Generic SIEM (custom HTTP endpoint)

Supports log ingestion queries, alert retrieval, and correlation rule management.
"""

import asyncio
import base64
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

try:
    from azure.identity import AzureCliCredential, DefaultAzureCredential
    _AZURE_IDENTITY_AVAILABLE = True
except ImportError:
    _AZURE_IDENTITY_AVAILABLE = False

import aiohttp

logger = logging.getLogger(__name__)


@dataclass
class SIEMEvent:
    """Represents a log event retrieved from a SIEM."""
    event_id: str
    timestamp: str
    source: str
    source_type: str
    host: str
    raw: str
    fields: Dict[str, Any] = field(default_factory=dict)
    severity: str = "info"
    mitre_technique: Optional[str] = None


@dataclass
class SIEMAlert:
    """Represents an alert from a SIEM."""
    alert_id: str
    title: str
    severity: str  # critical, high, medium, low, info
    status: str  # new, acknowledged, resolved, suppressed
    created_at: str
    updated_at: Optional[str] = None
    description: str = ""
    source: str = ""
    mitre_techniques: List[str] = field(default_factory=list)
    related_events: List[str] = field(default_factory=list)
    assigned_to: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SIEMCorrelationRule:
    """Represents a correlation rule in the SIEM."""
    rule_id: str
    name: str
    description: str
    query: str
    severity: str
    enabled: bool = True
    mitre_techniques: List[str] = field(default_factory=list)
    created_at: Optional[str] = None


class SIEMClient:
    """Async client for SIEM platforms.

    Supports multiple SIEM backends with a unified interface.
    Automatically detects platform from configuration.

    Example:
        client = SIEMClient(
            platform="splunk",
            base_url="https://splunk.example.com:8089",
            api_token="your-token",
        )
        events = await client.search_logs(
            query='index=main "failed login"',
            start_time=datetime.utcnow() - timedelta(hours=1),
        )
    """

    SUPPORTED_PLATFORMS = ["splunk", "elastic", "sentinel", "qradar", "generic"]

    def __init__(
        self,
        platform: Optional[str] = None,
        base_url: Optional[str] = None,
        api_token: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        index: Optional[str] = None,
        timeout: int = 60,
        verify_ssl: bool = True,
    ):
        self.platform = (
            platform
            or os.environ.get("SIEM_PLATFORM", "")
            or os.environ.get("SIEM_TYPE", "")
        ).lower()

        self.base_url = (
            base_url
            or os.environ.get("SIEM_URL", "")
            or os.environ.get("SIEM_BASE_URL", "")
        ).rstrip("/")

        self.api_token = api_token or os.environ.get("SIEM_API_TOKEN", "")
        self.username = username or os.environ.get("SIEM_USERNAME", "")
        self.password = password or os.environ.get("SIEM_PASSWORD", "")
        self.index = index or os.environ.get("SIEM_INDEX", "")
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.verify_ssl = verify_ssl

        if not self.platform:
            logger.warning("SIEM platform not configured. Set SIEM_PLATFORM.")
        elif self.platform not in self.SUPPORTED_PLATFORMS:
            logger.warning(
                f"Unsupported SIEM platform: {self.platform}. "
                f"Supported: {', '.join(self.SUPPORTED_PLATFORMS)}"
            )

        if not self.base_url:
            logger.warning("SIEM base URL not configured. Set SIEM_URL.")

    def _headers(self) -> Dict[str, str]:
        """Build auth headers based on platform."""
        headers = {"Content-Type": "application/json", "Accept": "application/json", "Accept-Encoding": "gzip, deflate"}

        if self.platform == "splunk":
            if self.api_token:
                headers["Authorization"] = f"Bearer {self.api_token}"
            elif self.username and self.password:
                creds = base64.b64encode(
                    f"{self.username}:{self.password}".encode()
                ).decode()
                headers["Authorization"] = f"Basic {creds}"
        elif self.platform == "elastic":
            if self.api_token:
                headers["Authorization"] = f"ApiKey {self.api_token}"
            elif self.username and self.password:
                creds = base64.b64encode(
                    f"{self.username}:{self.password}".encode()
                ).decode()
                headers["Authorization"] = f"Basic {creds}"
        elif self.platform == "sentinel":
            # Log Analytics query API requires Azure AD bearer token
            # Use azure-identity for automatic token refresh if available
            if _AZURE_IDENTITY_AVAILABLE:
                try:
                    credential = AzureCliCredential()
                    token = credential.get_token("https://api.loganalytics.io/.default")
                    headers["Authorization"] = f"Bearer {token.token}"
                except Exception as e:
                    logger.warning(f"Azure CLI credential failed: {e}, falling back to API token")
                    if self.api_token:
                        headers["Authorization"] = f"Bearer {self.api_token}"
            elif self.api_token:
                headers["Authorization"] = f"Bearer {self.api_token}"
        elif self.platform == "qradar":
            if self.api_token:
                headers["SEC"] = self.api_token
        elif self.platform == "generic":
            if self.api_token:
                headers["Authorization"] = f"Bearer {self.api_token}"

        return headers

    def _connector(self) -> Optional[aiohttp.TCPConnector]:
        if not self.verify_ssl:
            return aiohttp.TCPConnector(ssl=False)
        return None

    async def test_connection(self) -> Dict[str, Any]:
        """Test connectivity to the SIEM platform."""
        if not self.base_url:
            return {"status": "error", "message": "SIEM URL not configured"}

        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=15),
                connector=self._connector(),
            ) as session:
                if self.platform == "splunk":
                    url = f"{self.base_url}/services/server/info"
                elif self.platform == "elastic":
                    url = f"{self.base_url}/_cluster/health"
                elif self.platform == "sentinel":
                    url = f"{self.base_url}/v1/operationalInsights/workspaces"
                elif self.platform == "qradar":
                    url = f"{self.base_url}/api/system/about"
                else:
                    url = f"{self.base_url}/health"

                async with session.get(
                    url, headers=self._headers(), ssl=self.verify_ssl
                ) as resp:
                    if resp.status in (200, 201):
                        data = await resp.json()
                        return {
                            "status": "ok",
                            "platform": self.platform,
                            "url": self.base_url,
                            "info": data,
                        }
                    return {
                        "status": "error",
                        "code": resp.status,
                        "message": await resp.text(),
                    }
        except Exception as e:
            logger.error(f"SIEM connection test failed: {e}")
            return {"status": "error", "message": str(e)}

    async def search_logs(
        self,
        query: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[SIEMEvent]:
        """Search logs in the SIEM.

        Args:
            query: Platform-specific search query
            start_time: Start of time range
            end_time: End of time range
            limit: Maximum results

        Returns:
            List of SIEMEvent objects
        """
        if not self.base_url:
            logger.error("SIEM URL not configured")
            return []

        start_time = start_time or (datetime.utcnow() - timedelta(hours=1))
        end_time = end_time or datetime.utcnow()

        try:
            if self.platform == "splunk":
                return await self._splunk_search(
                    query, start_time, end_time, limit
                )
            elif self.platform == "elastic":
                return await self._elastic_search(
                    query, start_time, end_time, limit
                )
            elif self.platform == "sentinel":
                return await self._sentinel_search(
                    query, start_time, end_time, limit
                )
            elif self.platform == "qradar":
                return await self._qradar_search(
                    query, start_time, end_time, limit
                )
            else:
                return await self._generic_search(
                    query, start_time, end_time, limit
                )
        except Exception as e:
            logger.error(f"SIEM search failed: {e}")
            return []

    async def _splunk_search(
        self,
        query: str,
        start_time: datetime,
        end_time: datetime,
        limit: int,
    ) -> List[SIEMEvent]:
        """Execute Splunk search."""
        search_query = f"search {query}"
        if self.index:
            search_query = f"search index={self.index} {query}"

        payload = {
            "search": search_query,
            "earliest_time": start_time.isoformat(),
            "latest_time": end_time.isoformat(),
            "count": limit,
            "output_mode": "json",
        }

        async with aiohttp.ClientSession(
            timeout=self.timeout, connector=self._connector()
        ) as session:
            async with session.post(
                f"{self.base_url}/services/search/jobs/export",
                headers=self._headers(),
                data=payload,
                ssl=self.verify_ssl,
            ) as resp:
                if resp.status != 200:
                    logger.error(f"Splunk search failed: {resp.status}")
                    return []

                text = await resp.text()
                events: List[SIEMEvent] = []
                for line in text.strip().split("\n"):
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                        result = row.get("result", row)
                        events.append(self._parse_splunk_event(result))
                    except json.JSONDecodeError:
                        continue
                return events[:limit]

    async def _elastic_search(
        self,
        query: str,
        start_time: datetime,
        end_time: datetime,
        limit: int,
    ) -> List[SIEMEvent]:
        """Execute Elasticsearch search."""
        index = self.index or "*"
        body = {
            "query": {
                "bool": {
                    "must": [
                        {"query_string": {"query": query}},
                        {"range": {"@timestamp": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}},
                    ]
                }
            },
            "size": limit,
            "sort": [{"@timestamp": "desc"}],
        }

        async with aiohttp.ClientSession(
            timeout=self.timeout, connector=self._connector()
        ) as session:
            async with session.post(
                f"{self.base_url}/{index}/_search",
                headers=self._headers(),
                json=body,
                ssl=self.verify_ssl,
            ) as resp:
                if resp.status != 200:
                    logger.error(f"Elastic search failed: {resp.status}")
                    return []

                data = await resp.json()
                hits = data.get("hits", {}).get("hits", [])
                return [self._parse_elastic_event(h) for h in hits]

    async def _sentinel_search(
        self,
        query: str,
        start_time: datetime,
        end_time: datetime,
        limit: int,
    ) -> List[SIEMEvent]:
        """Execute Microsoft Sentinel (KQL) search via Log Analytics API."""
        # Log Analytics query API: GET /v1/workspaces/{workspaceId}/query
        workspace_id = self.index or os.environ.get(
            "AZURE_LOG_ANALYTICS_WORKSPACE_ID", ""
        )
        url = f"{self.base_url}/v1/workspaces/{workspace_id}/query"

        # Log Analytics API uses GET with query parameters
        # timespan must be ISO 8601 duration (e.g. PT1H) or start/end format
        # No 'top' param — use '| take N' in KQL instead
        params = {
            "query": query,
            "timespan": f"{start_time.isoformat()}/{end_time.isoformat()}",
        }

        async with aiohttp.ClientSession(
            timeout=self.timeout, connector=self._connector()
        ) as session:
            async with session.get(
                url,
                headers=self._headers(),
                params=params,
                ssl=self.verify_ssl,
            ) as resp:
                if resp.status != 200:
                    error_text = await resp.text()
                    logger.error(f"Sentinel search failed: {resp.status} - {error_text}")
                    return []

                data = await resp.json()
                tables = data.get("tables", [])
                if not tables:
                    return []

                rows = tables[0].get("rows", [])
                columns = [c["name"] for c in tables[0].get("columns", [])]
                events: List[SIEMEvent] = []
                for row in rows:
                    fields = dict(zip(columns, row))
                    events.append(self._parse_sentinel_event(fields))
                return events

    async def _qradar_search(
        self,
        query: str,
        start_time: datetime,
        end_time: datetime,
        limit: int,
    ) -> List[SIEMEvent]:
        """Execute IBM QRadar Ariel search."""
        params = {
            "query_expression": query,
            "start_time": int(start_time.timestamp() * 1000),
            "end_time": int(end_time.timestamp() * 1000),
            "limit": limit,
        }

        async with aiohttp.ClientSession(
            timeout=self.timeout, connector=self._connector()
        ) as session:
            async with session.post(
                f"{self.base_url}/api/ariel/searches",
                headers=self._headers(),
                json=params,
                ssl=self.verify_ssl,
            ) as resp:
                if resp.status != 201:
                    logger.error(f"QRadar search creation failed: {resp.status}")
                    return []

                search_data = await resp.json()
                search_id = search_data.get("search_id")

                for _ in range(30):
                    await asyncio.sleep(2)
                    async with session.get(
                        f"{self.base_url}/api/ariel/searches/{search_id}",
                        headers=self._headers(),
                        ssl=self.verify_ssl,
                    ) as status_resp:
                        status_data = await status_resp.json()
                        if status_data.get("status") == "COMPLETED":
                            async with session.get(
                                f"{self.base_url}/api/ariel/searches/{search_id}/results",
                                headers=self._headers(),
                                ssl=self.verify_ssl,
                            ) as results_resp:
                                results = await results_resp.json()
                                events_list = results.get("events", [])
                                return [
                                    self._parse_qradar_event(e)
                                    for e in events_list[:limit]
                                ]

                logger.warning("QRadar search timed out")
                return []

    async def _generic_search(
        self,
        query: str,
        start_time: datetime,
        end_time: datetime,
        limit: int,
    ) -> List[SIEMEvent]:
        """Execute generic SIEM search."""
        body = {
            "query": query,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "limit": limit,
        }

        async with aiohttp.ClientSession(
            timeout=self.timeout, connector=self._connector()
        ) as session:
            async with session.post(
                f"{self.base_url}/api/search",
                headers=self._headers(),
                json=body,
                ssl=self.verify_ssl,
            ) as resp:
                if resp.status != 200:
                    logger.error(f"Generic SIEM search failed: {resp.status}")
                    return []

                data = await resp.json()
                events_list = data.get("events", data.get("results", []))
                return [self._parse_generic_event(e) for e in events_list[:limit]]

    async def get_alerts(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> List[SIEMAlert]:
        """Retrieve alerts from the SIEM."""
        if not self.base_url:
            return []

        try:
            if self.platform == "splunk":
                return await self._splunk_get_alerts(severity, status, limit)
            elif self.platform == "elastic":
                return await self._elastic_get_alerts(severity, status, limit)
            elif self.platform == "sentinel":
                return await self._sentinel_get_alerts(severity, status, limit)
            else:
                return await self._generic_get_alerts(severity, status, limit)
        except Exception as e:
            logger.error(f"Failed to get SIEM alerts: {e}")
            return []

    async def _splunk_get_alerts(
        self, severity: Optional[str], status: Optional[str], limit: int
    ) -> List[SIEMAlert]:
        query = 'search index=_audit action=alert'
        if severity:
            query += f' severity={severity}'
        if status:
            query += f' alert_status="{status}"'

        events = await self._splunk_search(
            query,
            datetime.utcnow() - timedelta(hours=24),
            datetime.utcnow(),
            limit,
        )
        return [
            SIEMAlert(
                alert_id=e.fields.get("alert_sid", e.event_id),
                title=e.fields.get("alert_name", "Unknown Alert"),
                severity=e.fields.get("severity", "medium"),
                status=e.fields.get("alert_status", "new"),
                created_at=e.timestamp,
                description=e.fields.get("alert_message", ""),
                source="splunk",
                related_events=e.fields.get("related_events", "").split(",") if e.fields.get("related_events") else [],
            )
            for e in events
        ]

    async def _elastic_get_alerts(
        self, severity: Optional[str], status: Optional[str], limit: int
    ) -> List[SIEMAlert]:
        query = "kind:alert"
        if severity:
            query += f" AND event.severity:{severity}"
        if status:
            query += f" AND signal_status:{status}"

        body = {
            "query": {"query_string": {"query": query}},
            "size": limit,
            "sort": [{"@timestamp": "desc"}],
        }

        async with aiohttp.ClientSession(
            timeout=self.timeout, connector=self._connector()
        ) as session:
            async with session.post(
                f"{self.base_url}/.siem-signals/_search",
                headers=self._headers(),
                json=body,
                ssl=self.verify_ssl,
            ) as resp:
                if resp.status != 200:
                    return []

                data = await resp.json()
                hits = data.get("hits", {}).get("hits", [])
                alerts: List[SIEMAlert] = []
                for h in hits:
                    src = h.get("_source", {})
                    alerts.append(SIEMAlert(
                        alert_id=h.get("_id", ""),
                        title=src.get("signal", {}).get("rule", {}).get("name", "Unknown"),
                        severity=src.get("event", {}).get("severity", "medium"),
                        status=src.get("signal_status", "new"),
                        created_at=src.get("@timestamp", ""),
                        description=src.get("signal", {}).get("rule", {}).get("description", ""),
                        source="elastic",
                        mitre_techniques=[
                            t.get("id") for t in src.get("signal", {})
                            .get("rule", {})
                            .get("mitre", [])
                        ] if src.get("signal", {}).get("rule", {}).get("mitre") else [],
                    ))
                return alerts

    async def _sentinel_get_alerts(
        self, severity: Optional[str], status: Optional[str], limit: int
    ) -> List[SIEMAlert]:
        """Retrieve alerts from Microsoft Sentinel via KQL."""
        query = "SecurityAlert | sort by TimeGenerated desc"
        if severity:
            query += f" | where Severity == '{severity}'"
        if status:
            query += f" | where Status == '{status}'"
        query += f" | take {limit}"

        events = await self._sentinel_search(
            query=query,
            start_time=datetime.utcnow() - timedelta(days=7),
            end_time=datetime.utcnow(),
            limit=limit,
        )

        return [
            SIEMAlert(
                alert_id=e.event_id,
                title=e.fields.get("AlertName", e.fields.get("DisplayName", "")),
                severity=e.severity,
                status=e.fields.get("Status", "new"),
                created=e.timestamp,
                description=e.fields.get("Description", e.raw),
                mitre_technique=e.fields.get("Tactic", ""),
            )
            for e in events
        ]

    async def _generic_get_alerts(
        self, severity: Optional[str], status: Optional[str], limit: int
    ) -> List[SIEMAlert]:
        params = {"limit": limit}
        if severity:
            params["severity"] = severity
        if status:
            params["status"] = status

        async with aiohttp.ClientSession(
            timeout=self.timeout, connector=self._connector()
        ) as session:
            async with session.get(
                f"{self.base_url}/api/alerts",
                headers=self._headers(),
                params=params,
                ssl=self.verify_ssl,
            ) as resp:
                if resp.status != 200:
                    return []

                data = await resp.json()
                alerts_list = data.get("alerts", data) if isinstance(data, dict) else data
                return [
                    SIEMAlert(
                        alert_id=a.get("id", ""),
                        title=a.get("title", "Unknown Alert"),
                        severity=a.get("severity", "medium"),
                        status=a.get("status", "new"),
                        created_at=a.get("created_at", ""),
                        description=a.get("description", ""),
                        source="generic",
                        mitre_techniques=a.get("mitre_techniques", []),
                    )
                    for a in alerts_list
                ]

    async def ingest_log(self, log_entry: Dict[str, Any]) -> bool:
        """Ingest a log entry into the SIEM.

        Args:
            log_entry: Log data to ingest

        Returns:
            True if ingestion was successful
        """
        if not self.base_url:
            return False

        try:
            if self.platform == "elastic":
                index = self.index or "ciicerone-logs"
                async with aiohttp.ClientSession(
                    timeout=self.timeout, connector=self._connector()
                ) as session:
                    async with session.post(
                        f"{self.base_url}/{index}/_doc",
                        headers=self._headers(),
                        json=log_entry,
                        ssl=self.verify_ssl,
                    ) as resp:
                        return resp.status in (200, 201)
            elif self.platform == "splunk":
                payload = {"sourcetype": "ciicerone", "event": log_entry}
                async with aiohttp.ClientSession(
                    timeout=self.timeout, connector=self._connector()
                ) as session:
                    async with session.post(
                        f"{self.base_url}/services/receivers/simple",
                        headers=self._headers(),
                        data=json.dumps(payload),
                        ssl=self.verify_ssl,
                    ) as resp:
                        return resp.status in (200, 201)
            else:
                async with aiohttp.ClientSession(
                    timeout=self.timeout, connector=self._connector()
                ) as session:
                    async with session.post(
                        f"{self.base_url}/api/ingest",
                        headers=self._headers(),
                        json=log_entry,
                        ssl=self.verify_ssl,
                    ) as resp:
                        return resp.status in (200, 201)
        except Exception as e:
            logger.error(f"SIEM log ingestion failed: {e}")
            return False

    async def ingest_logs_batch(self, logs: List[Dict[str, Any]]) -> int:
        """Ingest multiple log entries.

        Returns:
            Number of successfully ingested logs
        """
        success = 0
        for log_entry in logs:
            if await self.ingest_log(log_entry):
                success += 1
        return success

    def _parse_splunk_event(self, result: Dict[str, Any]) -> SIEMEvent:
        return SIEMEvent(
            event_id=result.get("_key", result.get("_raw", "")),
            timestamp=result.get("_time", ""),
            source=result.get("_source", ""),
            source_type=result.get("_sourcetype", ""),
            host=result.get("host", ""),
            raw=result.get("_raw", ""),
            fields={k: v for k, v in result.items() if not k.startswith("_")},
            severity=result.get("severity", "info"),
        )

    def _parse_elastic_event(self, hit: Dict[str, Any]) -> SIEMEvent:
        src = hit.get("_source", {})
        return SIEMEvent(
            event_id=hit.get("_id", ""),
            timestamp=src.get("@timestamp", ""),
            source=src.get("event", {}).get("dataset", ""),
            source_type=src.get("event", {}).get("category", ""),
            host=src.get("host", {}).get("name", src.get("host", "")),
            raw=json.dumps(src),
            fields=src,
            severity=src.get("event", {}).get("severity", "info"),
            mitre_technique=src.get("event", {}).get("mitre_id"),
        )

    def _parse_sentinel_event(self, fields: Dict[str, Any]) -> SIEMEvent:
        return SIEMEvent(
            event_id=str(fields.get("EventID", fields.get("id", ""))),
            timestamp=fields.get("TimeGenerated", fields.get("timestamp", "")),
            source=fields.get("SourceSystem", ""),
            source_type=fields.get("Type", ""),
            host=fields.get("Computer", ""),
            raw=json.dumps(fields),
            fields=fields,
            severity=fields.get("Severity", fields.get("Level", "info")),
        )

    def _parse_qradar_event(self, event: Dict[str, Any]) -> SIEMEvent:
        return SIEMEvent(
            event_id=str(event.get("event_id", "")),
            timestamp=event.get("start_time", ""),
            source=event.get("log_source_id", ""),
            source_type=event.get("category", ""),
            host=event.get("source_ip", ""),
            raw=event.get("payload", ""),
            fields=event,
            severity=event.get("severity", "info"),
        )

    def _parse_generic_event(self, event: Dict[str, Any]) -> SIEMEvent:
        return SIEMEvent(
            event_id=str(event.get("id", event.get("event_id", ""))),
            timestamp=event.get("timestamp", event.get("@timestamp", "")),
            source=event.get("source", ""),
            source_type=event.get("source_type", ""),
            host=event.get("host", ""),
            raw=json.dumps(event),
            fields=event,
            severity=event.get("severity", "info"),
        )
