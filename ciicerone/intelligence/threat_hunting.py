"""Threat Hunting Service for Ciicerone.

Provides CVE intelligence gathering, KEV correlation, exploit availability
tracking, and structured hunting session management backed by live feeds
from NVD, CISA, and ExploitDB.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

import httpx
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class CVESeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


class ExploitAvailability(str, Enum):
    PUBLIC = "public"
    POC = "poc"
    WEAPONISED = "weaponised"
    KEV = "kev"
    NONE = "none"
    UNKNOWN = "unknown"


class ThreatHuntType(str, Enum):
    IOC_BASED = "ioc_based"
    TTP_BASED = "ttp_based"
    ANOMALY_BASED = "anomaly_based"
    INTEL_DRIVEN = "intel_driven"
    HYBRID = "hybrid"


class HuntingHypothesisStatus(str, Enum):
    PROPOSED = "proposed"
    ACTIVE = "active"
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"


class HuntingSessionStatus(str, Enum):
    PLANNED = "planned"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETE = "complete"
    ARCHIVED = "archived"


# =============================================================================
# Models
# =============================================================================

class CVEInfo(BaseModel):
    """Enriched CVE record."""

    cve_id: str
    description: str
    cvss_score: Optional[float] = None
    severity: CVESeverity = CVESeverity.UNKNOWN
    published: Optional[str] = None
    modified: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    cwe_ids: List[str] = Field(default_factory=list)
    affected_products: List[str] = Field(default_factory=list)
    exploit_availability: ExploitAvailability = ExploitAvailability.UNKNOWN
    is_in_kev: bool = False
    kev_due_date: Optional[str] = None


class CVEResult(BaseModel):
    cve_info: CVEInfo
    hunt_priority: str = "medium"
    recommended_data_sources: List[str] = Field(default_factory=list)
    recommended_queries: List[str] = Field(default_factory=list)
    fetched_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ExploitIntelligence(BaseModel):
    cve_id: str
    availability: ExploitAvailability
    exploit_db_ids: List[int] = Field(default_factory=list)
    metasploit_modules: List[str] = Field(default_factory=list)
    github_pocs: List[str] = Field(default_factory=list)
    is_weaponised: bool = False
    last_checked: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class KEVEntry(BaseModel):
    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: str
    short_description: str
    required_action: str
    due_date: str
    known_ransomware_use: bool = False
    notes: str = ""


class HuntingHypothesis(BaseModel):
    hypothesis_id: str = Field(default_factory=lambda: str(uuid4()))
    title: str
    description: str
    hunt_type: ThreatHuntType = ThreatHuntType.TTP_BASED
    mitre_tactic: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    status: HuntingHypothesisStatus = HuntingHypothesisStatus.PROPOSED
    data_sources: List[str] = Field(default_factory=list)
    queries: List[str] = Field(default_factory=list)
    evidence: List[str] = Field(default_factory=list)
    priority: str = "medium"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class HuntingSession(BaseModel):
    session_id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    target_environment: str
    description: str = ""
    status: HuntingSessionStatus = HuntingSessionStatus.PLANNED
    hypotheses: List[HuntingHypothesis] = Field(default_factory=list)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    cve_intel: List[CVEInfo] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None


# =============================================================================
# Service
# =============================================================================

class ThreatHuntingService:
    """Service for CVE intelligence gathering and threat hunting.

    Fetches live data from:
    - NVD (National Vulnerability Database) for CVE details
    - CISA KEV catalogue for known exploited vulnerabilities
    - ExploitDB / GitHub for exploit availability

    Sessions and hypotheses are held in memory; wire up a database
    backend by overriding ``_store_session`` / ``_load_session``.
    """

    NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    EXPLOITDB_SEARCH = "https://www.exploit-db.com/search?cve={cve_id}&type=webapps&format=json"

    def __init__(self) -> None:
        self._sessions: Dict[str, HuntingSession] = {}
        self._kev_cache: Optional[List[Dict[str, Any]]] = None
        self._kev_cache_time: Optional[datetime] = None
        self._kev_cache_ttl = timedelta(hours=1)

    # ------------------------------------------------------------------
    # CVE lookup
    # ------------------------------------------------------------------

    async def get_cve(self, cve_id: str) -> CVEInfo:
        """Fetch and enrich a single CVE from NVD + KEV."""
        cve_id = cve_id.upper()
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(self.NVD_BASE, params={"cveId": cve_id})
        resp.raise_for_status()
        data = resp.json()

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            raise ValueError(f"CVE {cve_id} not found in NVD")

        return await self._parse_cve(vulns[0]["cve"])

    async def search_cves(
        self,
        keyword: str,
        severity: Optional[CVESeverity] = None,
        days: Optional[int] = None,
        limit: int = 20,
    ) -> List[CVEInfo]:
        """Search NVD by keyword with optional severity / recency filters."""
        params: Dict[str, Any] = {"keywordSearch": keyword, "resultsPerPage": min(limit, 50)}
        if severity:
            params["cvssV3Severity"] = severity.value
        if days:
            end = datetime.now(timezone.utc)
            start = end - timedelta(days=days)
            params["pubStartDate"] = start.strftime("%Y-%m-%dT%H:%M:%S.000")
            params["pubEndDate"] = end.strftime("%Y-%m-%dT%H:%M:%S.000")

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(self.NVD_BASE, params=params)
        resp.raise_for_status()
        data = resp.json()

        results = []
        for item in data.get("vulnerabilities", []):
            try:
                results.append(await self._parse_cve(item["cve"]))
            except Exception as exc:
                logger.warning("Failed to parse CVE item: %s", exc)

        return results[:limit]

    async def _parse_cve(self, cve_data: Dict[str, Any]) -> CVEInfo:
        """Parse a raw NVD CVE dict into a CVEInfo model."""
        cve_id: str = cve_data.get("id", "")
        desc = next(
            (d["value"] for d in cve_data.get("descriptions", []) if d["lang"] == "en"),
            "No description available.",
        )
        metrics = cve_data.get("metrics", {})
        cvss_list = (
            metrics.get("cvssMetricV31", [])
            or metrics.get("cvssMetricV30", [])
            or metrics.get("cvssMetricV2", [])
        )
        base_score: Optional[float] = None
        severity = CVESeverity.UNKNOWN
        if cvss_list:
            base_score = float(cvss_list[0]["cvssData"].get("baseScore", 0))
            raw_sev = cvss_list[0]["cvssData"].get("baseSeverity", "UNKNOWN").upper()
            try:
                severity = CVESeverity(raw_sev)
            except ValueError:
                severity = CVESeverity.UNKNOWN

        refs = [r.get("url", "") for r in cve_data.get("references", []) if r.get("url")]
        cwes = [
            w.get("description", [{}])[0].get("value", "")
            for w in cve_data.get("weaknesses", [])
        ]
        configs = cve_data.get("configurations", [])
        products = [
            cpe.get("criteria", "")
            for cfg in configs
            for node in cfg.get("nodes", [])
            for cpe in node.get("cpeMatch", [])
        ]

        # KEV check
        kev_entries = await self._get_kev()
        kev_match = next((e for e in kev_entries if e.get("cveID", "").upper() == cve_id), None)
        is_in_kev = kev_match is not None
        kev_due = kev_match.get("dueDate") if kev_match else None

        exploit_avail = ExploitAvailability.KEV if is_in_kev else ExploitAvailability.UNKNOWN

        return CVEInfo(
            cve_id=cve_id,
            description=desc,
            cvss_score=base_score,
            severity=severity,
            published=cve_data.get("published", "")[:10],
            modified=cve_data.get("lastModified", "")[:10],
            references=refs[:10],
            cwe_ids=[c for c in cwes if c],
            affected_products=products[:20],
            exploit_availability=exploit_avail,
            is_in_kev=is_in_kev,
            kev_due_date=kev_due,
        )

    # ------------------------------------------------------------------
    # KEV
    # ------------------------------------------------------------------

    async def _get_kev(self) -> List[Dict[str, Any]]:
        """Fetch and cache the CISA KEV catalogue."""
        now = datetime.now(timezone.utc)
        if (
            self._kev_cache is not None
            and self._kev_cache_time is not None
            and (now - self._kev_cache_time) < self._kev_cache_ttl
        ):
            return self._kev_cache

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(self.KEV_URL)
                resp.raise_for_status()
            self._kev_cache = resp.json().get("vulnerabilities", [])
            self._kev_cache_time = now
        except Exception as exc:
            logger.warning("Could not fetch KEV catalogue: %s", exc)
            self._kev_cache = self._kev_cache or []

        return self._kev_cache

    async def get_kev_entries(
        self,
        days: Optional[int] = None,
        vendor: Optional[str] = None,
        limit: int = 100,
    ) -> List[KEVEntry]:
        """Return filtered KEV entries."""
        raw = await self._get_kev()
        cutoff = (datetime.utcnow() - timedelta(days=days)) if days else None
        results = []
        for entry in raw:
            if vendor and vendor.lower() not in entry.get("vendorProject", "").lower():
                continue
            if cutoff:
                try:
                    added = datetime.strptime(entry.get("dateAdded", ""), "%Y-%m-%d")
                    if added < cutoff:
                        continue
                except ValueError:
                    pass
            results.append(KEVEntry(
                cve_id=entry.get("cveID", ""),
                vendor_project=entry.get("vendorProject", ""),
                product=entry.get("product", ""),
                vulnerability_name=entry.get("vulnerabilityName", ""),
                date_added=entry.get("dateAdded", ""),
                short_description=entry.get("shortDescription", ""),
                required_action=entry.get("requiredAction", ""),
                due_date=entry.get("dueDate", ""),
                known_ransomware_use=(entry.get("knownRansomwareCampaignUse", "Unknown") == "Known"),
                notes=entry.get("notes", ""),
            ))
        return results[:limit]

    # ------------------------------------------------------------------
    # Sessions
    # ------------------------------------------------------------------

    def create_session(
        self,
        name: str,
        target_environment: str,
        description: str = "",
    ) -> HuntingSession:
        """Create and store a new hunting session."""
        session = HuntingSession(
            name=name,
            target_environment=target_environment,
            description=description,
            status=HuntingSessionStatus.ACTIVE,
        )
        self._sessions[session.session_id] = session
        logger.info("Created hunt session %s: %s", session.session_id, name)
        return session

    def get_session(self, session_id: str) -> Optional[HuntingSession]:
        """Retrieve a session by ID."""
        return self._sessions.get(session_id)

    def list_sessions(self, status: Optional[HuntingSessionStatus] = None) -> List[HuntingSession]:
        """List all sessions, optionally filtered by status."""
        sessions = list(self._sessions.values())
        if status:
            sessions = [s for s in sessions if s.status == status]
        return sessions

    def add_hypothesis(self, session_id: str, hypothesis: HuntingHypothesis) -> HuntingSession:
        """Add a hunting hypothesis to a session."""
        session = self._sessions.get(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")
        session.hypotheses.append(hypothesis)
        session.updated_at = datetime.now(timezone.utc)
        return session

    def update_hypothesis_status(
        self,
        session_id: str,
        hypothesis_id: str,
        status: HuntingHypothesisStatus,
        evidence: Optional[List[str]] = None,
    ) -> HuntingHypothesis:
        """Update the status and evidence for a hypothesis."""
        session = self._sessions.get(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")
        for hyp in session.hypotheses:
            if hyp.hypothesis_id == hypothesis_id:
                hyp.status = status
                if evidence:
                    hyp.evidence.extend(evidence)
                hyp.updated_at = datetime.now(timezone.utc)
                session.updated_at = datetime.now(timezone.utc)
                return hyp
        raise ValueError(f"Hypothesis {hypothesis_id} not found in session {session_id}")

    def close_session(self, session_id: str) -> HuntingSession:
        """Mark a session as complete."""
        session = self._sessions.get(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")
        session.status = HuntingSessionStatus.COMPLETE
        session.completed_at = datetime.now(timezone.utc)
        session.updated_at = session.completed_at
        return session


# =============================================================================
# Singleton accessor
# =============================================================================

_service: Optional[ThreatHuntingService] = None


def get_threat_hunting_service() -> ThreatHuntingService:
    """Return the module-level ThreatHuntingService singleton."""
    global _service
    if _service is None:
        _service = ThreatHuntingService()
    return _service
