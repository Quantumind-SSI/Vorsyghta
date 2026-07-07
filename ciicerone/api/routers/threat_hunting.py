"""Threat Hunting API Router.

Provides REST endpoints for threat hunting workflows:
- CVE lookup and enrichment via NVD
- CISA Known Exploited Vulnerabilities (KEV) catalogue
- AI-generated hunting hypotheses
- Hunt session management (CRUD)
"""

import json
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from pathlib import Path
from enum import Enum

import httpx
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/threat-hunting", tags=["Threat Hunting"])


# =============================================================================
# Redis-backed session store (shared across all uvicorn workers)
# =============================================================================

from ciicerone.core.redis_client import get_redis_client

_SESSION_KEY_PREFIX = "ciicerone:hunt_session:"
_SESSION_INDEX_KEY = "ciicerone:hunt_session_index"
_SESSION_TTL = 30 * 24 * 3600  # 30 days


def _get_redis():
    """Return the shared Redis client or None."""
    return get_redis_client()


# Fallback in-memory store (used only when Redis is unavailable)
_sessions: Dict[str, Dict[str, Any]] = {}


def _save_session(session_id: str, data: Dict[str, Any]) -> None:
    r = _get_redis()
    if r is not None:
        r.setex(f"{_SESSION_KEY_PREFIX}{session_id}", _SESSION_TTL, json.dumps(data, default=str))
        r.sadd(_SESSION_INDEX_KEY, session_id)
        r.expire(_SESSION_INDEX_KEY, _SESSION_TTL)
    else:
        _sessions[session_id] = data


def _load_session(session_id: str) -> Optional[Dict[str, Any]]:
    r = _get_redis()
    if r is not None:
        raw = r.get(f"{_SESSION_KEY_PREFIX}{session_id}")
        if raw:
            return json.loads(raw)
        return None
    return _sessions.get(session_id)


def _load_all_sessions() -> List[Dict[str, Any]]:
    r = _get_redis()
    if r is not None:
        ids = r.smembers(_SESSION_INDEX_KEY)
        sessions = []
        for sid in ids:
            raw = r.get(f"{_SESSION_KEY_PREFIX}{sid}")
            if raw:
                sessions.append(json.loads(raw))
            else:
                # Stale index entry — clean up
                r.srem(_SESSION_INDEX_KEY, sid)
        return sessions
    return list(_sessions.values())


def _delete_session(session_id: str) -> bool:
    r = _get_redis()
    if r is not None:
        deleted = r.delete(f"{_SESSION_KEY_PREFIX}{session_id}")
        r.srem(_SESSION_INDEX_KEY, session_id)
        return deleted > 0
    if session_id in _sessions:
        del _sessions[session_id]
        return True
    return False


# =============================================================================
# Models
# =============================================================================

class CVESeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


class CVEResult(BaseModel):
    cve_id: str
    description: str
    cvss_score: Optional[float] = None
    severity: CVESeverity = CVESeverity.UNKNOWN
    published: Optional[str] = None
    modified: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    cwe_ids: List[str] = Field(default_factory=list)
    affected_products: List[str] = Field(default_factory=list)


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


class HypothesisRequest(BaseModel):
    target_environment: str = Field(..., description="Description of the target environment")
    tactic: Optional[str] = Field(None, description="MITRE ATT&CK tactic to focus on")
    cve_ids: List[str] = Field(default_factory=list, description="CVEs to base hypotheses on")
    count: int = Field(5, ge=1, le=20, description="Number of hypotheses to generate")


class HuntingHypothesis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    tactic: str
    technique_id: Optional[str] = None
    description: str
    data_sources: List[str] = Field(default_factory=list)
    hunt_queries: List[str] = Field(default_factory=list)
    priority: str = "medium"


class HypothesisResponse(BaseModel):
    target_environment: str
    hypotheses: List[HuntingHypothesis]
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class HuntSessionCreate(BaseModel):
    name: str = Field(..., description="Human-readable session name")
    target_environment: str
    description: str = ""
    hypotheses: List[HuntingHypothesis] = Field(default_factory=list)


class HuntSession(BaseModel):
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    target_environment: str
    description: str = ""
    status: str = "active"
    hypotheses: List[HuntingHypothesis] = Field(default_factory=list)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    closed_at: Optional[datetime] = None


class HuntFinding(BaseModel):
    hypothesis_id: Optional[str] = None
    title: str
    description: str
    severity: str = "medium"
    evidence: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# =============================================================================
# CVE endpoints
# =============================================================================

@router.get("/cve/{cve_id}", response_model=CVEResult)
async def get_cve(cve_id: str):
    """Fetch CVE details from the NVD (NIST National Vulnerability Database).

    Returns CVSS score, severity, description, and affected products.
    """
    cve_id = cve_id.upper()
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=exc.response.status_code, detail=f"NVD API error: {exc}")
    except httpx.RequestError as exc:
        raise HTTPException(status_code=503, detail=f"NVD unreachable: {exc}")

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found in NVD")

    cve_data = vulns[0]["cve"]
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

    refs = [r.get("url", "") for r in cve_data.get("references", [])]
    cwes = [
        w.get("description", [{}])[0].get("value", "")
        for w in cve_data.get("weaknesses", [])
    ]

    configs = cve_data.get("configurations", [])
    products: List[str] = []
    for cfg in configs:
        for node in cfg.get("nodes", []):
            for cpe in node.get("cpeMatch", []):
                products.append(cpe.get("criteria", ""))

    return CVEResult(
        cve_id=cve_id,
        description=desc,
        cvss_score=base_score,
        severity=severity,
        published=cve_data.get("published", "")[:10],
        modified=cve_data.get("lastModified", "")[:10],
        references=refs[:10],
        cwe_ids=[c for c in cwes if c],
        affected_products=products[:20],
    )


@router.get("/cve", response_model=List[CVEResult])
async def search_cves(
    keyword: str = Query(..., description="Keyword to search NVD"),
    severity: Optional[CVESeverity] = Query(None),
    days: Optional[int] = Query(None, description="Published in last N days"),
    limit: int = Query(10, ge=1, le=50),
):
    """Search NVD for CVEs matching a keyword with optional filters."""
    params: Dict[str, Any] = {"keywordSearch": keyword, "resultsPerPage": min(limit, 50)}
    if days:
        pub_end = datetime.now(timezone.utc)
        pub_start = pub_end - timedelta(days=days)
        params["pubStartDate"] = pub_start.strftime("%Y-%m-%dT%H:%M:%S.000")
        params["pubEndDate"] = pub_end.strftime("%Y-%m-%dT%H:%M:%S.000")
    if severity:
        params["cvssV3Severity"] = severity.value

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params=params,
            )
            resp.raise_for_status()
            data = resp.json()
    except httpx.RequestError as exc:
        raise HTTPException(status_code=503, detail=f"NVD unreachable: {exc}")

    results = []
    for item in data.get("vulnerabilities", []):
        cve_data = item["cve"]
        desc = next(
            (d["value"] for d in cve_data.get("descriptions", []) if d["lang"] == "en"),
            "",
        )
        metrics = cve_data.get("metrics", {})
        cvss_list = (
            metrics.get("cvssMetricV31", [])
            or metrics.get("cvssMetricV30", [])
            or metrics.get("cvssMetricV2", [])
        )
        base_score = float(cvss_list[0]["cvssData"].get("baseScore", 0)) if cvss_list else None
        raw_sev = (cvss_list[0]["cvssData"].get("baseSeverity", "UNKNOWN").upper()) if cvss_list else "UNKNOWN"
        try:
            sev = CVESeverity(raw_sev)
        except ValueError:
            sev = CVESeverity.UNKNOWN
        results.append(CVEResult(
            cve_id=cve_data["id"],
            description=desc,
            cvss_score=base_score,
            severity=sev,
            published=cve_data.get("published", "")[:10],
        ))

    return results[:limit]


# =============================================================================
# KEV endpoints
# =============================================================================

_kev_cache: Dict[str, Any] = {"data": None, "fetched_at": None}
_KEV_CACHE_TTL = 3600  # 1 hour


async def _fetch_kev() -> List[Dict[str, Any]]:
    """Fetch and cache the CISA KEV catalogue."""
    now = datetime.now(timezone.utc)
    if (
        _kev_cache["data"] is not None
        and _kev_cache["fetched_at"] is not None
        and (now - _kev_cache["fetched_at"]).total_seconds() < _KEV_CACHE_TTL
    ):
        return _kev_cache["data"]

    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
    except httpx.RequestError as exc:
        raise HTTPException(status_code=503, detail=f"CISA KEV feed unreachable: {exc}")

    entries = data.get("vulnerabilities", [])
    _kev_cache["data"] = entries
    _kev_cache["fetched_at"] = now
    return entries


@router.get("/kev", response_model=List[KEVEntry])
async def list_kev(
    days: Optional[int] = Query(None, description="Entries added in last N days"),
    vendor: Optional[str] = Query(None, description="Vendor/project substring filter"),
    limit: int = Query(50, ge=1, le=500),
):
    """Return entries from the CISA Known Exploited Vulnerabilities catalogue."""
    entries = await _fetch_kev()

    cutoff = (datetime.utcnow() - timedelta(days=days)) if days else None
    results = []
    for entry in entries:
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


@router.get("/kev/{cve_id}", response_model=Optional[KEVEntry])
async def get_kev_entry(cve_id: str):
    """Check whether a specific CVE is in the CISA KEV catalogue."""
    cve_id = cve_id.upper()
    entries = await _fetch_kev()
    for entry in entries:
        if entry.get("cveID", "").upper() == cve_id:
            return KEVEntry(
                cve_id=entry["cveID"],
                vendor_project=entry.get("vendorProject", ""),
                product=entry.get("product", ""),
                vulnerability_name=entry.get("vulnerabilityName", ""),
                date_added=entry.get("dateAdded", ""),
                short_description=entry.get("shortDescription", ""),
                required_action=entry.get("requiredAction", ""),
                due_date=entry.get("dueDate", ""),
                known_ransomware_use=(entry.get("knownRansomwareCampaignUse", "Unknown") == "Known"),
                notes=entry.get("notes", ""),
            )
    raise HTTPException(status_code=404, detail=f"{cve_id} is not in the CISA KEV catalogue")


# =============================================================================
# Hypothesis generation
# =============================================================================

@router.post("/hypotheses/generate", response_model=HypothesisResponse)
async def generate_hypotheses(request: HypothesisRequest):
    """Generate AI-powered threat hunting hypotheses.

    Uses the configured LLM to produce structured, testable hypotheses
    aligned to MITRE ATT&CK for the specified target environment.
    """
    # Use the global LLM manager initialised during app startup (has Azure OpenAI configured)
    from ciicerone.api.main import llm_manager as global_llm
    mgr = global_llm
    if mgr is None:
        try:
            from ciicerone.llm.manager import LLMManager
            mgr = LLMManager()
        except ImportError as exc:
            raise HTTPException(status_code=503, detail=f"LLM manager unavailable: {exc}")

    cve_context = f"CVEs of interest: {', '.join(request.cve_ids)}. " if request.cve_ids else ""
    tactic_context = f"Focus on the '{request.tactic}' tactic. " if request.tactic else ""

    prompt = (
        f"You are a threat hunting expert. Generate {request.count} structured threat hunting "
        f"hypotheses for: {request.target_environment}. {tactic_context}{cve_context}"
        "Return a JSON array. Each element must have: title (string), tactic (MITRE ATT&CK tactic), "
        "technique_id (string, e.g. T1078), description (string), "
        "data_sources (array of strings), hunt_queries (array of pseudo-query strings), "
        "priority (one of: critical, high, medium, low)."
    )

    try:
        response = await mgr.generate_content(prompt, max_tokens=2500)
        response_text = response.content
    except Exception as exc:
        logger.error("LLM generation failed: %s", exc)
        raise HTTPException(status_code=502, detail=f"LLM generation failed: {exc}")

    import re
    try:
        match = re.search(r"\[.*\]", response_text, re.DOTALL)
        raw = json.loads(match.group(0)) if match else []
    except Exception:
        logger.warning("Could not parse JSON from LLM response; returning empty list")
        raw = []

    hypotheses = []
    for item in raw:
        try:
            hypotheses.append(HuntingHypothesis(
                title=item.get("title", "Untitled"),
                tactic=item.get("tactic", "unknown"),
                technique_id=item.get("technique_id"),
                description=item.get("description", ""),
                data_sources=item.get("data_sources", []),
                hunt_queries=item.get("hunt_queries", []),
                priority=item.get("priority", "medium"),
            ))
        except Exception as exc:
            logger.warning("Skipping malformed hypothesis item: %s", exc)

    return HypothesisResponse(
        target_environment=request.target_environment,
        hypotheses=hypotheses,
    )


# =============================================================================
# Hunt session management
# =============================================================================

@router.post("/sessions", response_model=HuntSession, status_code=status.HTTP_201_CREATED)
async def create_session(payload: HuntSessionCreate):
    """Create a new threat hunting session."""
    session = HuntSession(
        name=payload.name,
        target_environment=payload.target_environment,
        description=payload.description,
        hypotheses=payload.hypotheses,
    )
    _save_session(session.session_id, session.model_dump())
    logger.info("Hunt session created: %s (%s)", session.session_id, session.name)
    return session


@router.get("/sessions", response_model=List[HuntSession])
async def list_sessions(
    status_filter: Optional[str] = Query(None, alias="status"),
    limit: int = Query(20, ge=1, le=100),
):
    """List all hunt sessions, optionally filtered by status."""
    sessions = _load_all_sessions()
    if status_filter:
        sessions = [s for s in sessions if s.get("status") == status_filter]
    return sessions[:limit]


@router.get("/sessions/{session_id}", response_model=HuntSession)
async def get_session(session_id: str):
    """Get a specific hunt session by ID."""
    session = _load_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    return session


@router.post("/sessions/{session_id}/findings", response_model=HuntSession)
async def add_finding(session_id: str, finding: HuntFinding):
    """Add a finding to an existing hunt session."""
    session = _load_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    if session.get("status") == "closed":
        raise HTTPException(status_code=409, detail="Cannot add findings to a closed session")

    session["findings"].append(finding.model_dump())
    session["updated_at"] = datetime.now(timezone.utc).isoformat()
    _save_session(session_id, session)
    return session


@router.patch("/sessions/{session_id}/close", response_model=HuntSession)
async def close_session(session_id: str):
    """Mark a hunt session as closed."""
    session = _load_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    session["status"] = "closed"
    session["closed_at"] = datetime.now(timezone.utc).isoformat()
    session["updated_at"] = session["closed_at"]
    _save_session(session_id, session)
    return session


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_session(session_id: str):
    """Permanently delete a hunt session."""
    if not _delete_session(session_id):
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
