"""Orange Team — compliance and governance engine for Vorsyghta.

The Orange Team maps color-team exercise findings to regulatory frameworks
(PCI-DSS, SOX, GDPR, NIST CSF, ISO 27001), identifies compliance gaps,
generates auditor-ready compliance reports, prioritizes remediation, and
assesses regulatory and financial impact. It also integrates with the
organizational risk register and the shared event bus.

The engine consumes the same Red Team stage events, Blue Team alert events,
and Purple Team AAR that the other color teams produce, and publishes
``ORANGE_TEAM_COMPLIANCE_GAP`` and ``ORANGE_TEAM_REGULATORY_MAPPING`` events
on the event bus.

Owner: Orange Team Lead — Compliance & Governance
Phase 4 — Orange Team compliance engine
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

from vorsyghta.core.event_bus import EventBus
from vorsyghta.core.event_types import (
    BusEvent,
    EventType,
    OrangeTeamComplianceGapEvent,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Regulatory framework control catalogs
# ---------------------------------------------------------------------------
#
# Each framework is a mapping of control_id -> control metadata. The metadata
# includes a human-readable title, the control family, and an optional
# regulatory deadline (in days from gap identification) used when prioritizing
# remediation.

_FRAMEWORK_CONTROLS: Dict[str, Dict[str, Dict[str, Any]]] = {
    "PCI-DSS": {
        "Req 6": {
            "title": "Develop and maintain secure systems and applications",
            "family": "Secure Systems",
            "deadline_days": 30,
        },
        "Req 8": {
            "title": "Identify users and authenticate access to system components",
            "family": "Authentication",
            "deadline_days": 15,
        },
        "Req 10": {
            "title": "Track and monitor all access to network resources and cardholder data",
            "family": "Monitoring",
            "deadline_days": 30,
        },
        "Req 11": {
            "title": "Regularly test security systems and processes",
            "family": "Testing",
            "deadline_days": 90,
        },
        "Req 12": {
            "title": "Maintain an information security policy",
            "family": "Policy",
            "deadline_days": 60,
        },
    },
    "SOX": {
        "Section 302": {
            "title": "Corporate responsibility for financial reports",
            "family": "Corporate Governance",
            "deadline_days": 45,
        },
        "Section 404": {
            "title": "Management assessment of internal controls",
            "family": "Internal Controls",
            "deadline_days": 90,
        },
        "ITGC-Access": {
            "title": "IT General Controls — access controls",
            "family": "ITGC",
            "deadline_days": 30,
        },
        "ITGC-Change": {
            "title": "IT General Controls — change management",
            "family": "ITGC",
            "deadline_days": 45,
        },
        "ITGC-Ops": {
            "title": "IT General Controls — operations",
            "family": "ITGC",
            "deadline_days": 45,
        },
    },
    "GDPR": {
        "Article 5": {
            "title": "Principles relating to processing of personal data",
            "family": "Data Protection",
            "deadline_days": 30,
        },
        "Article 32": {
            "title": "Security of processing",
            "family": "Security",
            "deadline_days": 15,
        },
        "Article 33": {
            "title": "Notification of personal data breach (72 hours)",
            "family": "Breach Notification",
            "deadline_days": 3,
        },
        "Article 35": {
            "title": "Data protection impact assessment",
            "family": "Assessment",
            "deadline_days": 60,
        },
    },
    "NIST CSF": {
        "ID.AM": {
            "title": "Identify — Asset management",
            "family": "Identify",
            "deadline_days": 60,
        },
        "ID.RA": {
            "title": "Identify — Risk assessment",
            "family": "Identify",
            "deadline_days": 60,
        },
        "PR.AC": {
            "title": "Protect — Access control",
            "family": "Protect",
            "deadline_days": 30,
        },
        "PR.AT": {
            "title": "Protect — Awareness training",
            "family": "Protect",
            "deadline_days": 90,
        },
        "PR.DS": {
            "title": "Protect — Data security",
            "family": "Protect",
            "deadline_days": 30,
        },
        "DE.CM": {
            "title": "Detect — Continuous monitoring",
            "family": "Detect",
            "deadline_days": 30,
        },
        "DE.AE": {
            "title": "Detect — Anomalies and events",
            "family": "Detect",
            "deadline_days": 30,
        },
        "RS.RP": {
            "title": "Respond — Response planning",
            "family": "Respond",
            "deadline_days": 15,
        },
        "RS.AN": {
            "title": "Respond — Analysis",
            "family": "Respond",
            "deadline_days": 30,
        },
        "RC.RP": {
            "title": "Recover — Recovery planning",
            "family": "Recover",
            "deadline_days": 60,
        },
    },
    "ISO 27001": {
        "A.5": {
            "title": "Information security policies",
            "family": "Policies",
            "deadline_days": 60,
        },
        "A.6": {
            "title": "Organization of information security",
            "family": "Organization",
            "deadline_days": 60,
        },
        "A.8": {
            "title": "Asset management",
            "family": "Assets",
            "deadline_days": 60,
        },
        "A.9": {
            "title": "Access control",
            "family": "Access Control",
            "deadline_days": 30,
        },
        "A.9.2": {
            "title": "User access management",
            "family": "Access Control",
            "deadline_days": 30,
        },
        "A.9.2.3": {
            "title": "User responsibilities / awareness",
            "family": "Access Control",
            "deadline_days": 90,
        },
        "A.9.2.4": {
            "title": "Management of secret authentication information",
            "family": "Access Control",
            "deadline_days": 15,
        },
        "A.12.4": {
            "title": "Logging and monitoring of events",
            "family": "Operations Security",
            "deadline_days": 30,
        },
        "A.12.6": {
            "title": "Technical vulnerability management",
            "family": "Operations Security",
            "deadline_days": 30,
        },
        "A.16": {
            "title": "Incident management",
            "family": "Incident Management",
            "deadline_days": 15,
        },
        "A.18": {
            "title": "Compliance",
            "family": "Compliance",
            "deadline_days": 60,
        },
    },
}


# ---------------------------------------------------------------------------
# MITRE ATT&CK technique -> framework control mapping
# ---------------------------------------------------------------------------
#
# Each technique maps to a list of (framework, control_id) tuples. A technique
# is considered "covered" by a control if the control detected the technique
# during the exercise (i.e. a blue team alert matched the technique).

_TECHNIQUE_CONTROL_MAP: Dict[str, List[Tuple[str, str]]] = {
    "T1566": [  # Phishing
        ("PCI-DSS", "Req 12"),
        ("NIST CSF", "PR.AT"),
        ("ISO 27001", "A.9.2.3"),
        ("NIST CSF", "DE.AE"),
    ],
    "T1059": [  # PowerShell / Command and Scripting Interpreter
        ("PCI-DSS", "Req 6"),
        ("NIST CSF", "PR.AC"),
        ("ISO 27001", "A.12.4"),
        ("NIST CSF", "DE.CM"),
    ],
    "T1078": [  # Valid Accounts
        ("PCI-DSS", "Req 8"),
        ("SOX", "ITGC-Access"),
        ("NIST CSF", "PR.AC"),
        ("ISO 27001", "A.9.2"),
    ],
    "T1003": [  # Credential Dumping (OS Credential Dumping)
        ("PCI-DSS", "Req 8"),
        ("NIST CSF", "PR.AC"),
        ("ISO 27001", "A.9.2.4"),
        ("NIST CSF", "DE.CM"),
    ],
    "T1486": [  # Ransomware / Data Encrypted for Impact
        ("GDPR", "Article 32"),
        ("NIST CSF", "RS.RP"),
        ("ISO 27001", "A.16"),
        ("NIST CSF", "RC.RP"),
    ],
    "T1190": [  # Exploit Public-Facing Application
        ("PCI-DSS", "Req 6"),
        ("NIST CSF", "DE.CM"),
        ("ISO 27001", "A.12.6"),
        ("NIST CSF", "PR.DS"),
    ],
    "T1110": [  # Brute Force
        ("PCI-DSS", "Req 8"),
        ("NIST CSF", "PR.AC"),
        ("ISO 27001", "A.9.2"),
        ("NIST CSF", "DE.AE"),
    ],
    "T1021": [  # Remote Services (lateral movement)
        ("PCI-DSS", "Req 10"),
        ("NIST CSF", "PR.AC"),
        ("ISO 27001", "A.9.2"),
        ("NIST CSF", "DE.CM"),
    ],
    "T1071": [  # Application Layer Protocol (C2)
        ("PCI-DSS", "Req 10"),
        ("NIST CSF", "DE.CM"),
        ("ISO 27001", "A.12.4"),
    ],
    "T1027": [  # Obfuscated Files or Information
        ("PCI-DSS", "Req 11"),
        ("NIST CSF", "DE.AE"),
        ("ISO 27001", "A.12.4"),
    ],
}

# Default mapping for techniques not explicitly listed above. Maps to the
# generic monitoring/policy controls across frameworks.
_DEFAULT_TECHNIQUE_CONTROLS: List[Tuple[str, str]] = [
    ("PCI-DSS", "Req 10"),
    ("NIST CSF", "DE.CM"),
    ("ISO 27001", "A.12.4"),
    ("NIST CSF", "RS.AN"),
]


# ---------------------------------------------------------------------------
# Severity scoring helpers
# ---------------------------------------------------------------------------

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
_SEVERITY_FROM_RANK = {4: "critical", 3: "high", 2: "medium", 1: "low"}

# Indicative regulatory fine ceilings (USD) per framework, used by the
# regulatory impact assessment. These are conservative planning estimates,
# not legal advice.
_FRAMEWORK_MAX_FINE_USD: Dict[str, int] = {
    "PCI-DSS": 100_000,           # per month, per control — capped estimate
    "SOX": 5_000_000,             # per violation (corporate)
    "GDPR": 20_000_000,           # or 4% global turnover, whichever higher
    "NIST CSF": 0,                # voluntary framework — no direct fines
    "ISO 27001": 0,               # certification loss / contractual penalties
}


class ComplianceGovernanceEngine:
    """Orange Team compliance and governance engine.

    Maps color-team exercise findings to regulatory frameworks, identifies
    compliance gaps, generates auditor-ready reports, and feeds the
    organizational risk register.

    Args:
        risk_register: Optional risk register sink with an ``add_risk`` method
            accepting a risk dict. If provided, compliance gaps are pushed into
            the register during analysis.
        llm_provider: Optional LLM provider for AI-enhanced narrative
            generation in compliance reports. If None, rule-based narratives
            are used.
    """

    def __init__(
        self,
        risk_register: Optional[Any] = None,
        llm_provider: Optional[Any] = None,
    ) -> None:
        self.risk_register = risk_register
        self.llm_provider = llm_provider
        # Cached analysis keyed by exercise_id for event-bus driven workflows.
        self._exercise_cache: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # 1. Regulatory framework mapping
    # ------------------------------------------------------------------

    def map_to_frameworks(
        self,
        red_team_stages: List[Dict[str, Any]],
        blue_team_alerts: List[Dict[str, Any]],
        aar: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Dict[str, Dict[str, Any]]]:
        """Map exercise findings to regulatory framework controls.

        For each framework control, the status is determined as:
            - ``compliant`` — the control was exercised and the related
              technique(s) were detected by the blue team.
            - ``partially_compliant`` — the control was exercised and at least
              one related technique was detected, but at least one was missed.
            - ``non_compliant`` — the control was exercised but none of the
              related techniques were detected.
            - ``not_assessed`` — the control was not exercised in this run.

        Args:
            red_team_stages: Red Team attack stage event dicts (with
                ``payload.technique_id``).
            blue_team_alerts: Blue Team alert event dicts (with
                ``payload.technique_id`` and ``payload.detected``).
            aar: Optional Purple Team AAR dict. Coverage gaps and remediation
                recommendations from the AAR are folded into the mapping.

        Returns:
            Mapping of ``framework -> control_id -> control_status_dict``.
            Each control status dict contains:
                ``status``, ``title``, ``family``, ``deadline_days``,
                ``related_techniques``, ``detected_techniques``,
                ``missed_techniques``, ``evidence``.
        """
        attacked_techniques, detected_techniques = self._collect_techniques(
            red_team_stages, blue_team_alerts
        )

        # Build the full framework/control matrix initialized to not_assessed.
        mapping: Dict[str, Dict[str, Dict[str, Any]]] = {}
        for framework, controls in _FRAMEWORK_CONTROLS.items():
            mapping[framework] = {}
            for control_id, meta in controls.items():
                mapping[framework][control_id] = {
                    "status": "not_assessed",
                    "title": meta["title"],
                    "family": meta["family"],
                    "deadline_days": meta.get("deadline_days"),
                    "related_techniques": [],
                    "detected_techniques": [],
                    "missed_techniques": [],
                    "evidence": [],
                }

        # Invert the technique->control map to control->techniques.
        control_to_techniques: Dict[Tuple[str, str], List[str]] = {}
        for tech_id, controls in _TECHNIQUE_CONTROL_MAP.items():
            for fwk, ctrl in controls:
                control_to_techniques.setdefault((fwk, ctrl), []).append(tech_id)
        for tech_id in attacked_techniques:
            controls = _TECHNIQUE_CONTROL_MAP.get(tech_id, _DEFAULT_TECHNIQUE_CONTROLS)
            for fwk, ctrl in controls:
                control_to_techniques.setdefault((fwk, ctrl), []).append(tech_id)

        # Now evaluate each control that has related techniques exercised.
        for (fwk, ctrl), techs in control_to_techniques.items():
            if fwk not in mapping or ctrl not in mapping[fwk]:
                continue
            entry = mapping[fwk][ctrl]
            exercised = [t for t in techs if t in attacked_techniques]
            if not exercised:
                continue
            detected = [t for t in exercised if t in detected_techniques]
            missed = [t for t in exercised if t not in detected_techniques]
            exercised_unique = sorted(set(exercised))
            entry["related_techniques"] = exercised_unique
            entry["detected_techniques"] = sorted(set(detected))
            entry["missed_techniques"] = sorted(set(missed))
            if not missed:
                entry["status"] = "compliant"
                entry["evidence"].append(
                    f"All related techniques ({', '.join(exercised_unique)}) detected by blue team."
                )
            elif detected:
                entry["status"] = "partially_compliant"
                entry["evidence"].append(
                    f"Detected {len(set(detected))}/{len(exercised_unique)} related techniques; "
                    f"missed: {', '.join(sorted(set(missed)))}."
                )
            else:
                entry["status"] = "non_compliant"
                entry["evidence"].append(
                    f"None of the related techniques ({', '.join(exercised_unique)}) were detected."
                )

        # Fold in AAR coverage gaps as additional evidence for non-compliance.
        if aar:
            coverage_gaps = aar.get("coverage_gaps", []) or []
            for gap in coverage_gaps:
                tech_id = gap.get("technique_id")
                if not tech_id:
                    continue
                controls = _TECHNIQUE_CONTROL_MAP.get(
                    tech_id, _DEFAULT_TECHNIQUE_CONTROLS
                )
                for fwk, ctrl in controls:
                    if fwk not in mapping or ctrl not in mapping[fwk]:
                        continue
                    entry = mapping[fwk][ctrl]
                    if entry["status"] == "not_assessed":
                        entry["status"] = "non_compliant"
                        entry["related_techniques"] = list(
                            set(entry["related_techniques"] + [tech_id])
                        )
                        entry["missed_techniques"] = list(
                            set(entry["missed_techniques"] + [tech_id])
                        )
                    entry["evidence"].append(
                        f"AAR coverage gap: {tech_id} ({gap.get('stage_name', 'unknown')}) "
                        f"was not detected."
                    )

        logger.info(
            "Framework mapping complete: frameworks=%d, controls_assessed=%d",
            len(mapping),
            sum(
                1
                for fwk in mapping.values()
                for c in fwk.values()
                if c["status"] != "not_assessed"
            ),
        )
        return mapping

    # ------------------------------------------------------------------
    # 2. Compliance gap analysis
    # ------------------------------------------------------------------

    def analyze_compliance_gaps(
        self, framework_mapping: Dict[str, Dict[str, Dict[str, Any]]]
    ) -> List[Dict[str, Any]]:
        """Identify failing controls and return structured compliance gaps.

        Args:
            framework_mapping: The output of :meth:`map_to_frameworks`.

        Returns:
            A list of compliance gap dicts, each containing:
                ``gap_id``, ``framework``, ``control_id``, ``title``,
                ``family``, ``status``, ``severity``, ``gap_description``,
                ``remediation``, ``related_techniques``, ``deadline_days``,
                ``risk_register_entry``.
        """
        gaps: List[Dict[str, Any]] = []
        for framework, controls in framework_mapping.items():
            for control_id, entry in controls.items():
                status = entry["status"]
                if status in ("compliant", "not_assessed"):
                    continue
                severity = self._severity_for(
                    status, entry["missed_techniques"], framework
                )
                gap_id = f"CG-{framework}-{control_id}".replace(" ", "_")
                remediation = self._remediation_for(framework, control_id, status)
                gap = {
                    "gap_id": gap_id,
                    "framework": framework,
                    "control_id": control_id,
                    "title": entry["title"],
                    "family": entry["family"],
                    "status": status,
                    "severity": severity,
                    "gap_description": self._describe_gap(entry, framework, control_id),
                    "remediation": remediation,
                    "related_techniques": entry["related_techniques"],
                    "missed_techniques": entry["missed_techniques"],
                    "deadline_days": entry.get("deadline_days"),
                    "evidence": entry.get("evidence", []),
                    "risk_register_entry": None,
                }
                # Feed into the organizational risk register if configured.
                if self.risk_register is not None:
                    try:
                        risk_id = self.risk_register.add_risk({
                            "source": "orange_team",
                            "gap_id": gap_id,
                            "framework": framework,
                            "control_id": control_id,
                            "severity": severity,
                            "description": gap["gap_description"],
                            "remediation": remediation,
                        })
                        gap["risk_register_entry"] = risk_id
                    except Exception as exc:  # pragma: no cover - defensive
                        logger.warning(
                            "Risk register add_risk failed for %s: %s", gap_id, exc
                        )
                gaps.append(gap)

        gaps.sort(
            key=lambda g: (
                -_SEVERITY_RANK.get(g["severity"], 0),
                g["framework"],
                g["control_id"],
            )
        )
        logger.info(
            "Compliance gap analysis complete: gaps=%d (critical=%d, high=%d)",
            len(gaps),
            sum(1 for g in gaps if g["severity"] == "critical"),
            sum(1 for g in gaps if g["severity"] == "high"),
        )
        return gaps

    # ------------------------------------------------------------------
    # 3. Compliance reporting
    # ------------------------------------------------------------------

    async def generate_compliance_report(
        self,
        exercise_id: str,
        framework_mapping: Dict[str, Dict[str, Dict[str, Any]]],
        compliance_gaps: List[Dict[str, Any]],
        tenant_id: str = "default",
    ) -> Dict[str, Any]:
        """Generate a structured compliance report suitable for auditors.

        Args:
            exercise_id: ID of the exercise the report covers.
            framework_mapping: Output of :meth:`map_to_frameworks`.
            compliance_gaps: Output of :meth:`analyze_compliance_gaps`.
            tenant_id: Tenant scope.

        Returns:
            A compliance report dict with:
                ``report_id``, ``exercise_id``, ``tenant_id``,
                ``generated_at``, ``executive_summary``, ``framework_summary``,
                ``compliance_gaps``, ``remediation_priorities``,
                ``regulatory_impact``, ``overall_posture``.
        """
        report_id = str(uuid4())
        generated_at = datetime.now(timezone.utc).isoformat()

        framework_summary = self._framework_summary(framework_mapping)
        remediation_priorities = self.get_remediation_priorities(compliance_gaps)
        regulatory_impact = self.assess_regulatory_impact(compliance_gaps)
        overall_posture = self._overall_posture(framework_summary)
        executive_summary = await self._executive_summary(
            framework_summary, compliance_gaps, overall_posture
        )

        report = {
            "report_id": report_id,
            "exercise_id": exercise_id,
            "tenant_id": tenant_id,
            "generated_at": generated_at,
            "executive_summary": executive_summary,
            "framework_summary": framework_summary,
            "compliance_gaps": compliance_gaps,
            "remediation_priorities": remediation_priorities,
            "regulatory_impact": regulatory_impact,
            "overall_posture": overall_posture,
        }

        logger.info(
            "Compliance report generated: exercise=%s, posture=%s, gaps=%d",
            exercise_id,
            overall_posture,
            len(compliance_gaps),
        )
        return report

    # ------------------------------------------------------------------
    # 4. Remediation prioritization
    # ------------------------------------------------------------------

    def get_remediation_priorities(
        self, compliance_gaps: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Prioritize remediation of compliance gaps.

        Prioritization considers (in order):
            1. Regulatory deadline urgency (shorter deadline = higher priority).
            2. Gap severity (critical > high > medium > low).
            3. Business impact (derived from framework fine exposure).

        Args:
            compliance_gaps: Output of :meth:`analyze_compliance_gaps`.

        Returns:
            A list of prioritized remediation items, each containing:
                ``priority``, ``gap_id``, ``framework``, ``control_id``,
                ``severity``, ``deadline_days``, ``recommended_completion_by``,
                ``remediation``, ``business_impact``.
        """
        def sort_key(gap: Dict[str, Any]) -> Tuple[int, int, int]:
            deadline = gap.get("deadline_days")
            # Treat missing deadlines as the least urgent (large number).
            deadline_val = deadline if isinstance(deadline, int) else 9999
            severity_rank = _SEVERITY_RANK.get(gap["severity"], 0)
            fine = _FRAMEWORK_MAX_FINE_USD.get(gap["framework"], 0)
            return (deadline_val, -severity_rank, -fine)

        ordered = sorted(compliance_gaps, key=sort_key)
        priorities: List[Dict[str, Any]] = []
        for idx, gap in enumerate(ordered, start=1):
            deadline = gap.get("deadline_days")
            business_impact = self._business_impact_for(gap)
            priorities.append({
                "priority": idx,
                "gap_id": gap["gap_id"],
                "framework": gap["framework"],
                "control_id": gap["control_id"],
                "severity": gap["severity"],
                "deadline_days": deadline,
                "recommended_completion_by": self._deadline_iso(deadline),
                "remediation": gap["remediation"],
                "business_impact": business_impact,
            })
        return priorities

    # ------------------------------------------------------------------
    # 5. Regulatory impact assessment
    # ------------------------------------------------------------------

    def assess_regulatory_impact(
        self, compliance_gaps: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Assess the regulatory and financial impact of compliance gaps.

        Args:
            compliance_gaps: Output of :meth:`analyze_compliance_gaps`.

        Returns:
            An impact dict containing:
                ``total_gaps``, ``by_framework``, ``by_severity``,
                ``estimated_max_fine_usd``, ``mandatory_notification_required``,
                ``notification_deadline_hours``, ``frameworks_at_risk``,
                ``recommendations``.
        """
        by_framework: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        estimated_max_fine = 0
        frameworks_at_risk: List[str] = []
        mandatory_notification = False
        notification_deadline_hours: Optional[int] = None

        for gap in compliance_gaps:
            fwk = gap["framework"]
            by_framework[fwk] = by_framework.get(fwk, 0) + 1
            sev = gap["severity"]
            by_severity[sev] = by_severity.get(sev, 0) + 1

            fine = _FRAMEWORK_MAX_FINE_USD.get(fwk, 0)
            if fine > 0 and fwk not in frameworks_at_risk:
                frameworks_at_risk.append(fwk)
            # Severity scales the indicative fine exposure.
            sev_mult = {
                "critical": 1.0,
                "high": 0.6,
                "medium": 0.3,
                "low": 0.1,
            }.get(sev, 0.1)
            estimated_max_fine += int(fine * sev_mult)

            # GDPR Article 33 breach notification — 72 hours.
            if fwk == "GDPR" and gap["control_id"] == "Article 33":
                mandatory_notification = True
                notification_deadline_hours = 72
            # PCI-DSS critical gaps may require acquirer notification.
            if fwk == "PCI-DSS" and sev == "critical":
                mandatory_notification = True
                notification_deadline_hours = min(
                    notification_deadline_hours or 24, 24
                )

        recommendations: List[str] = []
        if mandatory_notification:
            recommendations.append(
                f"Initiate regulator/breach notification within "
                f"{notification_deadline_hours} hours — mandatory deadline triggered."
            )
        if "GDPR" in frameworks_at_risk:
            recommendations.append(
                "Engage the Data Protection Officer (DPO) and prepare a DPIA update."
            )
        if "PCI-DSS" in frameworks_at_risk:
            recommendations.append(
                "Notify the acquiring bank and prepare a PCI remediation plan."
            )
        if "SOX" in frameworks_at_risk:
            recommendations.append(
                "Escalate SOX ITGC deficiencies to internal audit and the audit committee."
            )
        if not recommendations:
            recommendations.append(
                "No mandatory notifications triggered; remediate gaps within deadlines."
            )

        return {
            "total_gaps": len(compliance_gaps),
            "by_framework": by_framework,
            "by_severity": by_severity,
            "estimated_max_fine_usd": estimated_max_fine,
            "mandatory_notification_required": mandatory_notification,
            "notification_deadline_hours": notification_deadline_hours,
            "frameworks_at_risk": frameworks_at_risk,
            "recommendations": recommendations,
        }

    # ------------------------------------------------------------------
    # 6. Event bus integration
    # ------------------------------------------------------------------

    def subscribe_to_event_bus(
        self,
        bus: EventBus,
        tenant_id: str,
        exercise_id: Optional[str] = None,
    ) -> None:
        """Subscribe to PURPLE_TEAM_AAR events to auto-generate compliance analysis.

        When an AAR event is received for the matching tenant, the engine:
            1. Reconstructs red/blue stage data from the AAR payload (if
               embedded) or uses cached stage data.
            2. Runs framework mapping and gap analysis.
            3. Generates a compliance report.
            4. Publishes ``ORANGE_TEAM_REGULATORY_MAPPING`` and one
               ``ORANGE_TEAM_COMPLIANCE_GAP`` event per identified gap.

        Args:
            bus: The shared :class:`EventBus`.
            tenant_id: Tenant scope to filter on.
            exercise_id: Optional exercise identifier to further filter.
        """
        if not isinstance(bus, EventBus):
            raise TypeError("bus must be an EventBus instance")

        async def _handler(event: BusEvent) -> None:
            if event.tenant_id != tenant_id:
                return
            if event.event_type != EventType.PURPLE_TEAM_AAR:
                return
            evt_exercise_id = event.exercise_id or exercise_id
            if exercise_id and evt_exercise_id != exercise_id:
                return

            payload = event.payload or {}
            aar = payload.get("aar") or payload
            red_stages = payload.get("red_team_stages") or []
            blue_alerts = payload.get("blue_team_alerts") or []

            # Fall back to cached stage data if the AAR event didn't embed it.
            cache = self._exercise_cache.get(evt_exercise_id or "", {})
            if not red_stages:
                red_stages = cache.get("red_team_stages", [])
            if not blue_alerts:
                blue_alerts = cache.get("blue_team_alerts", [])

            try:
                framework_mapping = self.map_to_frameworks(
                    red_stages, blue_alerts, aar
                )
                compliance_gaps = self.analyze_compliance_gaps(framework_mapping)
                report = await self.generate_compliance_report(
                    exercise_id=evt_exercise_id or "unknown",
                    framework_mapping=framework_mapping,
                    compliance_gaps=compliance_gaps,
                    tenant_id=tenant_id,
                )

                # Publish the regulatory mapping event.
                mapping_event = BusEvent(
                    event_type=EventType.ORANGE_TEAM_REGULATORY_MAPPING,
                    tenant_id=tenant_id,
                    exercise_id=evt_exercise_id,
                    simulation_id=event.simulation_id,
                    payload={
                        "report_id": report["report_id"],
                        "framework_summary": report["framework_summary"],
                        "overall_posture": report["overall_posture"],
                    },
                )
                await bus.publish(mapping_event)

                # Publish one compliance gap event per gap.
                for gap in compliance_gaps:
                    await bus.publish(
                        OrangeTeamComplianceGapEvent(
                            tenant_id=tenant_id,
                            exercise_id=evt_exercise_id,
                            gap_id=gap["gap_id"],
                            framework=gap["framework"],
                            control_id=gap["control_id"],
                            gap_description=gap["gap_description"],
                            severity=gap["severity"],
                            remediation=gap["remediation"],
                            related_technique_id=(
                                gap["related_techniques"][0]
                                if gap["related_techniques"]
                                else None
                            ),
                        )
                    )

                logger.info(
                    "Orange team auto-analysis complete for exercise %s: "
                    "gaps=%d, posture=%s",
                    evt_exercise_id,
                    len(compliance_gaps),
                    report["overall_posture"],
                )
            except Exception as exc:  # pragma: no cover - defensive
                logger.exception(
                    "Orange team event handler failed for exercise %s: %s",
                    evt_exercise_id,
                    exc,
                )

        bus.subscribe(EventType.PURPLE_TEAM_AAR, _handler)
        logger.info(
            "Orange team subscribed to PURPLE_TEAM_AAR for tenant %s exercise %s",
            tenant_id,
            exercise_id,
        )

    def cache_exercise_data(
        self,
        exercise_id: str,
        red_team_stages: List[Dict[str, Any]],
        blue_team_alerts: List[Dict[str, Any]],
    ) -> None:
        """Cache red/blue stage data for an exercise.

        Useful when the PURPLE_TEAM_AAR event does not embed the raw stage
        data; the event handler falls back to this cache.

        Args:
            exercise_id: Exercise identifier.
            red_team_stages: Red Team attack stage event dicts.
            blue_team_alerts: Blue Team alert event dicts.
        """
        self._exercise_cache[exercise_id] = {
            "red_team_stages": red_team_stages,
            "blue_team_alerts": blue_team_alerts,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _collect_techniques(
        red_stages: List[Dict[str, Any]],
        blue_alerts: List[Dict[str, Any]],
    ) -> Tuple[set, set]:
        """Return (attacked_techniques, detected_techniques) sets."""
        attacked: set = set()
        for stage in red_stages:
            payload = stage.get("payload", stage)
            tech_id = payload.get("technique_id")
            if tech_id:
                attacked.add(tech_id)
        detected: set = set()
        for alert in blue_alerts:
            payload = alert.get("payload", alert)
            if payload.get("detected", False):
                tech_id = payload.get("technique_id")
                if tech_id:
                    detected.add(tech_id)
        return attacked, detected

    @staticmethod
    def _severity_for(
        status: str, missed_techniques: List[str], framework: str
    ) -> str:
        """Determine gap severity from status, missed techniques, and framework."""
        if status == "non_compliant":
            # Frameworks with direct regulatory fines escalate to critical.
            if framework in ("GDPR", "SOX", "PCI-DSS"):
                return "critical"
            return "high"
        # partially_compliant
        if len(missed_techniques) >= 2:
            return "high"
        if framework in ("GDPR", "SOX", "PCI-DSS"):
            return "medium"
        return "low"

    @staticmethod
    def _describe_gap(
        entry: Dict[str, Any], framework: str, control_id: str
    ) -> str:
        missed = entry.get("missed_techniques", [])
        status = entry.get("status", "non_compliant")
        if status == "non_compliant":
            return (
                f"{framework} {control_id} ({entry['title']}) is non-compliant: "
                f"no detection coverage for techniques {', '.join(missed) or 'N/A'}."
            )
        return (
            f"{framework} {control_id} ({entry['title']}) is partially compliant: "
            f"detection gaps for techniques {', '.join(missed) or 'N/A'}."
        )

    @staticmethod
    def _remediation_for(framework: str, control_id: str, status: str) -> str:
        """Rule-based remediation recommendation for a control gap."""
        base = {
            ("PCI-DSS", "Req 6"): "Patch vulnerable systems; enforce secure SDLC and change management.",
            ("PCI-DSS", "Req 8"): "Enforce MFA on all in-scope accounts; review access control lists.",
            ("PCI-DSS", "Req 10"): "Deploy centralized logging and SIEM correlation for cardholder data access.",
            ("PCI-DSS", "Req 11"): "Schedule recurring vulnerability scans and penetration tests.",
            ("PCI-DSS", "Req 12"): "Update the information security policy and deliver security awareness training.",
            ("SOX", "ITGC-Access"): "Review privileged access recertification; enforce segregation of duties.",
            ("SOX", "ITGC-Change"): "Tighten change-management approvals and audit trails for financial systems.",
            ("SOX", "ITGC-Ops"): "Strengthen operational monitoring and exception handling for financial apps.",
            ("SOX", "Section 302"): "Escalate control deficiencies to certifying officers; document remediation.",
            ("SOX", "Section 404"): "Document and test ICFR controls; remediate design/operating deficiencies.",
            ("GDPR", "Article 32"): "Implement encryption, pseudonymization, and continuous security monitoring.",
            ("GDPR", "Article 33"): "Establish a 72-hour breach notification runbook; notify the supervisory authority.",
            ("GDPR", "Article 35"): "Conduct or update the Data Protection Impact Assessment.",
            ("GDPR", "Article 5"): "Review data processing records and lawfulness basis for personal data.",
            ("NIST CSF", "PR.AC"): "Implement least-privilege access control and MFA across the estate.",
            ("NIST CSF", "PR.AT"): "Deliver role-based security awareness training and phishing simulations.",
            ("NIST CSF", "PR.DS"): "Protect data at rest and in transit; verify backup integrity.",
            ("NIST CSF", "DE.CM"): "Deploy continuous monitoring across endpoints, network, and identity.",
            ("NIST CSF", "DE.AE"): "Tune anomaly detection and baseline alerting in the SIEM.",
            ("NIST CSF", "RS.RP"): "Update the incident response plan and exercise it tabletop-style.",
            ("NIST CSF", "RS.AN"): "Improve incident analysis playbooks and forensic readiness.",
            ("NIST CSF", "RC.RP"): "Validate recovery procedures and RTO/RPO targets.",
            ("NIST CSF", "ID.AM"): "Refresh the asset inventory and data flow mappings.",
            ("NIST CSF", "ID.RA"): "Update the risk register with the identified compliance gaps.",
            ("ISO 27001", "A.5"): "Review and re-approve the information security policy.",
            ("ISO 27001", "A.6"): "Clarify information security roles and responsibilities.",
            ("ISO 27001", "A.8"): "Update the asset register and ownership assignments.",
            ("ISO 27001", "A.9"): "Strengthen the access control policy and enforce MFA.",
            ("ISO 27001", "A.9.2"): "Review user access management and joiner/mover/leaver processes.",
            ("ISO 27001", "A.9.2.3"): "Deliver user awareness training on credential handling.",
            ("ISO 27001", "A.9.2.4"): "Rotate and protect secret authentication information (credential guard).",
            ("ISO 27001", "A.12.4"): "Expand logging and event monitoring coverage.",
            ("ISO 27001", "A.12.6"): "Patch management and vulnerability remediation program.",
            ("ISO 27001", "A.16"): "Update the incident management process and post-incident review.",
            ("ISO 27001", "A.18"): "Verify compliance with legal/statutory/regulatory requirements.",
        }.get((framework, control_id))
        if base:
            return base
        return (
            f"Remediate {framework} {control_id} control deficiency; "
            f"implement detection and preventive controls and document evidence."
        )

    @staticmethod
    def _framework_summary(
        framework_mapping: Dict[str, Dict[str, Dict[str, Any]]]
    ) -> Dict[str, Any]:
        """Aggregate per-framework status counts."""
        summary: Dict[str, Any] = {}
        for framework, controls in framework_mapping.items():
            counts = {"compliant": 0, "partially_compliant": 0,
                      "non_compliant": 0, "not_assessed": 0}
            for entry in controls.values():
                counts[entry["status"]] = counts.get(entry["status"], 0) + 1
            assessed = sum(v for k, v in counts.items() if k != "not_assessed")
            compliant = counts["compliant"]
            posture = (
                "compliant" if assessed and compliant == assessed
                else "at_risk" if counts["non_compliant"] > 0
                else "partial" if counts["partially_compliant"] > 0
                else "unassessed"
            )
            summary[framework] = {
                "control_counts": counts,
                "assessed_controls": assessed,
                "posture": posture,
            }
        return summary

    @staticmethod
    def _overall_posture(framework_summary: Dict[str, Any]) -> str:
        """Roll up framework postures into a single overall posture label."""
        postures = [fs["posture"] for fs in framework_summary.values()]
        if not postures:
            return "unassessed"
        if all(p == "compliant" for p in postures):
            return "compliant"
        if any(p == "at_risk" for p in postures):
            return "at_risk"
        if any(p == "partial" for p in postures):
            return "partial"
        return "unassessed"

    @staticmethod
    def _business_impact_for(gap: Dict[str, Any]) -> str:
        fine = _FRAMEWORK_MAX_FINE_USD.get(gap["framework"], 0)
        sev = gap["severity"]
        if fine >= 1_000_000 and sev in ("critical", "high"):
            return "critical"
        if fine >= 1_000_000:
            return "high"
        if fine > 0:
            return "medium"
        # No direct fines (NIST CSF, ISO 27001) — contractual/reputational.
        return "medium" if sev in ("critical", "high") else "low"

    @staticmethod
    def _deadline_iso(deadline_days: Optional[int]) -> Optional[str]:
        if not isinstance(deadline_days, int):
            return None
        from datetime import timedelta
        due = datetime.now(timezone.utc) + timedelta(days=deadline_days)
        return due.isoformat()

    async def _executive_summary(
        self,
        framework_summary: Dict[str, Any],
        compliance_gaps: List[Dict[str, Any]],
        overall_posture: str,
    ) -> str:
        """Generate an executive summary, optionally LLM-enhanced."""
        total_gaps = len(compliance_gaps)
        critical = sum(1 for g in compliance_gaps if g["severity"] == "critical")
        high = sum(1 for g in compliance_gaps if g["severity"] == "high")
        frameworks_at_risk = [
            fwk for fwk, fs in framework_summary.items()
            if fs["posture"] == "at_risk"
        ]

        if self.llm_provider is not None:
            try:
                prompt = (
                    "You are an Orange Team compliance analyst. Produce a concise "
                    "(3-5 sentence) executive summary of a color-team exercise's "
                    f"compliance posture. Overall posture: {overall_posture}. "
                    f"Total gaps: {total_gaps} (critical={critical}, high={high}). "
                    f"Frameworks at risk: {', '.join(frameworks_at_risk) or 'none'}."
                )
                result = self.llm_provider.generate(prompt)
                if isinstance(result, str) and result.strip():
                    return result.strip()
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("LLM executive summary failed: %s", exc)

        if total_gaps == 0:
            return (
                "The exercise found no compliance gaps across assessed regulatory "
                f"frameworks. Overall posture is {overall_posture}."
            )
        return (
            f"The exercise identified {total_gaps} compliance gap(s) across "
            f"regulatory frameworks, of which {critical} are critical and "
            f"{high} are high severity. Frameworks at risk: "
            f"{', '.join(frameworks_at_risk) or 'none'}. "
            f"Overall compliance posture is {overall_posture}. "
            "Immediate remediation of critical gaps is recommended to avoid "
            "regulatory exposure and potential fines."
        )
