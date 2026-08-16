"""Vorsyghta Proprietary Threat Intelligence Data Schema.

This module defines the proprietary threat intelligence data models that
form the Vorsyghta Threat Intelligence Stack IP. These models capture
structured intelligence from the Vorsyghta team (analysts, red team,
blue team, threat hunters) and make it available across all color teams
for simulation, detection, and reporting.

Schema Architecture:

    ThreatActorRecord
      └── CampaignRecord
            ├── MalwareFamilyRecord
            ├── IndicatorRecord (IOCs)
            └── TTPRecord (techniques, tactics, procedures)
      └── ThreatReportRecord (structured analyst reports)

    All entities are:
      - Tenant-scoped (multi-tenant isolation)
      - MITRE ATT&CK mapped (technique_id, tactic)
      - Confidence-scored (analyst confidence level)
      - Lifecycle-tracked (active, retired, deprecated)
      - Cross-team shared (red, blue, purple, white, black)

Owner: Vorsyghta Core Team
"""
from __future__ import annotations

from uuid import uuid4

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import relationship

from vorsyghta.db.base import Base


# ---------------------------------------------------------------------------
# Threat Actor — profiles of adversary groups, APTs, cybercriminal orgs
# ---------------------------------------------------------------------------

class ThreatActorRecord(Base):
    """A threat actor profile — an adversary group or individual.

    This is the top-level entity in the Vorsyghta threat intelligence
    schema. Threat actors are linked to campaigns, malware families,
    indicators, and TTPs.
    """

    __tablename__ = "threat_actors"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    actor_id = Column(String, unique=True, nullable=False, index=True)
    tenant_id = Column(String, nullable=False, index=True)

    # Identity
    name = Column(String, nullable=False)
    aliases = Column(Text, nullable=True)  # JSON list of aliases
    description = Column(Text, nullable=True)
    actor_type = Column(String, nullable=False, default="apt")
    # Types: apt, cybercriminal, hacktivist, insider, nation_state, unknown

    # Targeting
    target_industries = Column(Text, nullable=True)  # JSON list
    target_regions = Column(Text, nullable=True)     # JSON list
    target_countries = Column(Text, nullable=True)   # JSON list

    # Sophistication (1-10 scale)
    sophistication_level = Column(Integer, nullable=True)
    # 1=script kiddie, 5=organized, 10=nation-state

    # Motivation
    primary_motivation = Column(String, nullable=True)
    # financial, espionage, sabotage, ideological, personal, unknown
    secondary_motivations = Column(Text, nullable=True)  # JSON list

    # Lifecycle
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)

    # Intelligence metadata
    confidence_level = Column(String, nullable=False, default="medium")
    # very_high, high, medium, low, very_low
    sources = Column(Text, nullable=True)  # JSON list of source names
    collected_by = Column(String, nullable=True)  # analyst user_id
    collection_method = Column(String, nullable=True)
    # manual, osint, threat_feed, incident_response, simulation

    # Cross-team sharing
    shared_with_teams = Column(Text, nullable=True)  # JSON list: red, blue, purple, etc.

    # Timestamps
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    # Relationships
    campaigns = relationship(
        "CampaignRecord", back_populates="actor",
        cascade="all, delete-orphan", lazy="select",
    )
    reports = relationship(
        "ThreatReportRecord", back_populates="actor",
        cascade="all, delete-orphan", lazy="select",
    )

    def __repr__(self) -> str:
        return f"<ThreatActorRecord actor_id={self.actor_id!r} name={self.name!r}>"


# ---------------------------------------------------------------------------
# Campaign — coordinated attack campaigns by threat actors
# ---------------------------------------------------------------------------

class CampaignRecord(Base):
    """A coordinated attack campaign attributed to a threat actor."""

    __tablename__ = "threat_campaigns"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    campaign_id = Column(String, unique=True, nullable=False, index=True)
    tenant_id = Column(String, nullable=False, index=True)

    # Attribution
    actor_id = Column(
        String,
        ForeignKey("threat_actors.actor_id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    # Identity
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    campaign_status = Column(String, nullable=False, default="active")
    # active, dormant, completed, disrupted

    # Timeline
    start_date = Column(DateTime, nullable=True)
    end_date = Column(DateTime, nullable=True)
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)

    # Targeting
    target_organizations = Column(Text, nullable=True)  # JSON list
    target_sectors = Column(Text, nullable=True)        # JSON list
    target_geography = Column(Text, nullable=True)      # JSON list

    # MITRE ATT&CK
    mitre_techniques = Column(Text, nullable=True)  # JSON list of T-IDs
    mitre_tactics = Column(Text, nullable=True)     # JSON list of tactics

    # Impact
    impact_assessment = Column(Text, nullable=True)
    estimated_impact_usd = Column(Float, nullable=True)
    victims_count = Column(Integer, nullable=True)

    # Intelligence metadata
    confidence_level = Column(String, nullable=False, default="medium")
    sources = Column(Text, nullable=True)
    collected_by = Column(String, nullable=True)

    # Cross-team sharing
    shared_with_teams = Column(Text, nullable=True)

    # Timestamps
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    # Relationships
    actor = relationship("ThreatActorRecord", back_populates="campaigns", lazy="select")
    malware_families = relationship(
        "MalwareFamilyRecord", back_populates="campaign",
        cascade="all, delete-orphan", lazy="select",
    )
    indicators = relationship(
        "IndicatorRecord", back_populates="campaign",
        cascade="all, delete-orphan", lazy="select",
    )
    ttps = relationship(
        "TTPRecord", back_populates="campaign",
        cascade="all, delete-orphan", lazy="select",
    )

    def __repr__(self) -> str:
        return f"<CampaignRecord campaign_id={self.campaign_id!r} name={self.name!r}>"


# ---------------------------------------------------------------------------
# Malware Family — malware tools and families used by threat actors
# ---------------------------------------------------------------------------

class MalwareFamilyRecord(Base):
    """A malware family or tool used in a campaign."""

    __tablename__ = "malware_families"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    malware_id = Column(String, unique=True, nullable=False, index=True)
    tenant_id = Column(String, nullable=False, index=True)

    # Attribution
    campaign_id = Column(
        String,
        ForeignKey("threat_campaigns.campaign_id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    # Identity
    name = Column(String, nullable=False)
    aliases = Column(Text, nullable=True)  # JSON list
    family_type = Column(String, nullable=False, default="malware")
    # malware, ransomware, trojan, backdoor, rootkit, worm, adware, spyware,
    # botnet, loader, stealer, wiper, downloader, dropper

    description = Column(Text, nullable=True)

    # Technical
    platforms = Column(Text, nullable=True)  # JSON list: Windows, Linux, macOS, Android
    file_extensions = Column(Text, nullable=True)  # JSON list
    file_hashes = Column(Text, nullable=True)  # JSON list of known hashes
    c2_infrastructure = Column(Text, nullable=True)  # JSON list of C2 IPs/domains

    # MITRE ATT&CK
    mitre_techniques = Column(Text, nullable=True)  # JSON list

    # Detection
    yara_rules = Column(Text, nullable=True)  # YARA rule signatures
    detection_signatures = Column(Text, nullable=True)  # JSON list

    # Intelligence metadata
    confidence_level = Column(String, nullable=False, default="medium")
    sources = Column(Text, nullable=True)
    collected_by = Column(String, nullable=True)

    # Cross-team sharing
    shared_with_teams = Column(Text, nullable=True)

    # Timestamps
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    # Relationships
    campaign = relationship("CampaignRecord", back_populates="malware_families", lazy="select")

    def __repr__(self) -> str:
        return f"<MalwareFamilyRecord malware_id={self.malware_id!r} name={self.name!r}>"


# ---------------------------------------------------------------------------
# Indicator (IOC) — indicators of compromise with lifecycle management
# ---------------------------------------------------------------------------

class IndicatorRecord(Base):
    """An Indicator of Compromise (IOC) with full lifecycle management.

    IOC types: ip, domain, url, email, file_hash_md5, file_hash_sha1,
    file_hash_sha256, file_path, registry_key, mutex, certificate,
    user_agent, ja3_hash, ja3s_hash, autonomous_system.
    """

    __tablename__ = "threat_indicators"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    indicator_id = Column(String, unique=True, nullable=False, index=True)
    tenant_id = Column(String, nullable=False, index=True)

    # Attribution
    campaign_id = Column(
        String,
        ForeignKey("threat_campaigns.campaign_id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    # Identity
    indicator_type = Column(String, nullable=False, index=True)
    # ip, domain, url, email, file_hash_md5, file_hash_sha1, file_hash_sha256,
    # file_path, registry_key, mutex, certificate, user_agent, ja3_hash,
    # ja3s_hash, autonomous_system
    indicator_value = Column(Text, nullable=False)
    indicator_hash = Column(String, nullable=True, index=True)
    # Normalized hash for deduplication (SHA-256 of type:value)

    # Context
    description = Column(Text, nullable=True)
    context = Column(Text, nullable=True)  # JSON: where/when/how found

    # Lifecycle
    indicator_state = Column(String, nullable=False, default="active")
    # active, retired, expired, false_positive, deprecated
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)  # IOC expiration

    # Scoring
    confidence_level = Column(String, nullable=False, default="medium")
    threat_score = Column(Integer, nullable=True)  # 0-100
    # 0-20=low, 21-40=moderate, 41-60=elevated, 61-80=high, 81-100=critical
    false_positive_rate = Column(Float, nullable=True)  # 0.0-1.0

    # MITRE ATT&CK
    mitre_technique = Column(String, nullable=True)

    # Intelligence metadata
    sources = Column(Text, nullable=True)
    collected_by = Column(String, nullable=True)
    collection_method = Column(String, nullable=True)
    # manual, osint, threat_feed, incident_response, simulation, dark_web

    # Cross-team sharing
    shared_with_teams = Column(Text, nullable=True)

    # Timestamps
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    # Relationships
    campaign = relationship("CampaignRecord", back_populates="indicators", lazy="select")

    def __repr__(self) -> str:
        return f"<IndicatorRecord indicator_id={self.indicator_id!r} type={self.indicator_type!r}>"


# ---------------------------------------------------------------------------
# TTP — Techniques, Tactics, and Procedures
# ---------------------------------------------------------------------------

class TTPRecord(Base):
    """A Technique, Tactic, and Procedure (TTP) observed in a campaign.

    TTPs are the highest-fidelity intelligence — they describe *how* an
    adversary operates, not just *what* they use. TTPs are harder to
    change than IOCs and provide the basis for behavioral detection.
    """

    __tablename__ = "threat_ttps"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    ttp_id = Column(String, unique=True, nullable=False, index=True)
    tenant_id = Column(String, nullable=False, index=True)

    # Attribution
    campaign_id = Column(
        String,
        ForeignKey("threat_campaigns.campaign_id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    # MITRE ATT&CK mapping
    mitre_technique_id = Column(String, nullable=True, index=True)
    mitre_tactic = Column(String, nullable=True)
    mitre_subtechnique_id = Column(String, nullable=True)

    # TTP details
    ttp_name = Column(String, nullable=False)
    ttp_category = Column(String, nullable=False, default="technique")
    # technique, tactic, procedure, playbook, behavior
    description = Column(Text, nullable=True)

    # Observed procedure (how the adversary actually executed it)
    observed_procedure = Column(Text, nullable=True)
    # Detailed narrative of how the TTP was observed in the wild

    # Detection
    detection_recommendations = Column(Text, nullable=True)
    detection_data_sources = Column(Text, nullable=True)  # JSON list
    sigma_rule = Column(Text, nullable=True)  # Sigma detection rule
    splunk_query = Column(Text, nullable=True)  # Splunk SPL query
    elastic_query = Column(Text, nullable=True)  # Elasticsearch KQL
    sentinel_query = Column(Text, nullable=True)  # Kusto KQL for Sentinel

    # Mitigation
    mitigation_recommendations = Column(Text, nullable=True)

    # Simulation
    simulation_applicability = Column(String, nullable=True)
    # Which threat types this TTP is relevant to
    simulation_notes = Column(Text, nullable=True)

    # Intelligence metadata
    confidence_level = Column(String, nullable=False, default="medium")
    sources = Column(Text, nullable=True)
    collected_by = Column(String, nullable=True)

    # Cross-team sharing
    shared_with_teams = Column(Text, nullable=True)

    # Timestamps
    first_observed = Column(DateTime, nullable=True)
    last_observed = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    # Relationships
    campaign = relationship("CampaignRecord", back_populates="ttps", lazy="select")

    def __repr__(self) -> str:
        return f"<TTPRecord ttp_id={self.ttp_id!r} technique={self.mitre_technique_id!r}>"


# ---------------------------------------------------------------------------
# Threat Report — structured analyst reports
# ---------------------------------------------------------------------------

class ThreatReportRecord(Base):
    """A structured threat intelligence report authored by Vorsyghta analysts.

    Reports aggregate findings about a threat actor, campaign, or
    emerging threat. They are the primary deliverable from the threat
    intelligence team to other color teams.
    """

    __tablename__ = "threat_reports"

    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    report_id = Column(String, unique=True, nullable=False, index=True)
    tenant_id = Column(String, nullable=False, index=True)

    # Attribution
    actor_id = Column(
        String,
        ForeignKey("threat_actors.actor_id", ondelete="SET NULL"),
        nullable=True, index=True,
    )

    # Identity
    title = Column(String, nullable=False)
    report_type = Column(String, nullable=False, default="threat_assessment")
    # threat_assessment, campaign_analysis, actor_profile, vulnerability_advisory,
    # incident_lessons, trending_threats, sector_report
    summary = Column(Text, nullable=True)
    body = Column(Text, nullable=True)  # Full report content (markdown)

    # Classification
    classification = Column(String, nullable=False, default="TLP:AMBER")
    # TLP:RED, TLP:AMBER, TLP:GREEN, TLP:CLEAR
    severity = Column(String, nullable=False, default="medium")
    # critical, high, medium, low, info

    # Scope
    affected_industries = Column(Text, nullable=True)  # JSON list
    affected_regions = Column(Text, nullable=True)     # JSON list
    mitre_techniques = Column(Text, nullable=True)     # JSON list

    # Recommendations
    recommendations = Column(Text, nullable=True)  # JSON list of recommendations
    remediation_steps = Column(Text, nullable=True)  # JSON list

    # Intelligence metadata
    confidence_level = Column(String, nullable=False, default="medium")
    sources = Column(Text, nullable=True)
    authored_by = Column(String, nullable=True)  # analyst user_id
    reviewed_by = Column(String, nullable=True)   # reviewer user_id

    # Lifecycle
    report_status = Column(String, nullable=False, default="draft")
    # draft, in_review, published, archived, deprecated

    # Cross-team sharing
    shared_with_teams = Column(Text, nullable=True)

    # Timestamps
    published_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())

    # Relationships
    actor = relationship("ThreatActorRecord", back_populates="reports", lazy="select")

    def __repr__(self) -> str:
        return f"<ThreatReportRecord report_id={self.report_id!r} title={self.title!r}>"
