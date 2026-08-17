"""Tests for red-team findings persistence + client reporting (P2).

Two layers, per the project testing principle (unit + REAL-USAGE):

Component tests:
  1. FindingClassifier is evidence-based: it emits a structured CWE/CVSS finding
     only when the tool output actually contains the signature, and never for
     benign output.
  2. ReportGenerator.generate_from_attack_result turns structured findings into a
     deliverable VulnerabilityReport (markdown + JSON, severity-sorted).

Real-usage simulation (TestRealUsagePersistenceReporting): drives the actual
AI-driven run against a REAL in-memory SQLite DB, then proves:
  - the previously-dead attack_plans/attack_results/attack_steps rows are written;
  - the run result carries structured CWE/CVSS findings derived from real output;
  - a real client report (markdown) is produced from those findings.
Only the tool-server HTTP boundary is faked.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List

import pytest

from vorsyghta.core.ai_planner import AIAttackPlanner
from vorsyghta.research.finding_classifier import FindingClassifier
from vorsyghta.research.vuln_report import ReportGenerator


# --------------------------------------------------------------------------- #
# 1. FindingClassifier — evidence-based classification
# --------------------------------------------------------------------------- #
class TestFindingClassifier:
    def setup_method(self) -> None:
        self.c = FindingClassifier()

    def test_sqlmap_injection_is_critical_cwe89(self) -> None:
        out = "sqlmap identified the following injection point\nParameter 'id' is vulnerable"
        findings = self.c.classify("sqlmap", out, "T1190")
        assert findings, "expected a SQLi finding"
        f = findings[0]
        assert f.cwe_id == "CWE-89"
        assert f.severity == "critical"
        assert f.cvss_score == 9.8
        assert f.cvss_vector.startswith("CVSS:3.1/")
        assert f.technique_id == "T1190"

    def test_hydra_credentials_is_cwe307(self) -> None:
        out = "[22][ssh] host: 10.0.100.10 login: admin password: hunter2"
        findings = self.c.classify("hydra", out, "T1110")
        assert findings and findings[0].cwe_id == "CWE-307"
        assert findings[0].severity == "critical"

    def test_nmap_telnet_is_exposed_service_but_ssh_is_info(self) -> None:
        findings = self.c.classify("nmap", "22/tcp open ssh\n23/tcp open telnet", "T1595")
        by_cwe = {f.cwe_id: f for f in findings}
        # Telnet is a cleartext-exposure finding; plain ssh port is info (0.0).
        assert "CWE-319" in by_cwe and by_cwe["CWE-319"].cvss_score == 5.3
        info = [f for f in findings if f.title == "Open network port"]
        assert info and info[0].severity == "info"

    def test_benign_output_yields_no_findings(self) -> None:
        assert self.c.classify("nmap", "Nmap done: 1 host up", "T1595") == []
        assert self.c.classify("sqlmap", "no injectable parameters found", "T1190") == []

    def test_unknown_tool_yields_nothing(self) -> None:
        assert self.c.classify("mytool", "anything", "T1") == []

    def test_dedup_collapses_identical_evidence(self) -> None:
        out = "23/tcp open telnet\n23/tcp open telnet"
        findings = self.c.classify("nmap", out, "T1595")
        telnet = [f for f in findings if f.cwe_id == "CWE-319"]
        assert len(telnet) == 1

    def test_classify_many_dedups_across_observations(self) -> None:
        obs = [
            ("nmap", "23/tcp open telnet", "T1595"),
            ("nmap", "23/tcp open telnet", "T1046"),  # same evidence, later step
        ]
        findings = self.c.classify_many(obs)
        assert len([f for f in findings if f.cwe_id == "CWE-319"]) == 1


# --------------------------------------------------------------------------- #
# 2. ReportGenerator.generate_from_attack_result
# --------------------------------------------------------------------------- #
class TestReportBridge:
    def _findings(self) -> List[dict]:
        return [
            {"title": "SQL Injection", "cwe_id": "CWE-89", "cvss_score": 9.8,
             "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
             "severity": "critical", "description": "SQLi confirmed",
             "evidence": "is vulnerable", "remediation": "parameterise",
             "tool": "sqlmap", "technique_id": "T1190", "references": []},
            {"title": "Server version disclosure", "cwe_id": "CWE-200",
             "cvss_score": 3.7, "cvss_vector": "CVSS:3.1/...", "severity": "low",
             "description": "banner", "evidence": "Server: nginx",
             "remediation": "hide banner", "tool": "nikto",
             "technique_id": "T1190", "references": []},
        ]

    def test_report_is_severity_sorted_and_complete(self) -> None:
        report = ReportGenerator().generate_from_attack_result(
            findings=self._findings(), target="10.0.100.10",
            client="ACME", engagement_id="ENG-1",
            tools_used=["nmap", "sqlmap", "nikto"], ai_driven=True,
        )
        assert report.client == "ACME"
        assert report.engagement_id == "ENG-1"
        assert len(report.findings) == 2
        # Critical sorts before low.
        assert report.findings[0].cwe_id == "CWE-89"
        assert report.findings[1].cwe_id == "CWE-200"
        # AI-driven methodology + real deliverable renders.
        assert "AI-driven autonomous agent" in report.methodology
        md = report.to_markdown()
        assert "SQL Injection" in md and "CWE-89" in md
        assert "Critical | 1" in md
        # JSON round-trips.
        data = json.loads(report.to_json())
        assert data["findings"][0]["cwe_id"] == "CWE-89"

    def test_empty_findings_still_produces_valid_report(self) -> None:
        report = ReportGenerator().generate_from_attack_result(
            findings=[], target="10.0.100.10",
        )
        assert report.findings == []
        assert "10.0.100.10" in report.to_markdown()


# --------------------------------------------------------------------------- #
# Real-usage fixtures + simulation
# --------------------------------------------------------------------------- #
@pytest.fixture
async def sqlite_db():
    from sqlalchemy.ext.asyncio import create_async_engine
    from vorsyghta.db import base as db_base
    from vorsyghta.db.base import Base
    from vorsyghta.db.session import create_session_factory
    import vorsyghta.db.models.tool_tracking  # noqa: F401
    import vorsyghta.db.models.red_team  # noqa: F401 - register attack_* tables

    prev_engine = db_base._engine
    prev_factory = db_base._session_factory
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    db_base._engine = engine
    db_base._session_factory = create_session_factory(engine)
    try:
        yield engine
    finally:
        await engine.dispose()
        db_base._engine = prev_engine
        db_base._session_factory = prev_factory


class _PentestLLM:
    """Plans a web pentest, then adapts on real output (realistic)."""

    async def generate(self, prompt: str) -> str:
        if "Produce an ordered attack plan" in prompt:
            return json.dumps({"name": "Web pentest", "objectives": ["find injection"],
                "steps": [
                    {"technique_id": "T1595", "technique_name": "Scan",
                     "phase": "reconnaissance", "tool": "nmap",
                     "command": "nmap -sV -p 1-1000 10.0.100.10"},
                    {"technique_id": "T1190", "technique_name": "SQLi",
                     "phase": "initial_access", "tool": "sqlmap",
                     "command": "sqlmap -u http://10.0.100.10/?id=1 --batch"},
                ]})
        if "adapting an AUTHORIZED penetration test" in prompt:
            return json.dumps({"continue": True, "findings": [], "discovered": {}})
        return "{}"


class _VulnToolServer:
    """Returns output containing real vulnerability signatures."""

    url = "http://tool-server:9090"

    def __init__(self) -> None:
        self.executed: List[str] = []

    async def health_check(self) -> bool:
        return True

    async def execute_and_track(self, command: str, **kwargs: Any) -> Dict[str, Any]:
        self.executed.append(command)
        if command.startswith("nmap"):
            stdout = "22/tcp open ssh\n23/tcp open telnet"
        elif command.startswith("sqlmap"):
            stdout = ("sqlmap identified the following injection point\n"
                      "Parameter: id (GET) is vulnerable")
        else:
            stdout = ""
        return {"success": True, "stdout": stdout, "returncode": 0,
                "duration_seconds": 0.2}


class _InScope:
    def is_authorized(self, engagement_id: str, target: str):
        return (target == "10.0.100.10", "in scope")


@pytest.mark.usefixtures("sqlite_db")
class TestRealUsagePersistenceReporting:
    async def test_run_persists_results_and_produces_report(self, tmp_path) -> None:
        from vorsyghta.core.attack_orchestrator import AttackOrchestrator

        tool = _VulnToolServer()
        orch = AttackOrchestrator(
            tool_server_client=tool, tenant_id="acme",
            planner=AIAttackPlanner(_PentestLLM()),
            engagement_manager=_InScope(), engagement_id="ENG-1",
            require_authorization=True,
        )

        seq = await orch.create_ai_attack_sequence(
            scenario_name="Web pentest", target="10.0.100.10")
        result = await orch.execute_sequence(seq["sequence_id"], timeout_per_step=5)

        # --- Structured findings derived from REAL tool output ---
        cwes = {f["cwe_id"] for f in result["structured_findings"]}
        assert "CWE-89" in cwes, result["structured_findings"]   # SQLi from sqlmap
        assert "CWE-319" in cwes                                 # telnet from nmap
        assert result["result_id"], "expected a persisted result_id"

        # --- Persistence: the previously-dead red-team tables are now written ---
        from vorsyghta.db.session import get_session
        from vorsyghta.db.models.red_team import (
            AttackPlanRecord, AttackResultRecord, AttackStepRecord,
        )
        from sqlalchemy import select
        async with get_session() as session:
            plans = (await session.execute(select(AttackPlanRecord))).scalars().all()
            results = (await session.execute(select(AttackResultRecord))).scalars().all()
            steps = (await session.execute(select(AttackStepRecord))).scalars().all()
            assert len(plans) == 1 and plans[0].threat_type == "ai_pentest"
            assert len(results) == 1 and results[0].result_id == result["result_id"]
            # The result summary carries the structured findings (client payload).
            summary = json.loads(results[0].summary)
            assert any(f["cwe_id"] == "CWE-89" for f in summary["findings"])
            assert len(steps) == 2  # one AttackStepRecord per executed step

        # --- Reporting: produce a real client report from the run ---
        report = ReportGenerator().generate_from_attack_result(
            findings=result["structured_findings"], target="10.0.100.10",
            client="ACME", engagement_id="ENG-1",
            tools_used=["nmap", "sqlmap"], ai_driven=True,
        )
        report_file = tmp_path / "report.md"
        report.save(str(report_file), format="markdown")
        md = report_file.read_text()
        assert "Penetration Test Report" in md
        assert "SQL Injection" in md and "CWE-89" in md
        # Critical finding is surfaced in the severity summary.
        assert "Critical | 1" in md

    async def test_cli_report_flag_writes_client_report(self, tmp_path, monkeypatch) -> None:
        """Drive the CLI operator flow with --report and assert a report file."""
        from vorsyghta.cli import red_team as rt
        import vorsyghta.core.attack_orchestrator as ao

        tool = _VulnToolServer()
        real_cls = ao.AttackOrchestrator

        def _factory(**kwargs: Any):
            kwargs["tool_server_client"] = tool
            kwargs["engagement_manager"] = _InScope()
            return real_cls(**kwargs)

        monkeypatch.setattr(rt, "_build_planner", lambda: AIAttackPlanner(_PentestLLM()))
        monkeypatch.setattr(ao, "AttackOrchestrator", _factory)

        scenario_file = tmp_path / "s.yaml"
        scenario_file.write_text(json.dumps(
            {"name": "Web pentest", "mitre_techniques": ["T1595", "T1190"]}))
        report_file = tmp_path / "client_report.md"

        await rt._attack_standalone_async(
            scenario_path=str(scenario_file), target="10.0.100.10", output=None,
            tenant="acme", techniques_override=None, timeout=5,
            engagement_id="ENG-1", allow_unauthorized=False, use_ai=True,
            report_path=str(report_file),
        )

        assert report_file.exists()
        md = report_file.read_text()
        assert "CWE-89" in md  # the SQLi finding made it into the client report
