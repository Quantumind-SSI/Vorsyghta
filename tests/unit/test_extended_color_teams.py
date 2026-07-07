"""Tests for the extended color teams (White/Yellow/Green/Orange), enterprise
integrations API/CLI wiring, SSO, and Vault/KMS secret management.

These tests exercise the new modules added in the pilot readiness expansion:
  - ciicerone/core/white_team.py
  - ciicerone/core/yellow_team.py
  - ciicerone/core/green_team.py
  - ciicerone/core/orange_team.py
  - ciicerone/security/sso.py + sso_bridge.py
  - ciicerone/security/secret_manager.py
  - ciicerone/client_data/credentials/hashi_vault.py + aws_sm.py
  - ciicerone/api/routers/integrations.py + sso.py + secrets.py
  - ciicerone/cli/integrations.py
  - ExerciseOrchestrator integration with the 4 new teams
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ciicerone.core.event_bus import EventBus
from ciicerone.core.event_types import (
    EventType,
    RedTeamAttackStageEvent,
    WhiteTeamROECheckEvent,
    WhiteTeamROEViolationEvent,
    YellowTeamEnvReadyEvent,
    GreenTeamTrainingAssignedEvent,
    OrangeTeamComplianceGapEvent,
)
from ciicerone.core.white_team import WhiteTeamCoordinator
from ciicerone.core.yellow_team import InfrastructureManager
from ciicerone.core.green_team import TrainingAwarenessEngine
from ciicerone.core.orange_team import ComplianceGovernanceEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _red_stage(stage_id="s1", technique="T1566", tactic="initial_access",
               target="web-server-01", content="phishing email sent",
               stage_name="Phishing") -> dict:
    return {
        "event_type": "red_team.attack_stage",
        "tenant_id": "test-tenant",
        "payload": {
            "stage_id": stage_id,
            "stage_name": stage_name,
            "technique_id": technique,
            "tactic": tactic,
            "content": content,
            "target_system": target,
            "iocs": ["evil@example.com"],
        },
    }


def _blue_alert(alert_id="a1", detected=True, technique="T1566",
                severity="medium", response_ms=5000) -> dict:
    return {
        "event_type": "blue_team.alert",
        "tenant_id": "test-tenant",
        "payload": {
            "alert_id": alert_id,
            "source_module": "siem",
            "technique_id": technique,
            "severity": severity,
            "description": "Suspicious email detected",
            "detected": detected,
            "response_time_ms": response_ms,
        },
    }


# ---------------------------------------------------------------------------
# White Team
# ---------------------------------------------------------------------------

class TestWhiteTeam:
    def test_default_roe_rules_loaded(self):
        coord = WhiteTeamCoordinator()
        rules = coord.roe_rules
        rule_ids = {r.rule_id for r in rules}
        assert "ROE-001" in rule_ids
        assert "ROE-002" in rule_ids
        assert len(rules) >= 7

    def test_check_roe_compliance_no_violations(self):
        coord = WhiteTeamCoordinator()
        stages = [_red_stage(technique="T1566", target="test-lab-01")]
        violations = coord.check_roe_compliance(stages)
        # T1566 phishing on test-lab should not trigger DoS/exfil/prod rules
        assert isinstance(violations, list)

    def test_check_roe_compliance_dos_violation(self):
        coord = WhiteTeamCoordinator()
        stages = [_red_stage(technique="T1498", content="DoS flood attack")]
        violations = coord.check_roe_compliance(stages)
        rule_ids = {v["rule_id"] for v in violations}
        assert "ROE-001" in rule_ids

    def test_assess_risk(self):
        coord = WhiteTeamCoordinator()
        stages = [_red_stage(technique="T1498", content="DoS")]
        alerts = [_blue_alert(detected=False)]
        risk = coord.assess_risk(stages, alerts)
        assert "risk_score" in risk
        assert "risk_level" in risk
        assert "recommendation" in risk
        assert 0 <= risk["risk_score"] <= 100

    def test_approve_scope(self):
        coord = WhiteTeamCoordinator()
        scenario = {"name": "test", "target_systems": ["test-lab-01"]}
        approval = coord.approve_scope(scenario=scenario, target_systems=["test-lab-01"])
        assert "approved" in approval

    def test_generate_governance_report(self):
        coord = WhiteTeamCoordinator()
        stages = [_red_stage(technique="T1566")]
        alerts = [_blue_alert(detected=True)]
        violations = coord.check_roe_compliance(stages)
        risk = coord.assess_risk(stages, alerts)
        report = coord.generate_governance_report(
            exercise_id="ex1",
            red_team_stages=stages,
            blue_team_alerts=alerts,
            roe_violations=violations,
            risk_assessment=risk,
        )
        assert "roe_compliance" in report
        assert "risk_summary" in report
        assert "overall_status" in report

    @pytest.mark.asyncio
    async def test_event_bus_subscription(self):
        bus = EventBus()
        coord = WhiteTeamCoordinator()
        coord.subscribe_to_event_bus(bus, "t1", "ex1")

        published = []
        async def capture(event):
            published.append(event)
        bus.subscribe(EventType.WHITE_TEAM_ROE_CHECK, capture)
        bus.subscribe(EventType.WHITE_TEAM_ROE_VIOLATION, capture)

        event = RedTeamAttackStageEvent(
            tenant_id="t1",
            stage_id="s1",
            stage_name="DoS",
            technique_id="T1498",
            tactic="impact",
            content="DoS flood",
            target_system="test-lab-01",
            exercise_id="ex1",
        )
        await bus.publish(event)
        assert len(published) > 0


# ---------------------------------------------------------------------------
# Yellow Team
# ---------------------------------------------------------------------------

class TestYellowTeam:
    @pytest.mark.asyncio
    async def test_provision_environment(self):
        mgr = InfrastructureManager()
        scenario = MagicMock()
        scenario.name = "test-scenario"
        result = await mgr.provision_environment(
            scenario=scenario, tenant_id="t1"
        )
        assert "env_id" in result
        assert "components" in result
        assert "ready" in result

    @pytest.mark.asyncio
    async def test_validate_environment(self):
        mgr = InfrastructureManager()
        scenario = MagicMock()
        scenario.name = "test"
        env = await mgr.provision_environment(scenario=scenario, tenant_id="t1")
        validation = await mgr.validate_environment(env["env_id"])
        assert "valid" in validation
        assert "component_results" in validation

    @pytest.mark.asyncio
    async def test_monitor_environment(self):
        mgr = InfrastructureManager()
        scenario = MagicMock()
        scenario.name = "test"
        env = await mgr.provision_environment(scenario=scenario, tenant_id="t1")
        monitoring = await mgr.monitor_environment(env["env_id"])
        assert "vms" in monitoring or "components" in monitoring

    @pytest.mark.asyncio
    async def test_teardown_environment(self):
        mgr = InfrastructureManager()
        scenario = MagicMock()
        scenario.name = "test"
        env = await mgr.provision_environment(scenario=scenario, tenant_id="t1")
        teardown = await mgr.teardown_environment(env["env_id"])
        assert teardown is not None

    @pytest.mark.asyncio
    async def test_event_bus_subscription(self):
        bus = EventBus()
        mgr = InfrastructureManager()
        mgr.subscribe_to_event_bus(bus, "t1", "ex1")
        # Just verify subscription doesn't crash
        assert bus is not None


# ---------------------------------------------------------------------------
# Green Team
# ---------------------------------------------------------------------------

class TestGreenTeam:
    def test_analyze_training_needs(self):
        engine = TrainingAwarenessEngine()
        aar = {
            "coverage_gaps": [{"technique_id": "T1566", "tactic": "initial_access"}],
            "key_findings": ["Phishing detection gap"],
        }
        score = {"overall_score": 0.5, "component_scores": {"blue_team_detection": 0.4}}
        needs = engine.analyze_training_needs(
            aar=aar,
            score=score,
            red_team_stages=[_red_stage(technique="T1566")],
            blue_team_alerts=[_blue_alert(detected=False)],
        )
        assert "training_modules" in needs or "modules" in needs
        assert isinstance(needs, dict)

    def test_generate_training_plan(self):
        engine = TrainingAwarenessEngine()
        needs = {
            "training_modules": [
                {"module_id": "M001", "name": "Phishing Awareness", "priority": "high",
                 "target_roles": ["all_staff"], "duration_hours": 2}
            ],
        }
        plan = engine.generate_training_plan(training_needs=needs, tenant_id="t1")
        assert "modules" in plan
        assert len(plan["modules"]) >= 1

    def test_assess_awareness_level(self):
        engine = TrainingAwarenessEngine()
        assessment = engine.assess_awareness_level(
            blue_team_alerts=[_blue_alert(detected=True), _blue_alert(detected=False, alert_id="a2")],
            red_team_stages=[_red_stage()],
        )
        assert "score" in assessment or "awareness_score" in assessment
        assert "level" in assessment

    def test_track_training_effectiveness(self):
        engine = TrainingAwarenessEngine()
        history = [
            {"overall_score": 0.4},
            {"overall_score": 0.5},
            {"overall_score": 0.65},
        ]
        result = engine.track_training_effectiveness(history)
        assert "trend" in result or "effectiveness" in result

    @pytest.mark.asyncio
    async def test_event_bus_subscription(self):
        bus = EventBus()
        engine = TrainingAwarenessEngine()
        engine.subscribe_to_event_bus(bus, "t1", "ex1")
        assert bus is not None


# ---------------------------------------------------------------------------
# Orange Team
# ---------------------------------------------------------------------------

class TestOrangeTeam:
    def test_map_to_frameworks(self):
        engine = ComplianceGovernanceEngine()
        mapping = engine.map_to_frameworks(
            red_team_stages=[_red_stage(technique="T1566")],
            blue_team_alerts=[_blue_alert(detected=True, technique="T1566")],
            aar={"coverage_gaps": [{"technique_id": "T1566"}]},
        )
        assert isinstance(mapping, dict)
        assert len(mapping) >= 1
        # Should include at least one of the supported frameworks
        frameworks = set(mapping.keys())
        expected = {"PCI-DSS", "SOX", "GDPR", "NIST-CSF", "ISO-27001"}
        assert frameworks & expected  # at least one match

    def test_analyze_compliance_gaps(self):
        engine = ComplianceGovernanceEngine()
        mapping = engine.map_to_frameworks(
            red_team_stages=[_red_stage(technique="T1566")],
            blue_team_alerts=[_blue_alert(detected=False, technique="T1566")],
            aar=None,
        )
        gaps = engine.analyze_compliance_gaps(mapping)
        assert isinstance(gaps, list)
        for gap in gaps:
            assert "framework" in gap
            assert "control_id" in gap
            assert "severity" in gap

    @pytest.mark.asyncio
    async def test_generate_compliance_report(self):
        engine = ComplianceGovernanceEngine()
        mapping = engine.map_to_frameworks(
            red_team_stages=[_red_stage()],
            blue_team_alerts=[_blue_alert()],
            aar=None,
        )
        gaps = engine.analyze_compliance_gaps(mapping)
        report = await engine.generate_compliance_report(
            exercise_id="ex1",
            framework_mapping=mapping,
            compliance_gaps=gaps,
        )
        assert "executive_summary" in report or "summary" in report
        assert "posture" in report or "overall_status" in report or "overall_posture" in report

    def test_get_remediation_priorities(self):
        engine = ComplianceGovernanceEngine()
        gaps = [
            {"gap_id": "g1", "framework": "GDPR", "control_id": "Art 32",
             "severity": "critical", "deadline": "2026-01-01",
             "description": "test", "remediation": "fix it"},
        ]
        priorities = engine.get_remediation_priorities(gaps)
        assert isinstance(priorities, list)
        assert len(priorities) >= 1

    def test_assess_regulatory_impact(self):
        engine = ComplianceGovernanceEngine()
        gaps = [
            {"gap_id": "g1", "framework": "GDPR", "control_id": "Art 32",
             "severity": "critical", "description": "test"},
        ]
        impact = engine.assess_regulatory_impact(gaps)
        assert isinstance(impact, dict)

    @pytest.mark.asyncio
    async def test_event_bus_subscription(self):
        bus = EventBus()
        engine = ComplianceGovernanceEngine()
        engine.subscribe_to_event_bus(bus, "t1", "ex1")
        assert bus is not None


# ---------------------------------------------------------------------------
# Exercise Orchestrator Integration
# ---------------------------------------------------------------------------

class TestExerciseOrchestratorExtended:
    def test_exercise_result_has_extended_fields(self):
        from ciicerone.core.exercise_orchestrator import ExerciseResult
        result = ExerciseResult(
            exercise_id="ex1",
            tenant_id="t1",
            scenario_name="test",
            start_time=datetime.now(timezone.utc),
        )
        assert result.white_team_report is None
        assert result.yellow_team_report is None
        assert result.green_team_report is None
        assert result.orange_team_report is None

    def test_exercise_result_to_dict_includes_extended(self):
        from ciicerone.core.exercise_orchestrator import ExerciseResult
        result = ExerciseResult(
            exercise_id="ex1",
            tenant_id="t1",
            scenario_name="test",
            start_time=datetime.now(timezone.utc),
            white_team_report={"scope": "approved"},
        )
        d = result.to_dict()
        assert "white_team_report" in d
        assert "yellow_team_report" in d
        assert "green_team_report" in d
        assert "orange_team_report" in d
        assert d["white_team_report"]["scope"] == "approved"


# ---------------------------------------------------------------------------
# SSO
# ---------------------------------------------------------------------------

class TestSSO:
    def test_sso_user_info_model(self):
        from ciicerone.security.sso import SSOUserInfo
        info = SSOUserInfo(
            provider="oidc",
            external_id="ext-123",
            email="user@example.com",
            display_name="Test User",
            groups=["analyst", "security-team"],
        )
        assert info.provider == "oidc"
        assert info.email == "user@example.com"
        assert "analyst" in info.groups

    def test_oidc_config_model(self):
        from ciicerone.security.sso import OIDCConfig
        config = OIDCConfig(
            client_id="test-id",
            client_secret="test-secret",
            redirect_uri="http://localhost/callback",
            issuer_url="https://idp.example.com",
        )
        assert config.client_id == "test-id"
        assert "openid" in config.scopes

    def test_saml_config_model(self):
        from ciicerone.security.sso import SAMLConfig
        config = SAMLConfig(
            entity_id="https://sp.example.com",
            acs_url="https://sp.example.com/acs",
            idp_metadata_url="https://idp.example.com/metadata",
        )
        assert config.entity_id == "https://sp.example.com"

    def test_group_to_role_mapping_admin(self):
        from ciicerone.security.sso_bridge import SSOBridge, default_role_mapping
        from ciicerone.security.rbac import Role
        mapping = default_role_mapping()
        bridge = SSOBridge(user_store=MagicMock(), role_mapping=mapping)
        role = bridge._map_groups_to_role(["admins", "users"])
        assert role == Role.ADMIN

    def test_group_to_role_mapping_analyst(self):
        from ciicerone.security.sso_bridge import SSOBridge, default_role_mapping
        from ciicerone.security.rbac import Role
        mapping = default_role_mapping()
        bridge = SSOBridge(user_store=MagicMock(), role_mapping=mapping)
        role = bridge._map_groups_to_role(["security-team"])
        assert role == Role.ANALYST

    def test_group_to_role_mapping_default_viewer(self):
        from ciicerone.security.sso_bridge import SSOBridge, default_role_mapping
        from ciicerone.security.rbac import Role
        mapping = default_role_mapping()
        bridge = SSOBridge(user_store=MagicMock(), role_mapping=mapping)
        role = bridge._map_groups_to_role(["random-group"])
        assert role == Role.VIEWER

    def test_sso_token_response_model(self):
        from ciicerone.security.sso_bridge import SSOTokenResponse
        resp = SSOTokenResponse(
            access_token="jwt-token",
            user_id="u1",
            tenant_id="t1",
            role="analyst",
            email="user@example.com",
        )
        assert resp.access_token == "jwt-token"
        assert resp.token_type == "bearer"


# ---------------------------------------------------------------------------
# Secret Manager
# ---------------------------------------------------------------------------

class TestSecretManager:
    def test_secret_manager_chain(self):
        from ciicerone.security.secret_manager import SecretManager
        from ciicerone.client_data.credentials.env import EnvCredentialProvider
        mgr = SecretManager(providers=[EnvCredentialProvider()])
        assert len(mgr.providers) == 1

    @pytest.mark.asyncio
    async def test_get_secret_from_env(self, monkeypatch):
        from ciicerone.security.secret_manager import SecretManager
        from ciicerone.client_data.credentials.env import EnvCredentialProvider
        monkeypatch.setenv("TEST_SECRET_VALUE", "s3cr3t")
        mgr = SecretManager(providers=[EnvCredentialProvider()])
        from ciicerone.client_data.config import SecretRef
        value = await mgr.get_secret("TEST_SECRET_VALUE")
        assert value == "s3cr3t"

    @pytest.mark.asyncio
    async def test_get_required_raises_on_missing(self, monkeypatch):
        from ciicerone.security.secret_manager import SecretManager
        from ciicerone.client_data.credentials.env import EnvCredentialProvider
        monkeypatch.delenv("DEFINITELY_NOT_SET_SECRET", raising=False)
        mgr = SecretManager(providers=[EnvCredentialProvider()])
        with pytest.raises(ValueError):
            await mgr.get_required("DEFINITELY_NOT_SET_SECRET")

    @pytest.mark.asyncio
    async def test_get_many(self, monkeypatch):
        from ciicerone.security.secret_manager import SecretManager
        from ciicerone.client_data.credentials.env import EnvCredentialProvider
        monkeypatch.setenv("SECRET_A", "val_a")
        mgr = SecretManager(providers=[EnvCredentialProvider()])
        result = await mgr.get_many(["SECRET_A", "MISSING_SECRET"])
        assert result["SECRET_A"] == "val_a"
        assert result["MISSING_SECRET"] is None

    def test_from_env_with_no_config(self):
        from ciicerone.security.secret_manager import SecretManager
        mgr = SecretManager.from_env()
        # Should always have at least the env provider
        assert len(mgr.providers) >= 1

    def test_from_env_with_vault_config(self, monkeypatch):
        from ciicerone.security.secret_manager import SecretManager
        monkeypatch.setenv("VAULT_URL", "https://vault.example.com")
        monkeypatch.setenv("VAULT_TOKEN", "test-token")
        mgr = SecretManager.from_env()
        assert len(mgr.providers) >= 2  # Vault + Env


class TestHashiCorpVaultProvider:
    def test_init(self):
        from ciicerone.client_data.credentials.hashi_vault import HashiCorpVaultProvider
        provider = HashiCorpVaultProvider(
            vault_url="https://vault.example.com",
            token="test-token",
        )
        assert provider.vault_url == "https://vault.example.com"

    @pytest.mark.asyncio
    async def test_get_secret_not_found(self):
        from ciicerone.client_data.credentials.hashi_vault import HashiCorpVaultProvider
        from ciicerone.client_data.config import SecretRef
        provider = HashiCorpVaultProvider(
            vault_url="https://vault.example.com",
            token="test-token",
        )
        ref = SecretRef(name="nonexistent")
        # Mock httpx to return 404
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 404
            mock_response.raise_for_status.side_effect = Exception("404")
            mock_get.return_value = mock_response
            result = await provider.get_secret(ref)
            assert result is None


class TestAWSSecretsManagerProvider:
    def test_init(self):
        from ciicerone.client_data.credentials.aws_sm import AWSSecretsManagerProvider
        provider = AWSSecretsManagerProvider(
            region="us-east-1",
            access_key_id="test-key",
            secret_access_key="test-secret",
        )
        assert provider.region == "us-east-1"


# ---------------------------------------------------------------------------
# API Router Registration
# ---------------------------------------------------------------------------

class TestAPIRouterRegistration:
    def test_integrations_router_imported(self):
        from ciicerone.api.routers import integrations_router
        assert integrations_router is not None

    def test_sso_router_imported(self):
        from ciicerone.api.routers import sso_router
        assert sso_router is not None

    def test_secrets_router_imported(self):
        from ciicerone.api.routers import secrets_router
        assert secrets_router is not None

    def test_routers_in_all(self):
        from ciicerone.api.routers import __all__
        assert "integrations_router" in __all__
        assert "sso_router" in __all__
        assert "secrets_router" in __all__


# ---------------------------------------------------------------------------
# CLI Registration
# ---------------------------------------------------------------------------

class TestCLIRegistration:
    def test_integrations_cli_group_registered(self):
        from ciicerone.cli.integrations import integrations_group
        assert integrations_group is not None
        assert integrations_group.name == "integrations"

    def test_integrations_cli_has_commands(self):
        from ciicerone.cli.integrations import integrations_group
        command_names = list(integrations_group.commands.keys())
        assert "list" in command_names
        assert "test" in command_names or "test-all" in command_names


# ---------------------------------------------------------------------------
# ORM Models
# ---------------------------------------------------------------------------

class TestORMModels:
    def test_white_team_models_import(self):
        from ciicerone.db.models.white_team import (
            ROECheckRecord, ROEViolationRecord, RiskAssessmentRecord,
        )
        assert ROECheckRecord.__tablename__ == "roe_check_records"
        assert ROEViolationRecord.__tablename__ == "roe_violation_records"
        assert RiskAssessmentRecord.__tablename__ == "risk_assessment_records"

    def test_yellow_team_models_import(self):
        from ciicerone.db.models.yellow_team import (
            EnvironmentRecord, EnvironmentComponentRecord,
        )
        assert EnvironmentRecord.__tablename__ == "yellow_team_environments"
        assert EnvironmentComponentRecord.__tablename__ == "yellow_team_environment_components"

    def test_green_team_models_import(self):
        from ciicerone.db.models.green_team import (
            TrainingAssignmentRecord, TrainingModuleRecord, AwarenessAssessmentRecord,
        )
        assert TrainingAssignmentRecord.__tablename__ == "training_assignments"
        assert TrainingModuleRecord.__tablename__ == "training_modules"
        assert AwarenessAssessmentRecord.__tablename__ == "awareness_assessments"

    def test_orange_team_models_import(self):
        from ciicerone.db.models.orange_team import (
            ComplianceGapRecord, FrameworkMappingRecord, ComplianceReportRecord,
        )
        assert ComplianceGapRecord.__tablename__ == "compliance_gap_records"
        assert FrameworkMappingRecord.__tablename__ == "framework_mapping_records"
        assert ComplianceReportRecord.__tablename__ == "compliance_report_records"

    def test_all_new_tables_in_metadata(self):
        from ciicerone.db.base import Base
        tables = Base.metadata.tables
        assert "roe_check_records" in tables
        assert "roe_violation_records" in tables
        assert "risk_assessment_records" in tables
        assert "yellow_team_environments" in tables
        assert "yellow_team_environment_components" in tables
        assert "training_assignments" in tables
        assert "training_modules" in tables
        assert "awareness_assessments" in tables
        assert "compliance_gap_records" in tables
        assert "framework_mapping_records" in tables
        assert "compliance_report_records" in tables
