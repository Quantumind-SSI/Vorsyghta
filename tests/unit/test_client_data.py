"""Unit tests for client data integrators."""

import asyncio

import pytest

from vorsyghta.client_data.config import (
    ClientDataConfig,
    ClientDataSourceConfig,
    CredentialSet,
    SecretRef,
    SourceType,
)
from vorsyghta.client_data.credentials import EnvCredentialProvider
from vorsyghta.client_data.enrichment import ClientDataEnricher
from vorsyghta.client_data.manager import ClientDataManager
from vorsyghta.client_data.models import (
    ClientProfile,
    Employee,
    NetworkLink,
    NetworkNode,
    NetworkTopology,
)
from vorsyghta.client_data.sources import GenericApiSource, Gns3Source
from vorsyghta.client_data.sources.cloud import GoogleDriveSource
from vorsyghta.client_data.recon import CompanyReconAgent
from vorsyghta.intelligence.models import CompanyIntelligence, ConfidenceLevel, IntelligenceSource
from vorsyghta.client_data.sources.crm import HubSpotSource


@pytest.fixture
def env_provider():
    return EnvCredentialProvider()


@pytest.fixture
def sample_profile():
    return ClientProfile(
        tenant_id="test",
        name="Test Co",
        employees=[
            Employee(
                source_id="1",
                email="alice@test.co",
                name="Alice",
                role="Chief Financial Officer",
                department="finance",
                seniority="c_level",
            ),
            Employee(
                source_id="2",
                email="bob@test.co",
                name="Bob",
                role="Engineer",
                department="engineering",
            ),
        ],
        network_topology=NetworkTopology(
            name="lab",
            nodes=[NetworkNode(node_id="r1", name="Router1", node_type="router")],
            links=[NetworkLink(source_id="r1", target_id="r2")],
        ),
    )


def test_env_provider_resolves_from_env(monkeypatch):
    monkeypatch.setenv("TEST_SECRET", "value123")
    provider = EnvCredentialProvider()
    result = asyncio.run(provider.get_secret(SecretRef(name="TEST_SECRET")))
    assert result == "value123"


def test_client_data_manager_loads_empty_config():
    manager = ClientDataManager(ClientDataConfig())
    assert manager.list_sources() == []
    assert manager.get_profile("default") is None


def test_api_source_builds_headers_bearer(monkeypatch):
    monkeypatch.setenv("API_TOKEN", "token123")
    config = ClientDataSourceConfig(
        name="api",
        type=SourceType.API,
        credentials=CredentialSet(token=SecretRef(name="API_TOKEN")),
        settings={"auth_type": "bearer", "base_url": "https://example.com"},
    )
    source = GenericApiSource(config, EnvCredentialProvider())

    async def check():
        headers = await source._build_headers()
        assert headers["Authorization"] == "Bearer token123"

    import asyncio

    asyncio.run(check())


def test_api_source_maps_employees():
    config = ClientDataSourceConfig(
        name="api",
        type=SourceType.API,
        settings={
            "mapping": {
                "employees": {
                    "root": "people",
                    "id": "id",
                    "email": "email",
                    "name": "full_name",
                    "role": "title",
                    "department": "dept",
                }
            }
        },
    )
    source = GenericApiSource(config, EnvCredentialProvider())
    raw = {"people": [{"id": "1", "email": "a@b.co", "full_name": "A", "title": "T", "dept": "D"}]}
    profile = source.normalize(raw)
    assert len(profile.employees) == 1
    assert profile.employees[0].email == "a@b.co"


def test_gns3_source_normalizes_topology(tmp_path):
    project_path = tmp_path / "lab.gns3"
    project_path.write_text(
        '{"name": "Lab", "version": "2.2", "topology": {"nodes": [], "links": []}}'
    )
    config = ClientDataSourceConfig(
        name="gns3",
        type=SourceType.GNS3,
        settings={"project_path": str(project_path)},
    )
    source = Gns3Source(config, EnvCredentialProvider())

    async def check():
        profile = await source.fetch()
        assert profile.network_topology is not None
        assert profile.network_topology.name == "Lab"

    import asyncio

    asyncio.run(check())


def test_enricher_matches_employee_by_role(sample_profile):
    from vorsyghta.config.models import TargetProfile, ThreatScenario

    scenario = ThreatScenario(
        metadata={"name": "Test Scenario", "description": "A test phishing scenario", "version": "1.0.0"},
        threat_type="phishing",
        delivery_vector="email",
        target_profile=TargetProfile(
            role="Chief Financial Officer",
            seniority="c_level",
            department="finance",
            technical_level="moderate",
        ),
        behavioral_pattern={},
        difficulty_level=5,
        estimated_duration=30,
    )
    enricher = ClientDataEnricher(sample_profile)
    enriched = asyncio.run(enricher.enrich_scenario(scenario))
    assert enriched.target_profile.role == "Chief Financial Officer"
    assert enriched.custom_parameters["client_tenant_id"] == "test"
    assert enriched.custom_parameters["client_name"] == "Test Co"
    assert "client_network_topology" in enriched.custom_parameters


def test_hubspot_source_maps_contacts():
    config = ClientDataSourceConfig(
        name="hubspot",
        type=SourceType.HUBSPOT,
        settings={"max_records": 10},
    )
    source = HubSpotSource(config, EnvCredentialProvider())
    raw = [
        {
            "id": "1",
            "properties": {
                "email": "x@y.co",
                "firstname": "X",
                "lastname": "Y",
                "jobtitle": "Engineer",
                "department": "Eng",
                "phone": "123",
            },
        }
    ]
    profile = source.normalize(raw)
    assert len(profile.employees) == 1
    assert profile.employees[0].name == "X Y"


def test_google_drive_source_maps_files():
    config = ClientDataSourceConfig(
        name="gdrive",
        type=SourceType.GOOGLE_DRIVE,
        settings={"max_files": 10},
    )
    source = GoogleDriveSource(config, EnvCredentialProvider())
    raw = [
        {
            "id": "1",
            "name": "report.pdf",
            "webViewLink": "https://drive.google.com/1",
            "mimeType": "application/pdf",
            "size": 1024,
            "modifiedTime": "2024-01-01T00:00:00Z",
        }
    ]
    profile = source.normalize(raw)
    assert len(profile.documents) == 1
    assert profile.documents[0].name == "report.pdf"


def test_company_recon_agent_resolves_domain_from_email(sample_profile):
    class FakeOSINTService:
        async def comprehensive_reconnaissance(self, target, recon_types=None):
            from vorsyghta.intelligence.models import OSINTResult

            return OSINTResult(
                target_identifier=target,
                query_type="comprehensive_reconnaissance",
                overall_confidence=ConfidenceLevel.MEDIUM,
                data_sources_used=[IntelligenceSource.COMPANY_WEBSITE],
                collection_duration_seconds=1.0,
                completeness_score=0.5,
                data_retention_policy="test",
                company_intelligence=CompanyIntelligence(
                    company_name="Test Co",
                    domain=target,
                    website_url=f"https://{target}",
                    industry="technology",
                    confidence_level=ConfidenceLevel.MEDIUM,
                    sources=[IntelligenceSource.COMPANY_WEBSITE],
                ),
            )

    agent = CompanyReconAgent(osint_service=FakeOSINTService())
    from vorsyghta.config.models import TargetProfile, ThreatScenario

    scenario = ThreatScenario(
        metadata={"name": "Test", "description": "A test scenario", "version": "1.0.0"},
        threat_type="phishing",
        delivery_vector="email",
        target_profile=TargetProfile(
            role="Engineer",
            seniority="mid",
            department="engineering",
            technical_level="moderate",
        ),
        behavioral_pattern={},
        difficulty_level=5,
        estimated_duration=30,
    )
    result = asyncio.run(agent.recon_company(sample_profile, scenario))
    assert result is not None
    assert result["company_name"] == "Test Co"
    assert result["domain"] == "test.co"
