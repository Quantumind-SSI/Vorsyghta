"""FastAPI router for quantum threat simulation endpoints.

Provides REST API endpoints for:
- Cryptographic inventory scanning
- Quantum attack simulation
- PQC migration planning
- Hybrid PQ/TLS validation
- Y2Q readiness timeline
"""

import json
import logging
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ciicerone.quantum import QuantumThreatAgent
from ciicerone.quantum.models import (
    CryptoAlgorithmType,
    QuantumAttackVector,
    SeverityLevel,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/quantum", tags=["quantum"])


# Request/Response models

class CryptoScanRequest(BaseModel):
    target: str = Field(..., description="Target URL, IP, hostname, or VM ID")
    vm_id: Optional[str] = Field(None, description="VM ID for VM-based scanning")


class SimulateAttackRequest(BaseModel):
    algorithm: str = Field(..., description="Algorithm name (RSA, ECC, AES, etc.)")
    key_size: int = Field(..., description="Key size in bits")
    algorithm_type: str = Field("unknown", description="Algorithm type")


class PQCMigrationRequest(BaseModel):
    findings: List[Dict[str, Any]] = Field(..., description="Quantum vulnerability findings")
    organization_id: str = Field("default", description="Organization identifier")


class HybridValidateRequest(BaseModel):
    endpoint: str = Field(..., description="Target endpoint (host:port)")
    cipher_suite: str = Field("x25519_kyber768", description="Hybrid cipher suite")
    fallback_enabled: bool = Field(True, description="Enable classical fallback")


class Y2QTimelineRequest(BaseModel):
    findings: List[Dict[str, Any]] = Field(..., description="Quantum vulnerability findings")
    organization_id: str = Field("default", description="Organization identifier")
    migration_plan: Optional[Dict[str, Any]] = Field(None, description="Pre-generated migration plan")


class FullAssessmentRequest(BaseModel):
    target: str = Field(..., description="Target URL, IP, hostname, or VM ID")
    vm_id: Optional[str] = Field(None, description="VM ID for VM-based scanning")
    organization_id: str = Field("default", description="Organization identifier")


# Agent singleton
_agent: Optional[QuantumThreatAgent] = None


def get_agent() -> QuantumThreatAgent:
    global _agent
    if _agent is None:
        _agent = QuantumThreatAgent()
    return _agent


# Endpoints

@router.post("/crypto-scan")
async def crypto_scan(request: CryptoScanRequest):
    """Scan a target for quantum-vulnerable cryptographic implementations."""
    agent = get_agent()

    vm_operator = None
    if request.vm_id:
        try:
            from ciicerone.vm.operator import VMOperator
            vm_operator = VMOperator()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"VM operator unavailable: {e}")

    result = await agent.scan_crypto_inventory(
        request.target if not request.vm_id else request.vm_id,
        vm_operator,
    )
    return result.dict()


@router.post("/simulate-attack")
async def simulate_attack(request: SimulateAttackRequest):
    """Simulate a quantum attack on a specific cryptographic algorithm."""
    agent = get_agent()
    result = await agent.simulate_quantum_attack(
        request.algorithm,
        request.key_size,
        request.algorithm_type,
    )
    return result.dict()


@router.post("/pqc-migration")
async def pqc_migration(request: PQCMigrationRequest):
    """Generate a PQC migration plan from vulnerability findings."""
    from ciicerone.quantum.models import QuantumVulnerabilityFinding

    agent = get_agent()

    try:
        findings = [QuantumVulnerabilityFinding(**f) for f in request.findings]
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid finding data: {e}")

    plan = await agent.plan_pqc_migration(findings, request.organization_id)
    return plan.dict()


@router.post("/hybrid-validate")
async def hybrid_validate(request: HybridValidateRequest):
    """Validate a hybrid PQ/TLS deployment."""
    agent = get_agent()

    config = {
        "endpoint": request.endpoint,
        "cipher_suite": request.cipher_suite,
        "fallback_enabled": request.fallback_enabled,
    }

    result = await agent.validate_hybrid_deployment(config)
    return result.dict()


@router.post("/y2q-timeline")
async def y2q_timeline(request: Y2QTimelineRequest):
    """Simulate Y2Q readiness timeline."""
    from ciicerone.quantum.models import (
        PQCMigrationPlan,
        QuantumVulnerabilityFinding,
    )

    agent = get_agent()

    try:
        findings = [QuantumVulnerabilityFinding(**f) for f in request.findings]
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid finding data: {e}")

    migration_plan = None
    if request.migration_plan:
        try:
            migration_plan = PQCMigrationPlan(**request.migration_plan)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid migration plan: {e}")

    result = await agent.simulate_y2q_timeline(
        findings, request.organization_id, migration_plan
    )
    return result.dict()


@router.post("/assess")
async def full_assessment(request: FullAssessmentRequest):
    """Run a full quantum threat assessment (scan + migration + Y2Q)."""
    agent = get_agent()

    vm_operator = None
    if request.vm_id:
        try:
            from ciicerone.vm.operator import VMOperator
            vm_operator = VMOperator()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"VM operator unavailable: {e}")

    result = await agent.full_assessment(
        request.target if not request.vm_id else request.vm_id,
        vm_operator,
        request.organization_id,
    )

    return {
        "scan_result": result["scan_result"].dict(),
        "migration_plan": result["migration_plan"].dict(),
        "y2q_timeline": result["y2q_timeline"].dict(),
        "executive_summary": result["executive_summary"],
    }


@router.get("/inventory")
async def get_inventory():
    """Get quantum vulnerability inventory (placeholder for persistence)."""
    return {
        "message": "Crypto inventory endpoint. Use POST /crypto-scan to scan targets.",
        "supported_algorithms": list({
            "RSA", "ECC", "ECDSA", "DSA", "Diffie-Hellman",
            "AES", "SHA", "HMAC", "ChaCha20", "Poly1305",
            "Ed25519", "Ed448", "X25519", "X448",
        }),
        "pqc_standards": {
            "encryption": "CRYSTALS-Kyber (FIPS 203)",
            "signature": "CRYSTALS-Dilithium (FIPS 204)",
            "alternate_signature": "Falcon (FIPS 206)",
            "fallback_signature": "SPHINCS+ (FIPS 205)",
        },
    }
