"""CLI commands for quantum threat simulation.

Provides commands for crypto scanning, quantum attack simulation,
PQC migration planning, hybrid crypto validation, and Y2Q timeline modeling.
"""

import asyncio
import json
import logging
import sys
from typing import Optional

import click

logger = logging.getLogger(__name__)


def _get_agent(config_path: Optional[str] = None):
    """Get a QuantumThreatAgent instance."""
    from ciicerone.quantum import QuantumThreatAgent

    config = {}
    if config_path:
        try:
            import yaml
            with open(config_path) as f:
                full_config = yaml.safe_load(f)
                config = full_config.get("quantum", {})
        except Exception as e:
            logger.warning(f"Failed to load config from {config_path}: {e}")

    return QuantumThreatAgent(config=config)


def _output_json(data, output_file: Optional[str] = None):
    """Output data as JSON."""
    if hasattr(data, "dict"):
        data = data.dict()
    elif hasattr(data, "model_dump"):
        data = data.model_dump()

    formatted = json.dumps(data, indent=2, default=str)

    if output_file:
        with open(output_file, "w") as f:
            f.write(formatted)
        click.echo(f"Results saved to {output_file}")
    else:
        click.echo(formatted)


@click.group()
def quantum():
    """Quantum threat simulation commands.

    Scan for quantum-vulnerable crypto, simulate quantum attacks,
    plan PQC migration, validate hybrid PQ/TLS, and model Y2Q timelines.
    """
    pass


@quantum.command()
@click.option("--target", "-t", required=True, help="Target URL, IP, hostname, or VM ID")
@click.option("--vm", help="VM ID for VM-based scanning (requires VM operator)")
@click.option("--config", "-c", help="Path to configuration file")
@click.option("--output", "-o", help="Save results to JSON file")
def scan(target, vm, config, output):
    """Scan a target for quantum-vulnerable cryptographic implementations."""
    agent = _get_agent(config)

    vm_operator = None
    if vm:
        try:
            from ciicerone.vm.operator import VMOperator
            vm_operator = VMOperator()
            target = vm
        except Exception as e:
            click.echo(f"Failed to initialize VM operator: {e}", err=True)
            sys.exit(1)

    result = asyncio.run(agent.scan_crypto_inventory(target, vm_operator))
    _output_json(result, output)


@quantum.command()
@click.option("--algorithm", "-a", required=True, help="Algorithm name (RSA, ECC, AES, etc.)")
@click.option("--key-size", "-k", required=True, type=int, help="Key size in bits")
@click.option("--type", "algorithm_type", default="unknown", help="Algorithm type (encryption, signature, hash, key_exchange, symmetric)")
@click.option("--config", "-c", help="Path to configuration file")
@click.option("--output", "-o", help="Save results to JSON file")
def simulate(algorithm, key_size, algorithm_type, config, output):
    """Simulate a quantum attack on a specific cryptographic algorithm."""
    agent = _get_agent(config)
    result = asyncio.run(agent.simulate_quantum_attack(algorithm, key_size, algorithm_type))
    _output_json(result, output)


@quantum.command()
@click.option("--scan-file", "-s", required=True, help="Path to JSON file with scan results")
@click.option("--org", default="default", help="Organization identifier")
@click.option("--config", "-c", help="Path to configuration file")
@click.option("--output", "-o", help="Save migration plan to JSON file")
def migrate(scan_file, org, config, output):
    """Generate a PQC migration plan from scan results."""
    agent = _get_agent(config)

    with open(scan_file) as f:
        scan_data = json.load(f)

    from ciicerone.quantum.models import QuantumVulnerabilityFinding
    findings = [QuantumVulnerabilityFinding(**f) for f in scan_data.get("findings", [])]

    plan = asyncio.run(agent.plan_pqc_migration(findings, org))
    _output_json(plan, output)


@quantum.command()
@click.option("--endpoint", "-e", required=True, help="Target endpoint (host:port)")
@click.option("--cipher-suite", default="x25519_kyber768", help="Hybrid cipher suite to test")
@click.option("--no-fallback", is_flag=True, help="Disable fallback to classical")
@click.option("--config", "-c", help="Path to configuration file")
@click.option("--output", "-o", help="Save results to JSON file")
def validate(endpoint, cipher_suite, no_fallback, config, output):
    """Validate a hybrid PQ/TLS deployment."""
    agent = _get_agent(config)

    hybrid_config = {
        "endpoint": endpoint,
        "cipher_suite": cipher_suite,
        "fallback_enabled": not no_fallback,
    }

    result = asyncio.run(agent.validate_hybrid_deployment(hybrid_config))
    _output_json(result, output)


@quantum.command()
@click.option("--scan-file", "-s", required=True, help="Path to JSON file with scan results")
@click.option("--org", default="default", help="Organization identifier")
@click.option("--migration-file", "-m", help="Path to JSON file with migration plan (optional)")
@click.option("--config", "-c", help="Path to configuration file")
@click.option("--output", "-o", help="Save timeline to JSON file")
def timeline(scan_file, org, migration_file, config, output):
    """Simulate Y2Q readiness timeline."""
    agent = _get_agent(config)

    with open(scan_file) as f:
        scan_data = json.load(f)

    from ciicerone.quantum.models import QuantumVulnerabilityFinding
    findings = [QuantumVulnerabilityFinding(**f) for f in scan_data.get("findings", [])]

    migration_plan = None
    if migration_file:
        from ciicerone.quantum.models import PQCMigrationPlan
        with open(migration_file) as f:
            plan_data = json.load(f)
        migration_plan = PQCMigrationPlan(**plan_data)

    result = asyncio.run(agent.simulate_y2q_timeline(findings, org, migration_plan))
    _output_json(result, output)


@quantum.command()
@click.option("--target", "-t", required=True, help="Target URL, IP, hostname, or VM ID")
@click.option("--vm", help="VM ID for VM-based scanning")
@click.option("--org", default="default", help="Organization identifier")
@click.option("--config", "-c", help="Path to configuration file")
@click.option("--output", "-o", help="Save full assessment to JSON file")
def assess(target, vm, org, config, output):
    """Run a full quantum threat assessment (scan + migration + Y2Q timeline)."""
    agent = _get_agent(config)

    vm_operator = None
    if vm:
        try:
            from ciicerone.vm.operator import VMOperator
            vm_operator = VMOperator()
            target = vm
        except Exception as e:
            click.echo(f"Failed to initialize VM operator: {e}", err=True)
            sys.exit(1)

    result = asyncio.run(agent.full_assessment(target, vm_operator, org))
    _output_json(result, output)
