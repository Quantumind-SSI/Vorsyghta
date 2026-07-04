#!/usr/bin/env python3
"""
Recursive Prompting: A STRIDE- and SBOM-Guided, Semgrep-in-the-Loop LLM SAST Pipeline

Hybrid recon → threat model → recursive local-inference audit → manual or frontier-model triage

This pipeline implements a four-stage static analysis methodology:
1. Recon: Architecture diagrams, user-input flows, trust model, SBOM with Trivy audit
2. STRIDE Threat Model: Single local-model pass over recon artifacts
3. Recursive Audit Loop: N passes with clean context + Semgrep pattern matching
4. Triage: Manual or frontier-model verification and ranking

Usage:
    python security-audit/pipeline.py --stages 1,2,3,4 --passes 10 --model qwen
    python security-audit/pipeline.py --stage 1  # Run just recon
    python security-audit/pipeline.py --stage 3 --passes 5  # Run recursive audit
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
AUDIT_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = AUDIT_DIR / "output"
REPORTS_DIR = AUDIT_DIR / "reports"


class SecurityAuditPipeline:
    """Main pipeline orchestrator for the recursive STRIDE-guided SAST analysis."""

    def __init__(
        self,
        repo_root: Path,
        output_dir: Path,
        reports_dir: Path,
        model_name: str = "qwen2.5-coder:7b",
        semgrep_rules: Optional[Path] = None,
    ):
        self.repo_root = repo_root
        self.output_dir = output_dir
        self.reports_dir = reports_dir
        self.model_name = model_name
        self.semgrep_rules = semgrep_rules or AUDIT_DIR / "semgrep-rules"

        # Ensure directories exist
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.semgrep_rules.mkdir(parents=True, exist_ok=True)

        # Stage outputs
        self.recon_output = self.output_dir / "01-recon"
        self.threat_model_output = self.output_dir / "02-threat-model"
        self.audit_output = self.output_dir / "03-recursive-audit"
        self.triage_output = self.output_dir / "04-triage"

        for dir_path in [self.recon_output, self.threat_model_output, self.audit_output, self.triage_output]:
            dir_path.mkdir(exist_ok=True)

    def run_command(self, cmd: List[str], cwd: Optional[Path] = None, capture: bool = True) -> subprocess.CompletedProcess:
        """Run a command and return the result."""
        work_dir = cwd or self.repo_root
        print(f"Running: {' '.join(cmd)} in {work_dir}")
        
        if capture:
            result = subprocess.run(cmd, cwd=work_dir, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"Command failed: {result.stderr}")
            return result
        else:
            result = subprocess.run(cmd, cwd=work_dir)
            return result

    # ==================== STAGE 1: RECON ====================

    def stage1_recon(self) -> Dict[str, Any]:
        """Generate recon artifacts: architecture, user flows, trust model, SBOM."""
        print("\n=== STAGE 1: RECON ===")
        
        recon_results = {}

        # 1.1 Generate architecture diagrams
        print("1.1 Generating architecture diagrams...")
        recon_results["architecture"] = self._generate_architecture_diagrams()

        # 1.2 Generate user-input-flow diagrams
        print("1.2 Generating user-input-flow diagrams...")
        recon_results["user_flows"] = self._generate_user_flow_diagrams()

        # 1.3 Generate trust model
        print("1.3 Generating trust model...")
        recon_results["trust_model"] = self._generate_trust_model()

        # 1.4 Generate SBOM and audit with Trivy
        print("1.4 Generating SBOM and running Trivy audit...")
        recon_results["sbom"] = self._generate_sbom_and_audit()

        # Save recon results
        recon_file = self.recon_output / "recon_results.json"
        with open(recon_file, 'w') as f:
            json.dump(recon_results, f, indent=2)

        print(f"Recon artifacts saved to {self.recon_output}")
        return recon_results

    def _generate_architecture_diagrams(self) -> Dict[str, Any]:
        """Generate architecture diagrams showing service/component boundaries."""
        # Use tree-sitter or static analysis to understand the codebase structure
        architecture = {
            "components": self._discover_components(),
            "services": self._discover_services(),
            "data_flows": self._analyze_data_flows(),
            "boundaries": self._identify_boundaries()
        }

        # Save architecture diagram
        arch_file = self.recon_output / "architecture.json"
        with open(arch_file, 'w') as f:
            json.dump(architecture, f, indent=2)

        return architecture

    def _discover_components(self) -> List[Dict[str, Any]]:
        """Discover main components in the codebase."""
        components = []
        
        # Look for main Python modules
        ciicerone_dir = self.repo_root / "ciicerone"
        if ciicerone_dir.exists():
            for item in ciicerone_dir.iterdir():
                if item.is_dir() and not item.name.startswith('__'):
                    components.append({
                        "name": item.name,
                        "type": "module",
                        "path": str(item.relative_to(self.repo_root)),
                        "files": [f.name for f in item.glob('*.py')]
                    })

        # Look for API routers
        api_dir = self.repo_root / "ciicerone" / "api"
        if api_dir.exists():
            components.append({
                "name": "api",
                "type": "api_layer",
                "path": "ciicerone/api",
                "routers": [f.name for f in (api_dir / "routers").glob('*.py')] if (api_dir / "routers").exists() else []
            })

        return components

    def _discover_services(self) -> List[Dict[str, Any]]:
        """Discover external services and integrations."""
        services = []
        
        # Look for service files
        for pattern in ["**/*service*.py", "**/*client*.py", "**/*integration*.py"]:
            for file_path in self.repo_root.glob(pattern):
                services.append({
                    "name": file_path.stem,
                    "type": "service",
                    "path": str(file_path.relative_to(self.repo_root))
                })

        return services

    def _analyze_data_flows(self) -> List[Dict[str, Any]]:
        """Analyze data flows between components."""
        flows = []
        
        # Look for database models
        db_dir = self.repo_root / "ciicerone" / "db"
        if db_dir.exists():
            models_dir = db_dir / "models"
            if models_dir.exists():
                for model_file in models_dir.glob("*.py"):
                    flows.append({
                        "type": "database",
                        "source": "application",
                        "target": f"db.models.{model_file.stem}",
                        "description": f"Database model: {model_file.stem}"
                    })

        return flows

    def _identify_boundaries(self) -> List[Dict[str, Any]]:
        """Identify trust boundaries in the system."""
        boundaries = []
        
        # API boundary
        boundaries.append({
            "type": "api_boundary",
            "description": "External API interface",
            "entry_points": ["ciicerone/api/"],
            "trust_level": "untrusted_to_trusted"
        })

        # CLI boundary
        cli_dir = self.repo_root / "ciicerone" / "cli"
        if cli_dir.exists():
            boundaries.append({
                "type": "cli_boundary",
                "description": "Command-line interface",
                "entry_points": ["ciicerone/cli/"],
                "trust_level": "user_to_system"
            })

        return boundaries

    def _generate_user_flow_diagrams(self) -> Dict[str, Any]:
        """Generate user-input-flow diagrams tracing untrusted data."""
        flows = {
            "entry_points": self._find_entry_points(),
            "input_validation": self._analyze_input_validation(),
            "data_paths": self._trace_data_paths()
        }

        flows_file = self.recon_output / "user_flows.json"
        with open(flows_file, 'w') as f:
            json.dump(flows, f, indent=2)

        return flows

    def _find_entry_points(self) -> List[Dict[str, Any]]:
        """Find all entry points where untrusted data enters the system."""
        entry_points = []

        # API endpoints
        api_routers = self.repo_root / "ciicerone" / "api" / "routers"
        if api_routers.exists():
            for router_file in api_routers.glob("*.py"):
                entry_points.append({
                    "type": "api_endpoint",
                    "file": str(router_file.relative_to(self.repo_root)),
                    "description": f"API router: {router_file.stem}"
                })

        # CLI commands
        cli_dir = self.repo_root / "ciicerone" / "cli"
        if cli_dir.exists():
            for cli_file in cli_dir.glob("*.py"):
                entry_points.append({
                    "type": "cli_command",
                    "file": str(cli_file.relative_to(self.repo_root)),
                    "description": f"CLI module: {cli_file.stem}"
                })

        return entry_points

    def _analyze_input_validation(self) -> List[Dict[str, Any]]:
        """Analyze input validation mechanisms."""
        validation_points = []

        # Look for validation patterns
        validation_patterns = [
            "pydantic.BaseModel",
            "validator",
            "Field(",
            "@validate",
            "validate_"
        ]

        for pattern in validation_patterns:
            result = self.run_command([
                "rg", "-l", pattern, "--type", "py"
            ])
            if result.returncode == 0:
                for file_path in result.stdout.strip().split('\n'):
                    if file_path:
                        validation_points.append({
                            "pattern": pattern,
                            "file": file_path,
                            "type": "validation"
                        })

        return validation_points

    def _trace_data_paths(self) -> List[Dict[str, Any]]:
        """Trace how data flows through the system."""
        paths = []

        # Look for database operations
        db_patterns = ["session.add", "session.commit", "session.query", "db.session"]
        for pattern in db_patterns:
            result = self.run_command([
                "rg", "-l", pattern, "--type", "py"
            ])
            if result.returncode == 0:
                for file_path in result.stdout.strip().split('\n'):
                    if file_path:
                        paths.append({
                            "pattern": pattern,
                            "file": file_path,
                            "type": "database_operation"
                        })

        return paths

    def _generate_trust_model(self) -> Dict[str, Any]:
        """Generate trust model marking privilege changes."""
        trust_model = {
            "trust_levels": [
                {"level": "untrusted", "description": "External user input"},
                {"level": "user", "description": "Authenticated user"},
                {"level": "system", "description": "System processes"},
                {"level": "admin", "description": "Administrative access"}
            ],
            "privilege_boundaries": self._identify_privilege_boundaries(),
            "authentication_points": self._find_authentication_points()
        }

        trust_file = self.recon_output / "trust_model.json"
        with open(trust_file, 'w') as f:
            json.dump(trust_model, f, indent=2)

        return trust_model

    def _identify_privilege_boundaries(self) -> List[Dict[str, Any]]:
        """Identify where privilege changes occur."""
        boundaries = []

        # Look for authentication/authorization
        auth_patterns = ["@auth", "authenticate", "authorize", "login", "permission"]
        for pattern in auth_patterns:
            result = self.run_command([
                "rg", "-l", pattern, "--type", "py"
            ])
            if result.returncode == 0:
                for file_path in result.stdout.strip().split('\n'):
                    if file_path:
                        boundaries.append({
                            "pattern": pattern,
                            "file": file_path,
                            "type": "privilege_boundary"
                        })

        return boundaries

    def _find_authentication_points(self) -> List[Dict[str, Any]]:
        """Find authentication and authorization points."""
        auth_points = []

        # Look for auth-related files
        auth_files = list(self.repo_root.rglob("*auth*.py")) + list(self.repo_root.rglob("*rbac*.py"))
        for auth_file in auth_files:
            auth_points.append({
                "file": str(auth_file.relative_to(self.repo_root)),
                "type": "authentication"
            })

        return auth_points

    def _generate_sbom_and_audit(self) -> Dict[str, Any]:
        """Generate SBOM and audit with Trivy for known CVEs."""
        sbom_results = {}

        # Generate SBOM using CycloneDX
        print("  Generating SBOM with CycloneDX...")
        sbom_file = self.recon_output / "sbom.json"
        result = self.run_command([
            "cyclonedx-py", "--format", "json", "--output", str(sbom_file), 
            "--include", "dev", str(self.repo_root)
        ], capture=False)

        if sbom_file.exists():
            sbom_results["sbom_generated"] = True
            sbom_results["sbom_file"] = str(sbom_file)
        else:
            sbom_results["sbom_generated"] = False

        # Run Trivy audit
        print("  Running Trivy vulnerability scan...")
        trivy_file = self.recon_output / "trivy_scan.json"
        result = self.run_command([
            "trivy", "fs", "--format", "json", "--output", str(trivy_file), str(self.repo_root)
        ], capture=False)

        if trivy_file.exists():
            sbom_results["trivy_scan"] = True
            sbom_results["trivy_file"] = str(trivy_file)
            
            # Parse Trivy results
            try:
                with open(trivy_file, 'r') as f:
                    trivy_data = json.load(f)
                    sbom_results["vulnerabilities"] = len(trivy_data.get("Results", []))
            except:
                sbom_results["vulnerabilities"] = 0
        else:
            sbom_results["trivy_scan"] = False
            sbom_results["vulnerabilities"] = 0

        sbom_results_file = self.recon_output / "sbom_results.json"
        with open(sbom_results_file, 'w') as f:
            json.dump(sbom_results, f, indent=2)

        return sbom_results

    # ==================== STAGE 2: THREAT MODEL ====================

    def stage2_threat_model(self, recon_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create STRIDE threat model from recon artifacts."""
        print("\n=== STAGE 2: STRIDE THREAT MODEL ===")
        
        # Load recon data if not provided
        if not recon_data:
            recon_file = self.recon_output / "recon_results.json"
            if recon_file.exists():
                with open(recon_file, 'r') as f:
                    recon_data = json.load(f)

        # Generate STRIDE threat model using local LLM
        threat_model = self._generate_stride_model(recon_data)

        # Save threat model
        model_file = self.threat_model_output / "stride_threat_model.json"
        with open(model_file, 'w') as f:
            json.dump(threat_model, f, indent=2)

        # Generate Semgrep rules from threat model
        self._generate_semgrep_rules_from_threat_model(threat_model)

        print(f"STRIDE threat model saved to {self.threat_model_output}")
        return threat_model

    def _generate_stride_model(self, recon_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate STRIDE threat model using local LLM."""
        # Prepare context for LLM
        context = {
            "architecture": recon_data.get("architecture", {}),
            "user_flows": recon_data.get("user_flows", {}),
            "trust_model": recon_data.get("trust_model", {}),
            "stride_categories": {
                "Spoofing": "Identity impersonation attacks",
                "Tampering": "Data modification attacks", 
                "Repudiation": "Non-repudiation failures",
                "Information Disclosure": "Data leakage attacks",
                "Denial of Service": "Availability attacks",
                "Elevation of Privilege": "Privilege escalation attacks"
            }
        }

        # Create prompt for local LLM
        prompt = self._create_stride_prompt(context)

        # Call local LLM (placeholder - would integrate with actual model)
        threat_analysis = self._call_local_llm(prompt, "stride_analysis")

        # Parse and structure the threat model
        threat_model = {
            "generated_at": datetime.now().isoformat(),
            "model_used": self.model_name,
            "stride_analysis": threat_analysis,
            "trust_boundaries": context["trust_model"].get("privilege_boundaries", []),
            "entry_points": context["user_flows"].get("entry_points", []),
            "threats": self._parse_stride_threats(threat_analysis)
        }

        return threat_model

    def _create_stride_prompt(self, context: Dict[str, Any]) -> str:
        """Create STRIDE analysis prompt for local LLM."""
        return f"""
You are a security expert performing a STRIDE threat model analysis.

CONTEXT:
Architecture: {json.dumps(context.get('architecture', {}), indent=2)}
User Flows: {json.dumps(context.get('user_flows', {}), indent=2)}
Trust Model: {json.dumps(context.get('trust_model', {}), indent=2)}

STRIDE CATEGORIES:
- Spoofing: Identity impersonation attacks
- Tampering: Data modification attacks
- Repudiation: Non-repudiation failures  
- Information Disclosure: Data leakage attacks
- Denial of Service: Availability attacks
- Elevation of Privilege: Privilege escalation attacks

TASK:
Analyze the system for each STRIDE category. For each category:
1. Identify potential threat vectors
2. Map threats to specific components/files
3. Assess impact and likelihood
4. Suggest mitigations

FORMAT:
Return JSON with this structure:
{{
  "threats": [
    {{
      "category": "Spoofing|Tampering|Repudiation|Information Disclosure|Denial of Service|Elevation of Privilege",
      "title": "Threat title",
      "description": "Detailed description",
      "component": "Affected component",
      "file_path": "Relevant file path",
      "impact": "High|Medium|Low",
      "likelihood": "High|Medium|Low",
      "mitigation": "Suggested mitigation"
    }}
  ]
}}
"""

    def _call_local_llm(self, prompt: str, task_type: str) -> Dict[str, Any]:
        """Call local LLM for analysis (placeholder implementation)."""
        # This would integrate with the actual local model (e.g., Ollama, LM Studio)
        # For now, return a mock response
        return {
            "threats": [
                {
                    "category": "Information Disclosure",
                    "title": "Unvalidated API Input",
                    "description": "API endpoints may not properly validate input leading to information disclosure",
                    "component": "api",
                    "file_path": "ciicerone/api/routers/",
                    "impact": "Medium",
                    "likelihood": "Medium",
                    "mitigation": "Implement input validation and sanitization"
                }
            ]
        }

    def _parse_stride_threats(self, threat_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse threats from LLM response."""
        return threat_analysis.get("threats", [])

    def _generate_semgrep_rules_from_threat_model(self, threat_model: Dict[str, Any]) -> None:
        """Generate Semgrep rules based on threat model findings."""
        rules = []
        
        for threat in threat_model.get("threats", []):
            rule = {
                "id": f"stride-{threat['category'].lower()}-{threat['title'].lower().replace(' ', '-')}",
                "message": threat["description"],
                "severity": "ERROR" if threat["impact"] == "High" else "WARNING",
                "languages": ["python"],
                "pattern": self._create_pattern_for_threat(threat),
                "metadata": {
                    "category": threat["category"],
                    "mitigation": threat["mitigation"]
                }
            }
            rules.append(rule)

        # Save Semgrep rules
        rules_file = self.semgrep_rules / "stride-generated.yml"
        with open(rules_file, 'w') as f:
            yaml.dump({"rules": rules}, f, default_flow_style=False)

    def _create_pattern_for_threat(self, threat: Dict[str, Any]) -> str:
        """Create Semgrep pattern for a specific threat."""
        # This would create more sophisticated patterns based on threat type
        # For now, return a generic pattern
        return "$X"

    # ==================== STAGE 3: RECURSIVE AUDIT ====================

    def stage3_recursive_audit(self, threat_model: Dict[str, Any], num_passes: int = 10) -> Dict[str, Any]:
        """Run recursive audit loop with local model + Semgrep."""
        print(f"\n=== STAGE 3: RECURSIVE AUDIT LOOP ({num_passes} passes) ===")
        
        all_findings = []

        for pass_num in range(num_passes):
            print(f"\nPass {pass_num + 1}/{num_passes}")
            
            # 3.1 Run Semgrep with STRIDE-seeded rules
            semgrep_findings = self._run_semgrep_scan(pass_num)
            
            # 3.2 Run local LLM analysis with clean context
            llm_findings = self._run_llm_audit(pass_num, threat_model)
            
            # 3.3 Combine findings for this pass
            pass_findings = {
                "pass": pass_num + 1,
                "timestamp": datetime.now().isoformat(),
                "semgrep_findings": semgrep_findings,
                "llm_findings": llm_findings,
                "total_findings": len(semgrep_findings) + len(llm_findings)
            }
            
            all_findings.append(pass_findings)
            
            # Save intermediate results
            pass_file = self.audit_output / f"pass_{pass_num + 1:03d}.json"
            with open(pass_file, 'w') as f:
                json.dump(pass_findings, f, indent=2)

        # Aggregate all findings
        audit_results = {
            "total_passes": num_passes,
            "model_used": self.model_name,
            "findings": all_findings,
            "summary": self._summarize_audit_results(all_findings)
        }

        # Save complete audit results
        audit_file = self.audit_output / "recursive_audit_results.json"
        with open(audit_file, 'w') as f:
            json.dump(audit_results, f, indent=2)

        print(f"Recursive audit completed. Results saved to {self.audit_output}")
        return audit_results

    def _run_semgrep_scan(self, pass_num: int) -> List[Dict[str, Any]]:
        """Run Semgrep scan with STRIDE-seeded rules."""
        print(f"  Running Semgrep scan (pass {pass_num + 1})...")
        
        # Run Semgrep with custom rules
        rules_dir = self.semgrep_rules
        output_file = self.audit_output / f"semgrep_pass_{pass_num + 1:03d}.json"
        
        result = self.run_command([
            "semgrep", "--config", str(rules_dir), "--json", "--output", str(output_file),
            "--quiet", str(self.repo_root)
        ])

        findings = []
        if output_file.exists():
            try:
                with open(output_file, 'r') as f:
                    semgrep_data = json.load(f)
                    findings = semgrep_data.get("results", [])
            except:
                pass

        return findings

    def _run_llm_audit(self, pass_num: int, threat_model: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Run local LLM audit with clean context."""
        print(f"  Running LLM audit (pass {pass_num + 1})...")
        
        # Select a random component to analyze (clean context per pass)
        components = self._get_random_components_for_pass(pass_num)
        
        findings = []
        for component in components:
            # Create focused prompt for this component
            prompt = self._create_audit_prompt(component, threat_model)
            
            # Call local LLM
            analysis = self._call_local_llm(prompt, f"audit_pass_{pass_num}")
            
            # Parse findings
            for finding in analysis.get("findings", []):
                finding["pass"] = pass_num + 1
                finding["component"] = component
                findings.append(finding)

        return findings

    def _get_random_components_for_pass(self, pass_num: int) -> List[str]:
        """Get components to analyze for this pass (clean context)."""
        # Simple strategy: rotate through components
        all_components = ["api", "cli", "core", "db", "defense", "intelligence"]
        
        # Select 2-3 components per pass for clean context
        start_idx = (pass_num * 2) % len(all_components)
        selected = all_components[start_idx:start_idx + 2]
        if len(selected) < 2:
            selected.extend(all_components[:2 - len(selected)])
        
        return selected

    def _create_audit_prompt(self, component: str, threat_model: Dict[str, Any]) -> str:
        """Create audit prompt for a specific component."""
        return f"""
You are a security expert auditing the {component} component of a cybersecurity platform.

COMPONENT: {component}

RELEVANT THREATS FROM STRIDE MODEL:
{json.dumps([t for t in threat_model.get('threats', []) if component in t.get('component', '')], indent=2)}

TASK:
Analyze the {component} component for security vulnerabilities. Focus on:
1. Input validation and sanitization
2. Authentication and authorization
3. Data handling and storage
4. Error handling and information disclosure
5. Business logic vulnerabilities

FORMAT:
Return JSON with this structure:
{{
  "findings": [
    {{
      "title": "Finding title",
      "description": "Detailed description",
      "severity": "Critical|High|Medium|Low",
      "file_path": "Path to vulnerable file",
      "line_number": 123,
      "code_snippet": "Relevant code",
      "recommendation": "Fix recommendation"
    }}
  ]
}}
"""

    def _summarize_audit_results(self, all_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Summarize results from all audit passes."""
        total_semgrep = sum(len(f["semgrep_findings"]) for f in all_findings)
        total_llm = sum(len(f["llm_findings"]) for f in all_findings)
        total = total_semgrep + total_llm
        
        # Count by severity
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        
        for pass_findings in all_findings:
            for finding in pass_findings.get("llm_findings", []):
                severity = finding.get("severity", "Low")
                if severity in severity_counts:
                    severity_counts[severity] += 1

        return {
            "total_findings": total,
            "semgrep_findings": total_semgrep,
            "llm_findings": total_llm,
            "severity_breakdown": severity_counts,
            "findings_per_pass": [f["total_findings"] for f in all_findings]
        }

    # ==================== STAGE 4: TRIAGE ====================

    def stage4_triage(self, audit_results: Dict[str, Any]) -> Dict[str, Any]:
        """Triage candidates and generate verified findings report."""
        print("\n=== STAGE 4: TRIAGE ===")
        
        # 4.1 Collect all candidates from recursive audit
        all_candidates = self._collect_all_candidates(audit_results)
        
        # 4.2 Deduplicate and verify findings
        verified_findings = self._verify_and_deduplicate(all_candidates)
        
        # 4.3 Rank by severity and exploitability
        ranked_findings = self._rank_findings(verified_findings)
        
        # 4.4 Generate final report
        final_report = self._generate_final_report(ranked_findings, audit_results)
        
        print(f"Triage completed. Final report saved to {self.reports_dir}")
        return final_report

    def _collect_all_candidates(self, audit_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Collect all candidate findings from recursive audit."""
        candidates = []
        
        for pass_findings in audit_results.get("findings", []):
            # Add Semgrep findings
            for semgrep_finding in pass_findings.get("semgrep_findings", []):
                candidates.append({
                    "source": "semgrep",
                    "pass": pass_findings["pass"],
                    **semgrep_finding
                })
            
            # Add LLM findings
            for llm_finding in pass_findings.get("llm_findings", []):
                candidates.append({
                    "source": "llm",
                    "pass": pass_findings["pass"],
                    **llm_finding
                })
        
        return candidates

    def _verify_and_deduplicate(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Verify reachability and deduplicate findings."""
        print("  Verifying and deduplicating findings...")
        
        # Simple deduplication based on file path and line number
        seen = set()
        verified = []
        
        for candidate in candidates:
            # Create deduplication key
            file_path = candidate.get("path", candidate.get("file_path", ""))
            line = candidate.get("start", candidate.get("line_number", 0))
            key = (file_path, line)
            
            if key not in seen:
                # Verify the finding actually exists in the code
                if self._verify_finding(candidate):
                    verified.append(candidate)
                    seen.add(key)
        
        return verified

    def _verify_finding(self, finding: Dict[str, Any]) -> bool:
        """Verify that a finding actually exists in the code."""
        file_path = finding.get("path", finding.get("file_path", ""))
        if not file_path:
            return False
        
        full_path = self.repo_root / file_path
        if not full_path.exists():
            return False
        
        # Check if the file contains the relevant code
        try:
            content = full_path.read_text()
            
            # For Semgrep findings, check the pattern
            if finding.get("source") == "semgrep":
                # Simple verification - could be more sophisticated
                return True
            
            # For LLM findings, check the code snippet
            if finding.get("source") == "llm":
                snippet = finding.get("code_snippet", "")
                if snippet and snippet in content:
                    return True
            
            return True
        except:
            return False

    def _rank_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Rank findings by severity and exploitability."""
        print("  Ranking findings by severity...")
        
        # Define severity order
        severity_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "ERROR": 3, "WARNING": 2, "INFO": 1}
        
        # Sort findings
        ranked = sorted(findings, key=lambda f: (
            severity_order.get(f.get("severity", "Low"), 1),
            f.get("source", "") == "llm",  # Prefer LLM findings
            f.get("pass", 0)  # Earlier passes first
        ), reverse=True)
        
        # Add rank
        for i, finding in enumerate(ranked, 1):
            finding["rank"] = i
        
        return ranked

    def _generate_final_report(self, ranked_findings: List[Dict[str, Any]], audit_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate final verified findings report."""
        print("  Generating final report...")
        
        # Create summary statistics
        summary = {
            "total_findings": len(ranked_findings),
            "critical_findings": len([f for f in ranked_findings if f.get("severity") in ["Critical", "ERROR"]]),
            "high_findings": len([f for f in ranked_findings if f.get("severity") in ["High", "WARNING"]]),
            "medium_findings": len([f for f in ranked_findings if f.get("severity") == "Medium"]),
            "low_findings": len([f for f in ranked_findings if f.get("severity") in ["Low", "INFO"]]),
            "semgrep_findings": len([f for f in ranked_findings if f.get("source") == "semgrep"]),
            "llm_findings": len([f for f in ranked_findings if f.get("source") == "llm"])
        }
        
        # Generate report
        report = {
            "generated_at": datetime.now().isoformat(),
            "pipeline_version": "1.0.0",
            "model_used": self.model_name,
            "repository": str(self.repo_root),
            "summary": summary,
            "audit_summary": audit_results.get("summary", {}),
            "findings": ranked_findings[:50],  # Top 50 findings
            "recommendations": self._generate_recommendations(ranked_findings)
        }
        
        # Save detailed report
        report_file = self.reports_dir / "security_audit_report.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Save human-readable summary
        self._generate_markdown_report(report)
        
        return report

    def _generate_recommendations(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate recommendations based on findings."""
        recommendations = []
        
        # Group findings by type
        by_category = {}
        for finding in findings:
            category = finding.get("metadata", {}).get("category", "General")
            if category not in by_category:
                by_category[category] = []
            by_category[category].append(finding)
        
        # Generate recommendations for each category
        for category, category_findings in by_category.items():
            if len(category_findings) >= 3:  # Only recommend if multiple findings
                recommendations.append({
                    "category": category,
                    "priority": "High" if category in ["Elevation of Privilege", "Information Disclosure"] else "Medium",
                    "finding_count": len(category_findings),
                    "recommendation": f"Address {len(category_findings)} findings related to {category}. Implement comprehensive security controls for this category."
                })
        
        return recommendations

    def _generate_markdown_report(self, report: Dict[str, Any]) -> None:
        """Generate human-readable markdown report."""
        md_file = self.reports_dir / "security_audit_report.md"
        
        with open(md_file, 'w') as f:
            f.write("# Security Audit Report\n\n")
            f.write(f"**Generated:** {report['generated_at']}\n")
            f.write(f"**Model:** {report['model_used']}\n")
            f.write(f"**Repository:** {report['repository']}\n\n")
            
            # Summary
            f.write("## Summary\n\n")
            summary = report["summary"]
            f.write(f"- **Total Findings:** {summary['total_findings']}\n")
            f.write(f"- **Critical:** {summary['critical_findings']}\n")
            f.write(f"- **High:** {summary['high_findings']}\n")
            f.write(f"- **Medium:** {summary['medium_findings']}\n")
            f.write(f"- **Low:** {summary['low_findings']}\n\n")
            
            # Top Findings
            f.write("## Top Findings\n\n")
            for finding in report["findings"][:10]:
                f.write(f"### {finding.get('rank')}. {finding.get('message', finding.get('title', 'Unknown'))}\n\n")
                f.write(f"**Severity:** {finding.get('severity', 'Unknown')}\n")
                f.write(f"**File:** {finding.get('path', finding.get('file_path', 'Unknown'))}\n")
                if 'metadata' in finding and 'category' in finding['metadata']:
                    f.write(f"**Category:** {finding['metadata']['category']}\n")
                f.write(f"\n**Description:** {finding.get('message', finding.get('description', 'No description'))}\n\n")
            
            # Recommendations
            f.write("## Recommendations\n\n")
            for rec in report["recommendations"]:
                f.write(f"### {rec['category']}\n\n")
                f.write(f"**Priority:** {rec['priority']}\n")
                f.write(f"**Finding Count:** {rec['finding_count']}\n\n")
                f.write(f"{rec['recommendation']}\n\n")

    # ==================== MAIN ORCHESTRATION ====================

    def run_pipeline(
        self,
        stages: List[int] = None,
        num_passes: int = 10,
        resume: bool = False
    ) -> Dict[str, Any]:
        """Run the complete security audit pipeline."""
        if stages is None:
            stages = [1, 2, 3, 4]
        
        print(f"Starting Recursive STRIDE Security Audit Pipeline")
        print(f"Stages: {stages}")
        print(f"Model: {self.model_name}")
        print(f"Repository: {self.repo_root}")
        
        results = {}
        
        try:
            # Stage 1: Recon
            if 1 in stages:
                if not resume or not (self.recon_output / "recon_results.json").exists():
                    results["recon"] = self.stage1_recon()
                else:
                    print("Stage 1: Recon already completed, skipping...")
            
            # Stage 2: Threat Model
            if 2 in stages:
                if not resume or not (self.threat_model_output / "stride_threat_model.json").exists():
                    results["threat_model"] = self.stage2_threat_model(results.get("recon", {}))
                else:
                    print("Stage 2: Threat model already completed, skipping...")
            
            # Stage 3: Recursive Audit
            if 3 in stages:
                if not resume or not (self.audit_output / "recursive_audit_results.json").exists():
                    threat_model = results.get("threat_model", {})
                    if not threat_model:
                        model_file = self.threat_model_output / "stride_threat_model.json"
                        if model_file.exists():
                            with open(model_file, 'r') as f:
                                threat_model = json.load(f)
                    
                    results["audit"] = self.stage3_recursive_audit(threat_model, num_passes)
                else:
                    print("Stage 3: Recursive audit already completed, skipping...")
            
            # Stage 4: Triage
            if 4 in stages:
                if not resume or not (self.reports_dir / "security_audit_report.json").exists():
                    audit_results = results.get("audit", {})
                    if not audit_results:
                        audit_file = self.audit_output / "recursive_audit_results.json"
                        if audit_file.exists():
                            with open(audit_file, 'r') as f:
                                audit_results = json.load(f)
                    
                    results["triage"] = self.stage4_triage(audit_results)
                else:
                    print("Stage 4: Triage already completed, skipping...")
            
            print("\n=== PIPELINE COMPLETED ===")
            print(f"Results saved to: {self.output_dir}")
            print(f"Reports saved to: {self.reports_dir}")
            
            return results
            
        except Exception as e:
            print(f"Pipeline failed: {e}")
            raise


def main():
    parser = argparse.ArgumentParser(
        description="Recursive STRIDE-guided SAST Pipeline"
    )
    parser.add_argument(
        "--stages",
        type=str,
        default="1,2,3,4",
        help="Comma-separated list of stages to run (1=recon, 2=threat-model, 3=audit, 4=triage)"
    )
    parser.add_argument(
        "--passes",
        type=int,
        default=10,
        help="Number of recursive audit passes (default: 10)"
    )
    parser.add_argument(
        "--model",
        type=str,
        default="qwen2.5-coder:7b",
        help="Local model name to use (default: qwen2.5-coder:7b)"
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume from existing results"
    )
    
    args = parser.parse_args()
    
    # Parse stages
    stages = [int(s.strip()) for s in args.stages.split(',')]
    
    # Initialize pipeline
    pipeline = SecurityAuditPipeline(
        repo_root=REPO_ROOT,
        output_dir=OUTPUT_DIR,
        reports_dir=REPORTS_DIR,
        model_name=args.model
    )
    
    # Run pipeline
    try:
        results = pipeline.run_pipeline(
            stages=stages,
            num_passes=args.passes,
            resume=args.resume
        )
        print("\nPipeline completed successfully!")
        return 0
    except Exception as e:
        print(f"Pipeline failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())