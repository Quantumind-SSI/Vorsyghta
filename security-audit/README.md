# Recursive STRIDE-Guided SAST Pipeline

A hybrid static-analysis methodology that chains four stages: automated recon, STRIDE threat modeling, recursive local-inference audit, and triage.

## Overview

This pipeline implements the "Recursive Prompting" methodology for security auditing:

1. **Recon** - Architecture diagrams, user-input flows, trust model, SBOM with Trivy audit
2. **STRIDE Threat Model** - Single local-model pass over recon artifacts  
3. **Recursive Audit Loop** - N passes with clean context + Semgrep pattern matching
4. **Triage** - Manual or frontier-model verification and ranking

## Design Principles

- **Deterministic tools handle what they're good at** - Trivy and Semgrep handle known-CVEs and pattern matches
- **Clean context is the fuzzing mechanism** - Each recursive pass uses a fresh context to produce variation
- **High false-positive rate in Stage 2 is expected** - The triage stage verifies and rejects noise
- **Recon and threat model are infrastructure** - They enable Stage 2, not outputs themselves

## Installation

### Prerequisites

```bash
# Install required tools
pip install semgrep trivy cyclonedx-bom

# Install local LLM (Ollama example)
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull qwen2.5-coder:7b
```

### Python Dependencies

```bash
cd security-audit
pip install -r requirements.txt
```

## Usage

### Run Complete Pipeline

```bash
# Run all 4 stages with 10 recursive passes
python pipeline.py --stages 1,2,3,4 --passes 10

# Run with specific model
python pipeline.py --stages 1,2,3,4 --passes 15 --model qwen2.5-coder:7b
```

### Run Individual Stages

```bash
# Stage 1: Generate recon artifacts
python pipeline.py --stage 1

# Stage 2: Create STRIDE threat model
python pipeline.py --stage 2

# Stage 3: Run recursive audit (5 passes)
python pipeline.py --stage 3 --passes 5

# Stage 4: Triage and generate report
python pipeline.py --stage 4
```

### Resume from Previous Run

```bash
# Resume pipeline, skipping completed stages
python pipeline.py --stages 1,2,3,4 --resume
```

## Output Structure

```
security-audit/
├── output/
│   ├── 01-recon/                 # Stage 1 recon artifacts
│   │   ├── architecture.json     # Component architecture
│   │   ├── user_flows.json      # Input flow analysis
│   │   ├── trust_model.json     # Trust boundaries
│   │   ├── sbom.json           # Software Bill of Materials
│   │   └── trivy_scan.json     # Vulnerability scan
│   ├── 02-threat-model/         # Stage 2 STRIDE analysis
│   │   └── stride_threat_model.json
│   ├── 03-recursive-audit/      # Stage 3 audit passes
│   │   ├── pass_001.json
│   │   ├── pass_002.json
│   │   └── ...
│   └── 04-triage/               # Stage 4 triage results
├── reports/
│   ├── security_audit_report.json  # Final detailed report
│   └── security_audit_report.md    # Human-readable summary
├── semgrep-rules/              # Generated Semgrep rules
│   └── stride-generated.yml
└── pipeline.py                 # Main pipeline script
```

## Pipeline Stages

### Stage 1: Recon

Generates ground truth about the system before any LLM reasoning:

- **Architecture diagrams** - Service/component boundaries
- **User-input-flow diagrams** - How untrusted data enters and moves
- **Trust model** - Where privilege changes occur
- **SBOM audit** - Known CVE detection via Trivy

### Stage 2: STRIDE Threat Model

Single local-model pass over recon artifacts:

- Analyzes each STRIDE category (Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation of Privilege)
- Maps threats to specific components/files
- Generates Semgrep rules for pattern matching
- Produces reusable template for Stage 3

### Stage 3: Recursive Audit Loop

Multiple passes with clean context per pass:

- **Local LLM** (e.g., Qwen 3.6 Heretic) called N times
- **Semgrep** runs alongside with rules from threat model
- Each pass analyzes different components (clean context)
- High recall, high noise by design
- Expect hundreds-thousands of candidates

### Stage 4: Triage

Collapses candidate pool into verified findings:

- **Deduplication** - Removes duplicate findings across passes
- **Verification** - Confirms reachability and exploitability
- **Ranking** - Prioritizes by severity and impact
- **Reporting** - Generates both JSON and markdown reports

## Configuration

### Local Model Integration

The pipeline uses a placeholder `_call_local_llm()` method. To integrate with your preferred local model:

1. **Ollama Integration:**
```python
def _call_local_llm(self, prompt: str, task_type: str) -> Dict[str, Any]:
    import requests
    response = requests.post(
        "http://localhost:11434/api/generate",
        json={
            "model": self.model_name,
            "prompt": prompt,
            "format": "json"
        }
    )
    return json.loads(response.json()["response"])
```

2. **LM Studio Integration:**
```python
def _call_local_llm(self, prompt: str, task_type: str) -> Dict[str, Any]:
    import requests
    response = requests.post(
        "http://localhost:1234/v1/chat/completions",
        json={
            "model": self.model_name,
            "messages": [{"role": "user", "content": prompt}],
            "response_format": {"type": "json_object"}
        }
    )
    return json.loads(response.json()["choices"][0]["message"]["content"])
```

### Semgrep Rules

Custom Semgrep rules are generated from the STRIDE threat model and saved to `semgrep-rules/stride-generated.yml`. You can:

- Add custom rules to this directory
- Modify the `_create_pattern_for_threat()` method for better pattern generation
- Use existing Semgrep rule packs alongside generated rules

## Performance Tuning

### Number of Passes

- **10-15 passes** - Good balance for most codebases
- **20+ passes** - For large, complex systems
- **Monitor new-findings-per-pass** and stop at diminishing returns

### Chunking Strategy

The pipeline uses component-based chunking for clean context. Modify `_get_random_components_for_pass()` to:

- Use file-based chunking for better cross-file coverage
- Implement dependency-aware chunking
- Add custom chunking strategies for your codebase

### Cost Optimization

- Local models keep costs low vs. cloud APIs
- Semgrep provides fast deterministic filtering
- Triage can use frontier models sparingly for verification only

## Known Limitations

- **Recall bounded by local model quality** - Better models = better findings
- **Chunking affects cross-file coverage** - May miss multi-file vulnerabilities
- **Semgrep rules need periodic tuning** - Update based on new threat patterns
- **Can miss subtle business logic bugs** - Complement with manual review

## Troubleshooting

### Common Issues

1. **"No local model available"**
   - Ensure your local LLM service is running
   - Check model name and endpoint configuration

2. **"Semgrep not found"**
   - Install Semgrep: `pip install semgrep`
   - Check PATH configuration

3. **"Trivy scan failed"**
   - Install Trivy: `curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin`
   - Ensure Docker is available for container scanning

4. **"High memory usage"**
   - Reduce number of concurrent passes
   - Use smaller context windows
   - Implement result streaming

### Debug Mode

Run with verbose output:
```bash
python pipeline.py --stages 1,2,3,4 --verbose
```

Check intermediate results:
```bash
# View recon artifacts
cat output/01-recon/architecture.json

# View threat model
cat output/02-threat-model/stride_threat_model.json

# View specific audit pass
cat output/03-recursive-audit/pass_001.json
```

## Contributing

To extend the pipeline:

1. **Add new recon modules** - Implement in `_generate_*()` methods
2. **Improve threat modeling** - Modify `_create_stride_prompt()` templates
3. **Enhance LLM integration** - Update `_call_local_llm()` for your model
4. **Better triage** - Implement advanced deduplication in `_verify_and_deduplicate()`

## License

This security audit pipeline is part of the Ciicerone project. See the main project license for details.