# Vorsyghta Red-Team Suite Gap Analysis

**Date:** 2026-08-26

**Audited commit:** `444f4ad` (`master`, aligned with `origin/master` at audit time)

**Method:** Read-only execution-path and documentation review, followed by focused
unit/integration-style tests in the repository Poetry environment. No offensive
traffic was sent and no live target or tool server was exercised.

## Executive verdict

Vorsyghta has a credible standalone red-team execution engine, but the product is
not yet deployment-ready or audit-defensible as an integrated red/blue platform.
It remains split between:

1. A real standalone path (`vorsyghta red-team attack`) with LLM planning,
   deterministic fallback, command safety, rules-of-engagement checks, tool-server
   execution, persistence, evidence classification, and report generation.
2. A simulated exercise path (`ExerciseOrchestrator`) that produces prose attack
   stages and derives Blue-team detection outcomes from a deterministic hash.

The first path provides genuine component value. The second path must not be used
as measured detection assurance or customer-facing evidence.

## Capability status

| Capability | Status | Gap |
|---|---|---|
| AI planning and adaptation | Partial | Real planner, but weak schema/provenance checks and no `GuardrailsEngine` integration |
| Tool execution | Real but unsafe across all entry points | API and MCP routes bypass the canonical safety/ROE path |
| Rules of engagement | Partial | Standalone CLI checks target/time, but engagement administration lacks RBAC |
| Findings and reporting | Partial | Persisted reports exist; tool coverage and CVSS inference are narrow/heuristic |
| Sanctioned-target validation | Not operational end-to-end | Harness lacks a composed tool server, valid authorization flow, and automated ground truth |
| Red-to-Blue/Purple exercise | Simulated | Red stages are generated prose; Blue detection is hash-derived |
| Audit trail | Partial/in-memory | Exercise EventBus and default audit logger lack durable production persistence |
| Production isolation | Inadequate | Public unauthenticated tool-server deployment and target-scope parsing gaps |

## Deploy-blocking findings

### RT-C1: Execution paths bypass canonical command safety and ROE

The standalone orchestrator validates commands immediately before tool execution
(`vorsyghta/core/attack_orchestrator.py:973-1000`) and checks engagement scope
before a sequence runs (`:556-574`). Other production paths do not:

- `api/routers/attack_tracking.py:327-438` executes persisted commands directly
  through `ToolServerClient` without `VMSafetyController` or engagement approval.
- `api/routers/attack_tracking.py:656-689` accepts and executes a single arbitrary
  tool command with the same bypass.
- `mcp/server.py:64-80` instantiates a separate, weaker MCP safety controller.
- `mcp/tools/attack_tools.py:298,346,378,409,449,482-488` interpolates caller/LLM
  input into remote shell command strings.
- `mcp/tools/discovery_tools.py:1409-1414,1446` embeds input in generated Python
  and invokes a shell.

Impact: an authenticated or forged analyst request, or an MCP prompt-injection
path, can reach offensive tooling without the repository's canonical controls.

### RT-C2: Engagement approval is not a trustworthy authorization boundary

`api/routers/engagement.py:183-403` exposes creation, listing, approval, lifecycle,
target mutation, authorization checks, and export without route-level RBAC. The
router is mounted without a global auth dependency at `api/main.py:141-152`.

Engagement data is global plaintext JSON under `~/.vorsyghta/engagements`
(`research/engagement.py:318-329,439-444`) rather than tenant-bound durable
authorization records. The fallback JWT secret also remains at
`security/rbac.py:23`.

Impact: a caller can create and approve its own scope, and a default-key JWT can
be forged where deployment configuration does not override it correctly.

### RT-C3: Tool-server deployment exposes an offensive execution service

- `core/tool_server_client.py:31-32` defaults to a hard-coded public HTTP address.
- `docker/targets/tool_server.py:48-80` exposes execution without authentication.
- `scripts/azure_provision.sh:107-118` opens the execution port to any source.
- `scripts/azure_provision.sh:260` makes the Docker socket world-writable.
- `scripts/azure_provision.sh:266` contains a tracked Azure OpenAI credential.

The credential value is intentionally omitted from this report. Treat it as
compromised: rotate it immediately, purge it from Git history, and use Key Vault
or runtime secret injection. The tool server needs authenticated TLS, strict
network ingress, and enforceable egress to sanctioned targets only.

### RT-C4: The integrated exercise produces simulated assurance results

`core/exercise_orchestrator.py:204-230` invokes `Simulator`, not the real
`AttackOrchestrator`. `core/simulator.py:162-205` creates seven fixed stages and
marks generated/fallback content successful. Blue detection is calculated from
an MD5 bucket at `core/exercise_orchestrator.py:246-279`.

`api/routers/exercise.py:82-96` reports whether a real LLM generated content, but
does not carry the mandatory `simulation` provenance field promised by the
architecture. Exercise detection rates, AARs, and scores are therefore not
measured security outcomes.

## High-priority gaps

### RT-H1: Network-scope validation is bypassable

`vm/safety.py:250-292` ignores option tokens beginning with `-` and recognizes
only IPs, dotted DNS names, and `localhost`. A direct local probe found:

- `curl --url=http://evil.example/x` -> allowed
- `nmap evil` -> allowed

There is also no runtime verification of the
`com.vorsyghta.role: sanctioned-target` Docker label. Command-string blocklists
must not be the primary isolation boundary; argv-aware validation and network
egress policy are required.

### RT-H2: The sanctioned-target harness does not prove end-to-end operation

`scripts/run_sanctioned_target.sh:203-229` generates a CLI command without an
engagement ID or `--allow-unauthorized`, while `cli/red_team.py:350-360` refuses
that run. The CLI returns normally on several errors, allowing the harness to
print “Attack completed.”

No tool-server service is composed by the harness. A remote/container tool server
also cannot reach host-mapped Juice Shop through the supplied `localhost` target.
The documented ground-truth step (`run_sanctioned_target.sh:248-250`) is a manual
instruction rather than an automated recall measurement.

### RT-H3: Scenario and deterministic tool coverage do not align

The sanctioned scenario declares seven techniques
(`templates/sanctioned_targets/juice_shop_web_pentest.yaml:37-44`), while three
are absent from `MITRE_TO_TOOL_MAP` (`core/attack_orchestrator.py:92-151`) and are
silently skipped. Some deterministic templates expect a hostname but receive a
full URL, producing invalid `nmap` or double-scheme commands.

### RT-H4: LLM and evidence provenance controls are incomplete

`core/ai_planner.py:246-274` accepts any non-empty tool and command without
checking the allowed executable, target binding, MITRE format, or declared-tool
versus actual-command identity. Neither planner output nor target-controlled tool
output passes through `GuardrailsEngine`.

The report classifier trusts the claimed tool identity and supports only six
tools (`research/finding_classifier.py:307-315`). The orchestrator stores only the
first 2 KB of stdout for classification (`attack_orchestrator.py:1056-1064`).

### RT-H5: Persistence and audit evidence are not fail-closed

`core/tool_server_client.py:232-265` swallows tool-usage persistence failures.
Failed/unreachable runs do not consistently produce canonical result records.
Production creates `EventBus()` without a store (`api/routers/exercise.py:46`),
and the default audit logger starts with a memory sink
(`core/audit_logger.py:425-450`). This is insufficient for replayable compliance
evidence.

## Existing-document audit

### `BUSINESS_LOGIC_DEEP_DIVE_2026-08-16.md`

Directionally correct but stale. Its central “two parallel pipelines” diagnosis,
simulated exercise finding, hash-derived Blue detection, disconnected teams, and
unpersisted event-store findings remain valid. Its blanket conclusion that Red
Team does not work is outdated for the standalone CLI because later commits added
AI planning, ROE enforcement, command safety, lifecycle protection, persistence,
and client reports.

### `AUDIT_STATE_2026-08-16.md`

The red-team-relevant C1-C4 findings remain unresolved: fallback JWT key,
unauthenticated state-changing routes, MCP command injection, and crash-collection
script injection. Its “verified-good” characterization of authenticated attack
tracking is incomplete because those routes bypass safety and engagement scope.

### `docs/architecture/TEAM_ARCHITECTURE.md`

Internally contradictory. Lines 41-58 and 93-97 describe Red/Blue/Purple and
replayable persistence as implemented, while lines 203-214 correctly list removal
of the hash detector, real Blue integration, event-store wiring, and simulation
provenance as future milestones.

### README and pentest toolchain plan

The README overstates full-kill-chain adaptive capability and documents a harness
command that currently fails authorization. `docs/plans/pentest-toolchain-plan.md`
is the most accurate status document because it explicitly labels the toolbox as
“plan only,” but its claim that every command passes `VMSafetyController` is false
for the API and MCP routes.

## Validation performed

Environment:

- Python 3.12.13 in repository-local `.venv`
- Poetry 2.4.1
- pytest 9.0.3
- `python -m pip check`: no broken requirements

Focused command:

```text
poetry run pytest tests/unit/test_red_team.py \
  tests/unit/test_red_team_ai_consolidation.py \
  tests/unit/test_red_team_persistence_reporting.py -q --no-cov
```

Measured result: **84 passed in 1.88 seconds**.

A repository-wide collection check also completed successfully: **770 tests
collected with zero import/collection errors**.

This verifies the mocked red-team code paths and persistence/reporting tests. It
does not establish that the Docker tool server builds, that real offensive tools
are present, or that the Juice Shop harness works end-to-end; those boundaries are
faked in the tests.

## Remediation order

1. Rotate and purge the exposed credential; close public tool-server ports; add
   authenticated TLS and strict target-only egress.
2. Route every API, CLI, MCP, and agent execution through the canonical safety
   and engagement authorization boundary.
3. Add RBAC, tenant isolation, signed approval history, and durable storage to
   engagement administration; remove the fallback JWT secret.
4. Replace the simulated exercise Red/Blue path or force every result, score, and
   report to carry `simulation=true`.
5. Repair the existing sanctioned-target harness and compose the existing tool
   server internally with automated Juice Shop ground-truth scoring.
6. Add adversarial tests for option-attached URLs, bare hostnames, tool-name/argv
   mismatches, MCP injection, API authorization bypass, and tool-server egress.
7. Expand evidence parsers, preserve complete evidence securely, require analyst
   validation for client CVSS, and fail closed on persistence errors.
8. Reconcile the README, architecture, and historical audit documents with the
   actual implementation status.
