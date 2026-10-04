# Vorsyghta — Full Application Audit (Current State)

> **Platform scope.** This audit is measured against Vorsyghta's **seven-capability target** — see **[README § Platform scope — the full target](../README.md#platform-scope--the-full-target)**.

**Date:** 2026-08-16
**Auditor:** Automated + manual review (OpenCode)
**Commit:** `0495391` (All the changes left for Vorsyghta)
**Scope:** Full audit — security, architecture, dependencies, containers, quality.

---

## 1. Snapshot

| Metric | Value |
|---|---|
| Lines of Python | ~103,575 |
| Python files | 264 |
| Top-level modules | 24 (core, cli, llm, api, mcp, analytics, rag, intelligence, security, research, defense, datasets, feedback, vm, db, client_data, integrations, quantum, deployment, config, safety, utils) |
| Stack | FastAPI, async SQLAlchemy 2.x, Alembic, Pydantic v2, MCP, OpenAI/Anthropic, Redis, Postgres |
| Test files / tests | 18 files / 253 tests (12 collection errors; pytest.ini broken) |

### Automated tool results
- **ruff:** 1,032 findings (299 unused imports, 282 long lines, 106 raise-without-from, 44 unused vars, 29 swallowed excepts, etc.)
- **bandit:** 134 issues — 2 HIGH, 44 MEDIUM, 88 LOW
- **pip-audit:** 1 CVE — `ecdsa 0.19.2` PYSEC-2026-1325 (Minerva timing attack, upstream won't-fix)

---

## 2. Findings by severity

### CRITICAL (deploy-blocking)
- **C1 — Hardcoded fallback JWT signing key** · `vorsyghta/security/rbac.py:23`
  `SECRET_KEY = os.getenv("VORSYGHTA_SECRET_KEY", "changeme-replace-in-production-with-256bit-secret")`.
  Only enforced when `ENVIRONMENT=production`; otherwise anyone can forge admin JWTs. Fix: fail-closed at startup, no default.
- **C2 — Unauthenticated state-changing routers** · `api/main.py:142-152`
  `disclosure.py`, `knowledge.py`, `manuals.py`, `feedback.py`, `threat_hunting.py`, `engagement.py` have no auth dependency. World-accessible CRUD; `GET /disclosures/{id}/export` leaks PoC data. Fix: `dependencies=[Depends(require_analyst)]`.
- **C3 — Command injection in MCP attack tools** · `mcp/tools/attack_tools.py:298,346,378,409,449,482`
  LLM-controlled args f-string-interpolated into shell commands, no quoting, no `validate_command()`. RCE via `extra_args="; id #"`. Fix: `shlex.quote()` + argv.
- **C4 — Script-injection in crash-collect** · `mcp/tools/discovery_tools.py:1412-1414,1446`
  LLM args baked raw into generated Python script; safety check validates the wrong string; `shell=True` present. Fix: `json.dumps()` + drop shell.

### HIGH
- **H1 — No rate limiting** on any endpoint incl. `/auth/token`, `/auth/register`.
- **H2 — Unquoted extra_args/format/language tokens** in `discovery_tools.py:775,836,1116,1152,1210,1280`.
- **H3 — Path traversal** · `api/routers/templates.py:184`, `knowledge.py:294`. `validate_file_path` helper exists but unused.
- **H4 — Blocklist-based safety is bypassable** · `mcp/safety/controller.py:99` (misses `;`, `&&`, `|`, `>`, `${IFS}`, spacing).

### MEDIUM
- **M1 — Weak MD5 for security** (bandit HIGH) · `core/exercise_orchestrator.py:273`, `defense/blue_team/forensics.py:306`.
- **M2 — CORS** `allow_credentials=True` + `allow_methods/headers=["*"]` · `api/main.py:130`.
- **M3 — Weak default secrets** in `docker-compose.attack.yml:22,28,29` (`:-` not `:?`); seed pw `Analyst123!` in `db/seed.py:47`.
- **M4 — Token TTL 8h**, no refresh/revocation; no `iss`/`aud` check · `rbac.py:25,98`.
- **M5 — SSRF**: `attack_curl`/gobuster/nuclei skip `validate_network` · `attack_tools.py:362+`.
- **M6 — Verbose error leakage** `detail=f"...{str(e)}"` · `api/main.py:375,473`.

### LOW / Quality
- `ecdsa` CVE (via `python-jose`); prefer `pyjwt` (already a dep).
- All 41 deps use floating `>=` (no `==` pins) in `requirements.txt` → non-reproducible builds.
- 12 pytest collection errors + broken `pytest.ini` (`asyncio_mode` crashes pytest).
- F821 undefined name `PlatformIntegrationManager` · `api/routers/integrations.py:46`.
- Dockerfile installs full dev deps into runtime image (`Dockerfile:29`).

### Verified-good controls
- Secret-manager provider chain (Vault/Azure/AWS/env); DB-URL password masking; bcrypt+salt.
- Self-registration privilege escalation closed (role forced to `viewer`).
- `attack_tracking` command exec auth-gated + audit-logged; `secrets`/`exercise`/`threat_intel` use RBAC.
- Main `docker-compose.yml` fail-closes secrets with `:?`.
- `yaml_loader` uses SafeLoader (bandit B506 false positive).

---

## 3. Recommended fix order
1. C1 JWT fail-closed key
2. C2 auth on 6 routers
3. C3/C4 shlex.quote/argv + json.dumps in MCP tools
4. H1 rate limiting, H3 path containment
5. Fix pytest.ini; then M/L items.

---

*Business-logic deep dive tracked separately in `BUSINESS_LOGIC_DEEP_DIVE_2026-08-16.md`.*
