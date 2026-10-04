# Vorsyghta Frontend Product and Engineering Scope

> **Platform scope.** This document defines **capability #5 of seven** in Vorsyghta's full scope: the commercial SaaS product (Next.js app, Stripe trial, engagements→assessments→findings→reports). See the canonical statement in **[README § Platform scope — the full target](../../README.md#platform-scope--the-full-target)**.

Status: Approved for foundational implementation

Last updated: 2026-09-14

Owners: Product, Frontend, Backend, Security, Compliance

## 1. Purpose

This document is the source of truth for the public website, authenticated web
application, self-service trial, and billing experience for Vorsyghta. It
replaces the previous broad dashboard plan with a staged product that reflects
the capabilities and limitations of the current repository.

The first release is an evidence-first interface for authorized security
validation. It is not a generic cyber dashboard and it does not expose every
CLI or internal engine through a browser.

The primary customer journey is:

`Define scope -> approve engagement -> configure assessment -> execute safely -> inspect evidence -> validate findings -> publish report`

The public conversion journey is:

`Landing page -> create account -> register payment method -> 14-day trial -> guided application -> paid Team subscription`

## 2. Product Positioning

### 2.1 Category

Vorsyghta is an evidence-first platform for authorized security assessments
and coordinated cyber operations.

### 2.2 Core message

Primary headline:

> Run authorized security validation. Keep the evidence.

Supporting statement:

> Vorsyghta helps security teams scope, execute, observe, and report controlled
> adversarial assessments with human approval and explicit result provenance.

### 2.3 Primary audiences

| Persona | Primary need |
|---|---|
| CISO and security leader | Current, defensible evidence of control performance |
| Red-team lead | Authorized scope, bounded execution, evidence, and findings |
| Security analyst | Repeatable assessments and technical result review |
| Pilot sponsor | Approval, risk oversight, and executive reporting |
| External client reviewer | Read-only access to approved reports |
| Platform administrator | Identity, integration, health, and deployment controls |

Regulated organizations are the initial market emphasis. Financial services is
the first vertical supported by existing scenarios and sales material.

### 2.4 Product promise

Every customer-visible result must identify its provenance. The interface must
distinguish these states:

- Measured by a named tool or data source
- Simulated by a deterministic scenario
- Generated or summarized by an AI model
- Produced by a deterministic fallback
- Validated by an analyst
- Unavailable because a dependency failed

AI-generated prose is not evidence that an attack, detection, or remediation
occurred.

## 3. Current Repository Reality

### 3.1 Existing assets

- FastAPI is the current backend application in `vorsyghta/api/main.py`.
- This change adds the foundational Next.js application in `frontend/`, with
  public pages, registration, sign-in, a read-only workspace, and billing UI.
- This change adds the Stripe billing projection, hosted Checkout and Portal
  integration, signed webhook reconciliation, and API entitlement dependency.
- JWT authentication and four roles exist in `vorsyghta/security/rbac.py`.
- Tenant and user records exist in `vorsyghta/db/models/auth.py`; foundation
  registration now creates a dedicated tenant and owner identity atomically.
- Attack tracking and threat intelligence have the strongest database-backed
  API surfaces.
- The canonical safe offensive path is
  `vorsyghta/core/attack_orchestrator.py` with
  `vorsyghta/vm/safety.py` and engagement authorization.
- A design reference exists in `design-md/sentry/DESIGN.md`.
- A historical Vite dashboard exists in Git history but was never merged and
  does not match current API contracts.

### 3.2 Material gaps

- The frontend and billing foundation exists in this uncommitted change, but it
  is not a production launch declaration and every gate in Section 17 still
  requires measured sign-off.
- Generic staging ingress, TLS, secret delivery, Stripe endpoint registration,
  backup and restore, and release automation are not yet provided.
- Main-app product routers now require authenticated entitlement, but several
  legacy storage layers still require tenant-scoped persistence before launch.
- Several workflows store state in process memory while production uses
  multiple API workers.
- No browser-facing SSE or WebSocket transport exists.
- The direct attack-tracking execution API bypasses the canonical engagement
  and command-safety path.
- The integrated color-team exercise includes simulated Red and Blue outcomes.
- The current logo is branded ThreatSimGPT rather than Vorsyghta.

### 3.3 Security incident containment

Commit `6165b26` introduced an obfuscated Node program disguised as
`public/fonts/fa-solid-400.woff2` and a hidden VS Code task configured to run it
when the folder opened. The compromised `.vscode` and `public/fonts` bundles
must remain deleted. The payload SHA-256 was:

`9e286f7a54f071e5a4e9f09de84abca872d8347cbb7059c966c7db54a7e4dcba`

Public deployment is blocked until repository provenance and potentially
affected developer machines have been reviewed.

## 4. Product Principles

1. Evidence before assertion.
2. Authorization before execution.
3. Tenant isolation is enforced by the backend, never by hidden navigation.
4. Billing entitlement, user permission, and engagement authorization are
   separate decisions and all applicable checks must pass.
5. No fake metrics, findings, activity, testimonials, or screenshots.
6. Dangerous operations are not exposed until they use the canonical safety
   path.
7. Missing data is displayed as unavailable, not as zero.
8. Public claims must be traceable to implemented and tested behavior.
9. The web application remains usable on desktop and mobile, while complex
   operational workflows are optimized for desktop.
10. Card data never enters Vorsyghta infrastructure.

## 5. Public Website Scope

### 5.1 Sitemap

| Route | Purpose |
|---|---|
| `/` | Primary product landing page |
| `/pricing` | Team trial and enterprise contact options |
| `/security` | Security model and trust boundaries |
| `/responsible-use` | Authorized-use and sanctioned-target policy |
| `/deployment` | Hosted and self-hosted deployment choices |
| `/contact` | Sales and pilot contact |
| `/sign-in` | Existing-user authentication |
| `/start-trial` | Authenticated trial checkout entry |
| `/legal/privacy` | Privacy notice |
| `/legal/terms` | Terms of service and trial terms |
| `/legal/acceptable-use` | Acceptable-use policy |
| `/docs` | Documentation entry or redirect |

### 5.2 Landing page composition

| Section | Required content |
|---|---|
| Header | Product, Use Cases, Security, Deployment, Pricing, Docs, Sign In |
| Hero | Clear outcome, bounded claim, Request Demo and Start Trial actions |
| Trust strip | Self-hosting, local model option, MITRE mapping, open core |
| Problem | Point-in-time tests and fragmented tools lose evidence and context |
| Operating loop | Scope, authorize, execute, observe, improve |
| Core workflows | Assessment, defensive validation, findings, reporting, intelligence |
| Evidence view | Real or explicitly labeled sample provenance and timeline |
| Use cases | Red team, security leadership, SOC, research, regulated enterprise |
| Deployment | Data boundary, model provider, and egress choices |
| Responsible use | Sanctioned targets, human approval, safety checks, auditability |
| Pricing | Team trial plus Enterprise and Mission contact options |
| Final action | Start Trial, Request Demo, View on GitHub |
| Footer | Legal, security, support, documentation, license, status |

### 5.3 Marketing claim rules

The website may state that Vorsyghta:

- Supports authorized security validation
- Maps activity to MITRE ATT&CK
- Generates structured findings and reports
- Supports self-hosting and local model providers
- Includes engagement, command-safety, RBAC, SSO, secret, and audit primitives
- Supports evidence collection and compliance mapping

The website must not currently claim:

- Every result is measured
- Fully autonomous live Red-versus-Blue validation
- Immutable audit evidence
- Guaranteed legal or regulatory compliance
- Zero data egress by default
- Production-ready security
- Guaranteed zero-day discovery

## 6. Trial and Billing Scope

### 6.1 Commercial model

| Tier | Acquisition path | Billing model |
|---|---|---|
| Team | Self-service 14-day trial | Stripe recurring subscription |
| Enterprise | Request demo | Sales-assisted contract |
| Mission | Request demo | Sales-assisted contract |

The exact Team amount, currency, cadence, taxes, and renewal date are read from
an active Stripe Price and displayed before checkout. The application never
invents or hard-codes a public price.

### 6.2 Billing authority

Stripe Billing is the only subscription, invoice, trial, and payment authority.
PostgreSQL stores a local entitlement projection for reliable authorization and
audit. A browser redirect never activates access.

OnePay UK is not a separate merchant gateway. OnePay-issued Mastercard cards
are submitted through Stripe's standard card rail. Acceptance remains subject
to Stripe, Mastercard, issuer controls, available balance, Strong Customer
Authentication, and risk rules.

### 6.3 Trial journey

1. The customer chooses the Team trial.
2. The customer creates and verifies an account.
3. The customer supplies organization and workspace details.
4. The backend creates a pending tenant, owner, and billing record atomically.
5. The authenticated owner starts Stripe-hosted Checkout.
6. Stripe collects a card and performs required authentication.
7. A signed Stripe webhook confirms the subscription and trial state.
8. The backend grants a 14-day entitlement and records trial consumption.
9. The customer enters the guided trial application.
10. Stripe attempts the first recurring charge when the trial ends.
11. Cancellation or failed payment updates local access through verified events.

### 6.4 Payment screen requirements

- Heading: `Start your 14-day Team trial`
- Zero amount due today
- Exact renewal amount, currency, cadence, and date
- Team entitlements and trial limits
- Stripe-hosted card collection
- Cardholder and billing-address collection
- Tax identification when applicable
- Automatic-renewal disclosure
- Terms, privacy, acceptable-use, and refund links
- Primary action: `Start 14-day free trial`
- Clear cancellation deadline
- Processing, decline, authentication, network, cancellation, and success states

No card number, security code, or magnetic-stripe data may pass through the
Vorsyghta browser server, FastAPI server, logs, analytics, or database.

### 6.5 Trial entitlements

The trial includes only capabilities that are implemented, tenant-safe, and
authorized:

- Template and scenario browsing
- Sanctioned-target assessment setup
- Dry-run and preflight validation
- Bounded Juice Shop lab assessments after safe job APIs are available
- Assessment progress from durable events
- Measured or explicitly simulated result views
- Findings and evidence review
- AAR and vulnerability-report viewing
- CVE and CISA KEV intelligence
- MITRE ATT&CK mappings
- Guided product walkthrough
- Secure report export when artifact APIs are available

The trial excludes:

- Production or external targets
- Arbitrary command execution
- VM provisioning and GUI control
- Raw secret access
- Production phishing delivery
- External SIEM, EDR, and cloud integrations
- Autonomous agent steering
- Client-data ingestion
- Enterprise identity administration
- Mission-tier research capabilities

Usage limits are server-side entitlements. They cover users, assessment runs,
concurrent jobs, storage, exports, and LLM consumption.

### 6.6 Subscription states

| State | Product access |
|---|---|
| `checkout_pending` | Billing and support only |
| `trialing` | Yes until the entitlement boundary |
| `active` | Yes until the paid entitlement boundary |
| `incomplete` | No |
| `incomplete_expired` | No |
| `past_due` | No under the initial strict policy |
| `unpaid` | No |
| `paused` | No |
| `canceled` | No after the entitlement boundary |
| `unknown` | No |

The administrative tenant switch remains independent. A Stripe event must not
reactivate an administratively suspended tenant.

### 6.7 Billing notifications

- Trial started
- Seven days remaining
- Twenty-four hours remaining
- Trial canceled
- Subscription activated
- Payment succeeded
- Payment failed or requires action
- Subscription canceled
- Data-retention deadline

Every message includes the exact amount, currency, relevant date, account link,
and cancellation route where applicable.

## 7. Authenticated Application Scope

### 7.1 Primary navigation

1. Overview
2. Engagements
3. Assessments
4. Findings
5. Reports
6. Intelligence
7. Environments
8. Administration

The first release does not create separate navigation areas for all color
teams. Team attribution belongs in events and reports.

### 7.2 Route inventory

| Route | Purpose | Release |
|---|---|---|
| `/app` | Tenant, trial, health, and recent recorded activity | Foundation |
| `/app/settings/billing` | Subscription, trial, invoices, payment management | Foundation |
| `/app/engagements` | Tenant-scoped engagement list | Operational MVP |
| `/app/engagements/new` | Scope and rules-of-engagement wizard | Operational MVP |
| `/app/engagements/:id` | Scope review, approval, pause, completion | Operational MVP |
| `/app/assessments` | Assessment inventory | Operational MVP |
| `/app/assessments/new` | Approved engagement, template, target, preflight | Operational MVP |
| `/app/assessments/:id` | Durable progress, evidence, failures, safe stop | Operational MVP |
| `/app/findings` | Searchable findings register | Operational MVP |
| `/app/findings/:id` | Evidence, CWE, CVSS, remediation, validation | Operational MVP |
| `/app/reports` | Executive, technical, AAR, and vulnerability reports | Operational MVP |
| `/app/reports/:id` | Approved report viewer and secure exports | Operational MVP |
| `/app/intelligence` | CVE, KEV, actor, campaign, indicator, and TTP data | Operational MVP |
| `/app/environments` | Connected-environment hub (containers, cloud, files, web apps & APIs, external infrastructure, images, media) | Operational MVP |
| `/app/environments/new` | Adapter selection and credential flow for a new environment connection | Operational MVP |
| `/app/environments/:id` | Connection health, sync history, ingested inventory, rotation/revocation | Operational MVP |
| `/app/audit` | Tenant-scoped audit event viewer | Operational MVP |
| `/app/admin/system` | Service and dependency health | Administration |
| `/app/admin/integrations` | Integration status without raw secrets | Administration |
| `/app/admin/users` | Tenant users and roles | Administration |

### 7.3 Foundation application behavior

The first engineering slice is deliberately read-only after billing activation.
It provides:

- Authenticated identity and tenant display
- Trial and subscription state
- Remaining trial time
- Stripe customer portal access
- Real health status
- Tenant-scoped attack sequence and tool-usage counts
- Recent recorded tool activity
- Explicit empty and unavailable states

It does not expose engagement approval, attack execution, arbitrary commands,
exercise scorecards, or simulated assurance data.

### 7.4 Operational workflow

1. An analyst drafts an engagement and defines targets and exclusions.
2. A pilot sponsor reviews and approves the rules of engagement.
3. The analyst creates an assessment under an approved engagement.
4. Preflight verifies target, testing window, data handling, provider, and safety.
5. The backend creates a durable job and returns immediately.
6. The browser receives progress through authenticated SSE.
7. Findings enter analyst review rather than automatic confirmation.
8. Approved findings produce executive and technical reports.
9. A viewer receives only approved and redacted report content.

### 7.5 Roles

| Backend role | Product label | Access |
|---|---|---|
| `viewer` | Report Viewer | Approved reports and permitted results |
| `analyst` | Security Operator | Drafts, assessments, evidence, findings |
| `pilot_sponsor` | Approver | Scope approval and engagement lifecycle |
| `admin` | Administrator | Tenant identity, integrations, and health |

Role-based access, paid entitlement, tenant status, and engagement authorization are
independent server-side checks.

### 7.6 MVP screen plan (operational release)

The MVP is planned in two tiers against the verified backend reality, not against
aspiration. **Tier A** screens are buildable on endpoints that ship today and need no new
backend contracts. **Tier B** screens are blocked on the durable job model (§11.5); they are
planned now so the backend work and the screens land together. Every screen honours §8
(evidence/safety UX) and §9.2 (interaction states); no screen exposes arbitrary command
input, VM/GUI control, raw secret values, or exercise scorecards presented as measured
assurance.

#### 7.6.1 Screen inventory

| # | Screen | Route | Tier | Role | Primary data source | Backend gate |
|---|---|---|---|---|---|---|
| 1 | Landing | `/` | Public | — | static | — |
| 2 | Pricing | `/pricing` | Public | — | `GET /api/billing/offer` | none |
| 3 | Sign in | `/sign-in` | Public | — | `POST /api/auth/token` | none |
| 4 | Register | `/register` | Public | — | `POST /api/auth/register` | none |
| 5 | Trial checkout | `/start-trial` | Public→auth | billing owner | `POST /api/billing/checkout-session` | none |
| 6 | Privacy / terms / acceptable use | `/legal/privacy`, `/legal/terms`, `/legal/acceptable-use` | Public | — | static | **missing routes — build** |
| 7 | Workspace overview | `/app` | Foundation | viewer+ | `/health`, `/api/billing/status`, attack-tracking counts, recent tool usage | none (shipped) |
| 8 | Billing settings | `/app/settings/billing` | Foundation | billing owner | `GET /api/billing/status`, `POST /api/billing/portal-session` | none (shipped) |
| 9 | Threat intelligence | `/app/intelligence` | **MVP (Tier A)** | viewer+ (read) | threat-intel router: CVE search, CISA KEV, actors, campaigns, indicators, TTPs | none — endpoints are live and tenant-scoped |
| 10 | Scenario templates | `/app/templates`, `/app/templates/:id` | **MVP (Tier A)** | viewer+ (read) | templates router (list, detail, validate) | none — browse and preview only, no execution |
| 11 | Audit events | `/app/audit` | **MVP (Tier A)** | analyst+ | `GET /audit/events` | **tenant filtering** — endpoint is currently global |
| 12 | Findings register | `/app/findings`, `/app/findings/:id` | **MVP (Tier A, read-only)** | viewer+ / analyst | attack-tracking DB records (sequences, step reports, classified CWE/CVSS) | none for read-only; durable-events upgrade is Tier B |
| 13 | Engagements list | `/app/engagements` | **MVP (Tier B)** | analyst, approver, admin | durable engagement records | **durable tenant-bound storage + route RBAC** (today: global plaintext JSON files, no route-level auth) |
| 14 | Engagement wizard | `/app/engagements/new` | **MVP (Tier B)** | analyst | same + RoE template | same + signed approval history |
| 15 | Engagement detail | `/app/engagements/:id` | **MVP (Tier B)** | approver (approve/pause), analyst (read) | same | same |
| 16 | Assessment wizard | `/app/assessments/new` | **MVP (Tier B)** | analyst | approved engagement + template + target + preflight | **durable job model + canonical safety path** |
| 17 | Assessment detail | `/app/assessments/:id` | **MVP (Tier B)** | analyst | durable job events via authenticated SSE | **SSE transport + durable events + safe stop** |
| 18 | Assessments list | `/app/assessments` | **MVP (Tier B)** | analyst | durable job records | same as 16 |
| 19 | Reports list | `/app/reports` | **MVP (Tier B)** | viewer+ | durable report artifacts | **durable artifact records** |
| 20 | Report viewer | `/app/reports/:id` | **MVP (Tier B)** | viewer+ (redacted), analyst (full) | same + approval state | **approval workflow + short-lived authorized exports** |
| 21 | Admin: system | `/app/admin/system` | Administration | admin | `/health`, `/ready`, dependency probes | admin role |
| 22 | Admin: integrations | `/app/admin/integrations` | Administration | admin | integrations status | admin role; **must not use `GET /api/secrets/{name}` (returns raw values)** |
| 23 | Admin: users | `/app/admin/users` | Administration | admin | tenant users + roles | admin role; no cross-tenant listing |
| 24 | Environments hub | `/app/environments` | **MVP (Tier A, connect/read)** | analyst+, admin (manage) | `client-data` adapter registry + durable connection records | **durable tenant-bound connection storage** (today: config/env only) |
| 25 | Connect environment wizard | `/app/environments/new` | **MVP (Tier B)** | admin | adapter-specific credential flow | **secret-manager write path + validated credential test** |
| 26 | Environment detail | `/app/environments/:id` | **MVP (Tier B)** | admin (manage), analyst (read) | connection health, sync state, ingested inventory | **credential rotation + sync job model** |

#### 7.6.2 Tier A screen specifications (buildable today)

**9 — Threat intelligence (`/app/intelligence`).**
- Content: tab strip (CVE search · CISA KEV · Actors · Campaigns · Indicators · TTPs), per-tab counts, search with technique/CVSS filters, KEV staleness chip (upstream cache TTL 1 hour), per-record detail drawer.
- Data: threat-intel router (tenant-scoped, DB-backed, live NVD + CISA KEV feeds).
- States: per-tab loading / precise empty / error / stale; read-only (no hunt authoring — Tier B).
- Gate: none beyond entitlement. This is the highest-value Tier A screen: the feeds are real.

**10 — Scenario templates (`/app/templates`).**
- Content: filterable list (threat type, severity, target role), detail page with scenario parameters, safety flags, and validation result; "validate-all" bulk action.
- Data: templates router. Execution is excluded — the screen never runs a scenario.
- States: loading / empty / error; validation failure shown per template, never as success.

**11 — Audit events (`/app/audit`).**
- Content: filterable event table (category, severity, correlation id, actor, timestamp), hash-chain integrity chip, event detail expansion.
- Data: `GET /audit/events` (analyst+).
- Gate: the endpoint must gain server-side tenant filtering before this screen ships; until then the screen is not built.

**12 — Findings register (`/app/findings`).**
- Content: searchable register of recorded attack sequences and step reports — tool, technique, CWE, CVSS baseline, evidence summary, provenance chip per record.
- Data: attack-tracking DB records (read-only). No finding confirmation, editing, or validation state changes in Tier A.
- Upgrade (Tier B): re-source from durable events; add analyst validation workflow (§7.4 step 7).

**6 — Legal routes.** Three static pages plus the existing `legal-links` component targets. Required before trial traffic (§17 gate 11).

**24 — Environments hub (`/app/environments`).**
- Content: adapter-category grid matching the ingestion surface the codebase already implements, per-connection health and last-sync state, ingested-inventory counts, and an explicit "connect a new environment" action.
- Adapter categories (derived from `vorsyghta/client_data/sources/`, not invented):
  - **Containers** — Docker/compose cluster connections; container images as assessable artifacts.
  - **Cloud** — AWS S3, Azure Blob, GCP GCS storage; account structure, IAM policies, security groups, VPC/VNet topology, compute, Kubernetes (EKS/AKS/GKE), serverless, API gateway, logging, secrets, CDN/WAF.
  - **Files** — OneDrive, SharePoint, Google Drive document inventories (policies, architecture diagrams, configs).
  - **Web apps & APIs** — GenericApiSource REST/GraphQL endpoints, OpenAPI/Swagger specs, webhook endpoint inventories.
  - **External infrastructure** — GNS3 network topology exports (nodes, links, subnets), firewall/router/DNS/VPN configuration exports, asset inventories, exposed-service lists.
  - **Directories / CRM** — Microsoft 365, Entra ID, Salesforce, HubSpot, Google Workspace employee/org data (feeds Pillar 2 OSINT enrichment).
  - **Media & other formats** — container images, VM images, packet captures, forensic artifacts, and any additional adapter registered against the `ClientDataSource` base class; the grid renders unknown/unregistered media as an explicit "adapter not available" state, never as a silent gap.
- Data: the client-data adapter registry; connections and credentials live in durable tenant-bound storage (backend prerequisite below). No credential value is ever displayed, logged, or round-tripped through the browser.
- States: per-connection connected / connecting / degraded / auth-failed / expired; per-category empty state; credential-test result; revocation confirmation.
- Gate: durable tenant-bound connection records. Today connections exist only as config/env state — the screen is not built until connections are persisted with tenant isolation.

**25 — Connect environment wizard (`/app/environments/new`).**
- Content: adapter selection → category-specific credential flow (cloud keys, OAuth device/consent flows for M365/Drive/CRM, SSH/key material for infrastructure, registry credentials for images) → scope of what may be ingested → validated connection test → confirmation.
- Data: adapter-specific credential flows through the secret-manager chain (Vault → Azure KeyVault → AWS SM → env); the browser never receives a credential value.
- Gate: a secret-manager write path plus a validated credential test. Connection must fail closed on an invalid test — never stored as connected.

**26 — Environment detail (`/app/environments/:id`).**
- Content: connection health and credentials metadata (never values), sync history, ingested inventory (assets, subnets, services, documents, images), ingestion scope, rotation and revocation controls.
- Data: credential rotation via the secret-manager; sync via the durable job model.
- Gate: credential rotation + sync job model. Sync runs as a durable job with the same progress/SSE/failure contract as assessments (§11.5).

#### 7.6.3 Tier B screen specifications (blocked on the durable job model)

**13–15 — Engagement lifecycle.**
- List: tenant-scoped engagements with status (`draft → pending_approval → approved → active → paused → completed`), approver, window.
- Wizard (`/new`): targets and exclusions editor, method allowlist, prohibited techniques, time window, data handling, RoE summary; submit for approval.
- Detail: scope review, approve/pause/complete (approver role), signed approval history, linked assessments.
- Gate: durable tenant-bound engagement records with route-level RBAC and signed approval history. The current global plaintext-JSON engagement store and unauthenticated router are disqualifying.

**16–18 — Assessments.**
- Wizard (`/new`): requires an approved engagement; selects template, target, preflight checks (target in scope, testing window, data handling, provider, safety); creates a durable job and returns immediately.
- Detail: durable progress (phase, timestamps, typed failures) over authenticated SSE, evidence links, emergency stop.
- Gate: durable job model + SSE + canonical orchestration through engagement and command-safety checks. The direct attack-tracking execution API is unexposed in SaaS mode and must not become the transport.

**19–20 — Reports.**
- List: executive, technical, AAR, and vulnerability reports with approval state.
- Viewer: analysts see full content; viewers see approved, redacted content only. Exports are short-lived, authorized, and tenant-scoped.
- Gate: durable report artifacts, an approval workflow, and secure download endpoints.

**21–23 — Administration.**
- System: real health and dependency probes; failures display unavailable, not zero.
- Integrations: status without raw secrets — the raw-secret endpoint is excluded from the UI by design.
- Users: tenant users and roles; no cross-tenant listing.

#### 7.6.4 Build order

| Wave | Screens | Backend prerequisite |
|---|---|---|
| 1 | Legal routes (6), Threat intelligence (9), Templates (10), Findings read-only (12), Environments hub read/connect state (24, Tier A portion) | none (tenant filter on audit events before 11) |
| 2 | Audit events (11) | server-side tenant filtering on `/audit/events` |
| 3 | Engagements (13–15) | durable tenant-bound engagement records + route RBAC + signed approval history |
| 4 | Assessments (16–18) | durable job model + SSE + canonical safety path |
| 5 | Reports (19–20), Admin (21–23), Connect/Detail environment wizards (25–26) | durable artifacts, approval workflow, secure exports, durable connection records + secret-manager write path |

Wave 1 is the MVP gate: it ships real, tenant-safe value on shipped endpoints with no new
backend contracts. Waves 3–5 land only after their backend prerequisites exist — the screens
are planned now so the contracts (§11.5) and surfaces arrive together, never as stubs.

### 7.7 Onboarding journey (post-registration)

The primary customer journey extends at registration. After the account and tenant exist
atomically, the customer is onboarded through a guided wizard that both activates the
workspace and captures structured customer intelligence — the same data Pillar 2 (OSINT
enrichment) and the engagement workflow consume later.

#### 7.7.1 Journey map

```
Landing → Register (account + tenant created atomically)
       → Onboarding wizard (4 steps)
            1. Organization profile   — industry, size, region, security-team maturity
            2. Use cases              — which of the seven capabilities they bought/need
            3. Environment intent     — what they will connect (§7.6 Environments)
            4. Review & activate      — summary, terms acceptance, workspace entry
       → /app (Evidence workspace, onboarding state recorded)
```

#### 7.7.2 Customer intelligence captured

Every answer is structured and persisted as a tenant-scoped knowledge entry (the knowledge
API is live and tenant-scoped; `POST /api/knowledge/entries` → 201). Nothing is invented:
unanswered items persist as `"unanswered"`, never as a default.

| Step | Data captured | Consumed by |
|---|---|---|
| 1. Organization profile | industry vertical, company size band, operating regions, security-team maturity (none → ad-hoc → defined → managed), compliance obligations in scope (PCI-DSS, NDPR, GDPR, SOC 2, ISO 27001, CBN, HIPAA) | Engagement scoping (§7.4), compliance mapping (Orange), GRC reporting |
| 2. Use cases | capability selection (seven pillars), primary persona (CISO, red-team lead, analyst, pilot sponsor), success criteria free-text | Product focus, assessment defaults, report templates |
| 3. Environment intent | which adapter categories they plan to connect (containers, cloud, files, web apps & APIs, external infrastructure, directories/CRM, media), cloud providers, whether targets are sanctioned/lab | Environments hub defaults (§7.6), Pillar 2 digital-twin ingestion |
| 4. Review & activate | terms acceptance timestamp, onboarding completion | Onboarding state, trial-abuse signals |

#### 7.7.3 Wizard contract

| Step | Route | Role | Behavior |
|---|---|---|---|
| Entry | `/onboarding` | authenticated (viewer+) | Resumes at the first incomplete step; a completed onboarding redirects to `/app` |
| 1 | `/onboarding/profile` | viewer+ | Save → next; each field validated client-side, re-validated server-side |
| 2 | `/onboarding/use-cases` | viewer+ | Capability multi-select (must select ≥1), persona radio, success criteria text |
| 3 | `/onboarding/environments` | viewer+ | Adapter-category multi-select, cloud-provider check, sanctioned-target confirmation |
| 4 | `/onboarding/review` | viewer+ | Full summary, terms + acceptable-use acceptance (required), activate → `/app` |
| Resume | any step | viewer+ | Back/next navigation preserves answers; partial answers are saved, never discarded |

- Server actions persist each completed step immediately (knowledge entry per step, tenant-scoped) — a run survives refreshes and different workers.
- Every step renders honest states: loading, error, saved, and unavailable. No fake email validation: the platform has **no email verification and no password reset** — the wizard never claims an email was sent or verified.
- Completion is recorded as onboarding state; `/app` displays onboarding completion and the captured profile summary.

#### 7.7.4 Forgot password and email validation (honest surfaces)

- **No email verification exists.** The register form must not claim "we sent a verification email". Sign-in works immediately after registration.
- **No password reset exists.** The sign-in form links a "Forgot password?" route that renders an explicit unavailable state: password recovery is not yet available; contact the support link in the footer. No fake "reset link sent" state.
- Backend prerequisite (planned, not built): `POST /api/auth/forgot-password` + token-based reset + email delivery. Until both exist, the surfaces above render unavailable and never simulate success.

### 7.8 Application page scope (the actual product pages)

The onboarding screens (§7.7) are journey scaffolding. The **actual product pages** are the
authenticated application surface that delivers the seven capabilities. This section scopes
that surface against the verified endpoint reality (probed live, 2026-09-28): every page is
classified as **shipped**, **Tier A** (endpoint live, page buildable now), **Tier B** (blocked
on backend prerequisites), or **unmounted** (backend module exists, no API — page blocked on
a mounted router). No page ships as a stub; missing data renders as unavailable.

#### 7.8.1 Page map by capability (the seven pillars)

| # | Capability | Pages | Route | Status | Live endpoint evidence |
|---|---|---|---|---|---|
| 1 | **Colour teams + orchestrator** | Workspace overview | `/app` | **shipped** | `/health` 200, stats 200 |
| | | Findings register | `/app/findings` | **shipped** (read-only, role-scoped) | sequences 200 analyst / 403 viewer |
| | | **Exercise console** | `/app/exercises` | **Tier A** | `GET /api/exercises/` 200 analyst (list, run, status, report, replay); viewer → 403 role-scoped panel |
| | | **Scenario templates** | `/app/templates(/:id)` | **shipped** | 200 (catalog + detail) |
| 2 | **Intelligence stack** | Threat intelligence | `/app/intelligence` | **shipped** | actors/campaigns/indicators/ttps 200 |
| | | **Knowledge base** | `/app/knowledge` | **Tier A** | `GET /api/knowledge/stats` 200 (entries live); entries + search endpoints live |
| | | **Detection rules workbench** | `/app/detect` | **unmounted** | no API router; analytics generators exist in `vorsyghta/analytics/` — blocked until a router lands |
| | | Environments hub | `/app/environments` | **shipped** (Tier A hub) | client-data adapters; connection storage Tier B |
| 3 | **Zero-day research** | **Disclosure register** | `/app/disclosures` | **Tier A** | `GET /api/disclosures` 200 (full CVD lifecycle in `research/disclosure.py`) |
| | | **Research campaigns** | `/app/research` | **Tier B** | crash-pipeline/mutator run over SSH — needs the durable job model + SSE |
| 4 | **Quantum / PQC** | **Quantum workspace** | `/app/quantum` | **unmounted** | `api/routers/quantum.py` exists but is not mounted (404) — blocked until mounted + RBAC |
| 5 | **Commercial SaaS** | Billing settings | `/app/settings/billing` | **shipped** | status 200; offer 503 until Stripe configured (honest) |
| | | Engagements | `/app/engagements(/new)(/:id)` | **Tier B** | router 200 but global plaintext storage, no route RBAC — disqualifying |
| | | Assessments | `/app/assessments(/new)(/:id)` | **Tier B** | durable job model + SSE + canonical safety path |
| | | Reports | `/app/reports(/:id)` | **Tier B** | durable artifacts + approval workflow |
| | | **Compliance dashboard** | `/app/compliance` | **Tier A** | compliance gap/framework records live (`db/models/orange_team.py`); needs a read API — blocked until one lands → reclassify **Tier B** |
| 6 | **Simulation paradigms** | (inherits exercise console) | — | **planned** | paradigm engines not built |
| 7 | **RL / RLHF** | **Feedback loop** | `/app/feedback` | **unmounted** | feedback router exists (7 paths) but path shape unverified; analyzer/enhancer live in `vorsyghta/feedback/` |
| — | Cross-cutting | Audit events | `/app/audit` | **Tier A, gated** | 200 analyst / 403 viewer — blocked until server-side tenant filtering |
| | | Integrations status | `/app/admin/integrations` | **Tier A** | 6 paths live, analyst 403 |
| | | Secrets providers | `/app/admin/secrets` | **Tier A, restricted** | 403 admin; **never returns raw values in the UI** |
| | | Datasets | `/app/datasets` | **unmounted** | `vorsyghta/datasets/` processors exist; no API router |
| | | Admin: system / users | `/app/admin/system`, `/app/admin/users` | **Tier A** | health/ready live |

#### 7.8.2 The actual-application navigation (target state)

```
Overview · Engagements · Assessments · Findings · Reports · Intelligence ·
Environments · Templates · Exercises · Research · Compliance · Datasets ·
Detection · Quantum · Feedback · Administration
```

The current 8-item nav covers onboarding-era value. The target nav groups the
actual product pages by capability and renders Tier B/unmounted entries as
explicit "requires backend" states — never hidden, never fabricated.

#### 7.8.3 Build order for the actual pages

| Wave | Pages | Prerequisite |
|---|---|---|
| A1 | Exercise console, Disclosure register, Knowledge base, Integrations status, Secrets providers, Admin system/users | none — endpoints live today |
| A2 | Audit events | server-side tenant filtering on `/audit/events` |
| B1 | Engagements → Assessments → Reports | durable tenant-bound records + RBAC + signed approvals; durable job model + SSE |
| B2 | Research campaigns, Compliance dashboard | durable jobs; compliance read API |
| B3 | Detection rules, Datasets, Quantum workspace, Feedback loop | routers must land first (unmounted modules) |

Wave A1 is the highest-value next step: five real product pages on live endpoints with no
new backend contracts. Waves B* land only after their backend prerequisites exist.

## 8. Evidence and Safety UX

Every result view displays:

- Provenance classification
- Authorized engagement and target
- Tool and data source
- Initiating user and tenant
- Start and completion timestamps
- Persistence status
- Integrity state
- Redaction state
- Dependency degradation and fallback
- MITRE, CWE, and CVSS references where applicable

Operational screens display:

- Engagement approval
- Allowed target
- Testing window
- Prohibited methods
- Remaining run time
- Emergency stop
- Request correlation identifier
- Explicit launch confirmation

No arbitrary command input is included in the first operational release.

## 9. Visual and Interaction Direction

### 9.1 Visual language

- Midnight violet provides structural depth.
- Warm neutral surfaces support long-form evidence and reports.
- Electric lime identifies primary action and verified state.
- Pink and violet identify AI-assisted or simulated state.
- Semantic state always includes text and an icon, never color alone.
- Monospace is reserved for commands, identifiers, hashes, and evidence.
- Marketing layouts are editorial and spacious.
- Application layouts are compact and data-dense.

The visual system must be original. It may use the palette cues in
`design-md/sentry/DESIGN.md`, but it must not reproduce Sentry trade dress or
the historical neon dashboard.

The first release uses a text wordmark. A distinct Vorsyghta symbol, SVG
wordmark, favicon, social image, and dark/light asset set require approved brand
artwork. The legacy ThreatSimGPT JPEG is not used.

### 9.2 Interaction states

Every interactive component defines:

- Default
- Hover
- Focus-visible
- Active
- Selected
- Loading
- Disabled
- Empty
- Error
- Unauthorized
- Degraded
- Stale
- Success
- Reduced-motion behavior

### 9.3 Responsive behavior

- Public pages support small mobile through large desktop.
- Trial checkout and account management are fully mobile accessible.
- Overview, approvals, findings, and reports are mobile usable.
- Dense operational timelines prioritize desktop while retaining readable
  narrow-screen fallbacks.
- Navigation never relies on a permanently fixed desktop sidebar.

## 10. Frontend Architecture

### 10.1 Application structure

Use one Next.js App Router application in `frontend/` for public and protected
routes. The same source produces a self-hostable container.

| Concern | Decision |
|---|---|
| Framework | Current stable Next.js App Router |
| Language | Strict TypeScript |
| Rendering | Static or server rendering for public routes; server-first protected routes |
| Authentication | FastAPI bearer token held only in an HTTP-only web session cookie |
| API access | Same-origin server-side BFF calls to FastAPI |
| Billing UI | Stripe-hosted Checkout and Customer Portal |
| Validation | Runtime schemas at external response boundaries |
| Styling | CSS custom properties and component-local CSS |
| Fonts | Self-hosted open fonts; no external font request |
| Server state | Server components first; client cache only when interaction requires it |
| Real-time | Authenticated SSE for durable one-way events |
| Testing | Unit, integration, accessibility, and Playwright |

The browser never receives the FastAPI bearer token, Stripe secret key, or raw
billing provider identifiers that are not needed for display.

### 10.2 Deployment

- The frontend listens on container port 3000 and host port 3002 in local
  Compose because ports 3000 and 3001 are already allocated.
- The frontend calls FastAPI through the internal service URL.
- The browser calls only the frontend origin.
- Production can place both services behind one reverse proxy.
- The image uses a supported Node LTS release and a locked pnpm version.
- Hosted and self-hosted modes use explicit configuration, never implicit
  defaults.

For the local foundation stack:

```bash
cp .env.example .env
# Replace every placeholder secret before startup.
docker compose --profile web up --build
```

Startup ordering is mandatory: PostgreSQL must become healthy, the one-shot
`migrate` service must complete `python -m alembic upgrade head`, the API must
return HTTP 200 from `/ready`, and only then may the web service start. Alembic
is the sole schema authority; API startup never calls
`Base.metadata.create_all()`.

Existing Docker volumes created by the former `Base.metadata.create_all()`
startup path need operator-led adoption before this migration service is used.
Back up the volume, compare the existing schema with revision
`003_persistence_layer`, resolve any drift and case-colliding email records,
then stamp revision 003 only when that comparison proves equivalence. A volume
that has not been verified must not be stamped or upgraded in place.

The host publishes web on 3002 and API on 8001. Containers use web port 3000
and API port 8000 on the private bridge. The web container explicitly permits
its cleartext private-bridge API URL; external staging and production traffic
still requires HTTPS.

Staging must set `VORSYGHTA_BILLING_REQUIRED=true`, use Stripe test mode with
`STRIPE_EXPECTED_LIVEMODE=false`, and configure non-loopback HTTPS Checkout and
Portal return URLs. Production uses live mode and the same non-loopback HTTPS
rule.

### 10.3 Failure behavior

| Failure | Required interface behavior |
|---|---|
| API is unconfigured | Public site renders; sign-in and app fail closed |
| API is unavailable | Show service unavailable; never use synthetic data |
| Session is invalid | Clear the cookie and redirect to sign-in |
| Stripe is unconfigured | Trial action is unavailable; no invented price |
| Stripe is unavailable | Public content remains; billing-gated data remains hidden |
| Offer is invalid | Disable checkout and expose a contact route |
| Subscription is not entitled | Show checkout or billing management only |
| Stats fail | Display unavailable, not zero |
| Valid empty result | Display a precise empty state |
| Checkout is canceled | Return to trial screen without activating access |
| Checkout return is invalid | Ignore the success query and fail closed |

All upstream calls use bounded timeouts and bounded retries.

## 11. Backend Foundation

### 11.1 Billing records

`tenant_subscriptions` stores one current billing projection per tenant:

- Tenant identifier
- Billing owner user identifier
- Billing status
- Stripe customer identifier
- Stripe subscription identifier
- Stripe Checkout session identifier
- Configured Stripe Price identifier
- Stripe live-mode flag
- Checkout attempt number
- Checkout expiration
- Trial start and end
- Immutable trial-consumed timestamp
- Entitlement end
- Cancel-at-period-end flag
- Created and updated timestamps

`stripe_webhook_events` stores the durable, idempotent event inbox:

- Stripe event identifier
- Related tenant identifier
- Event type
- Stripe object identifier
- Live-mode flag
- API version
- Sanitized outcome and reason
- Previous and resulting local status
- Processing timestamp

Complete webhook payloads and card data are not stored.

### 11.2 Billing API

| Endpoint | Access | Behavior |
|---|---|---|
| `GET /api/billing/offer` | Public | Active Team offer metadata without secret IDs |
| `POST /api/billing/checkout-session` | Billing owner | Create or reuse hosted Checkout |
| `GET /api/billing/status` | Authenticated tenant user | Local entitlement projection |
| `POST /api/billing/portal-session` | Billing owner | Create a short-lived portal URL |
| `POST /api/billing/webhook` | Stripe signature | Transactionally reconcile billing state |

The client cannot provide a Price ID, Customer ID, tenant ID, trial duration,
quantity, success URL, cancel URL, or portal return URL.

### 11.3 Webhook processing

Webhook handling must:

1. Read the unmodified request body with a bounded size.
2. Require and verify the Stripe signature and timestamp.
3. Reject test events in live mode and live events in test mode.
4. Lock the subscription record in a database transaction.
5. Treat duplicate event identifiers as successful no-ops.
6. Retrieve current Stripe state when event order matters.
7. Validate tenant metadata, customer, subscription, Price, quantity, and mode.
8. Update billing projection and event receipt atomically.
9. Return success only after commit.
10. Return a retriable error for transient Stripe or database failures.

Required event families cover Checkout completion and expiration, subscription
creation and changes, trial ending, invoice success, invoice failure, required
payment action, and subscription deletion.

### 11.4 Authentication hardening

- SaaS registration creates a dedicated tenant and owner atomically.
- Client-provided role and tenant values are rejected.
- Email is normalized and verified.
- Password policy and rate limits are enforced.
- Database identity is authoritative; Redis and process memory are not fallback
  identity stores in SaaS mode.
- User and tenant active state is checked on protected requests.
- JWT tenant and role claims are not trusted after database state changes.
- A production signing secret is mandatory at startup.
- Access tokens are short-lived and revocable.
- Unsafe SSO paths remain disabled until cryptographic verification and state
  validation are complete.

### 11.5 Operational job model

Before operational assessment screens are enabled, the backend provides:

- Durable scenarios, assessments, stages, findings, and artifacts
- Create, list, read, cancel, and retry job endpoints
- Current phase, progress, timestamps, typed failure, and result links
- Durable events with reconnect and replay support
- Authenticated SSE backed by shared persistence or a broker
- Canonical orchestration through engagement and command-safety checks
- Secure artifact metadata and downloads

## 12. Security and Privacy Requirements

- Paid routes are absent from the public foundation deployment unless they are
  explicitly allowlisted.
- Tool server, MCP, VM, Docker socket, SSH, WinRM, and hypervisor credentials
  are not present in the public web runtime.
- Tenant isolation is verified on every resource query.
- Browser-side route guards are navigation aids, not security boundaries.
- Stripe fields are hosted by Stripe.
- Stripe webhook signatures and idempotency are mandatory.
- Authentication, billing, and execution events are auditable.
- Raw secrets are never returned by an API.
- Session replay excludes authentication, billing, evidence, and report data.
- Content Security Policy restricts script, frame, connect, image, and font
  sources.
- CSRF protection applies to cookie-authenticated mutations.
- Sensitive downloads are short-lived, authorized, and tenant-scoped.
- Retention and deletion behavior is disclosed before trial enrollment.
- Trial abuse prevention includes email verification, bounded attempts,
  account and card signals, and request throttling.

## 13. Accessibility and Performance

### 13.1 Accessibility

- WCAG 2.2 AA is the minimum acceptance level.
- All actions are keyboard accessible.
- Focus is visible and ordered logically.
- Status never relies on color alone.
- Charts have text or table equivalents.
- Motion respects `prefers-reduced-motion`.
- Form errors identify the field and corrective action.
- Checkout remains usable with screen readers and browser zoom.
- Contrast is measured rather than inferred from tokens.

### 13.2 Performance

Public pages target these 75th-percentile Core Web Vitals:

- Largest Contentful Paint at or below 2.5 seconds
- Interaction to Next Paint at or below 200 milliseconds
- Cumulative Layout Shift at or below 0.1

The public page ships no dashboard charting library, client state framework, or
external font request. Operational routes load only their required code.

## 14. Testing Strategy

### 14.1 Frontend gates

- Dependency installation from a frozen lockfile
- ESLint with zero warnings
- Strict TypeScript checking
- Unit tests for configuration, API parsing, sessions, and billing decisions
- Component tests for public, trial, error, and protected states
- Accessibility checks for every route
- Production build
- Playwright tests for public routes and protected redirects
- Configured staging flow through Stripe test Checkout
- Production dependency audit

### 14.2 Backend gates

- Unit tests for registration, entitlement, Checkout, portal, and webhook paths
- PostgreSQL migration upgrade and downgrade tests
- Concurrent and duplicate webhook delivery tests
- Out-of-order event convergence tests
- Forged-signature and wrong-mode tests
- Cross-tenant authorization tests
- Database and Stripe outage tests
- Trial expiration and cancellation tests with Stripe Test Clocks
- Log assertions proving card and secret data are absent
- Existing regression suite
- Ruff, mypy, Bandit, and dependency integrity checks

CI renders PostgreSQL upgrade and downgrade SQL from the single Alembic head,
validates the base and integration Compose models, and builds both API and web
containers. These structural gates do not replace a live staging migration,
restore test, or Stripe test-mode acceptance run.

### 14.3 Live acceptance

- Mastercard trial setup
- Strong Customer Authentication challenge
- Declined setup without activation
- Trial conversion and failed renewal
- Customer portal card update and cancellation
- Controlled OnePay UK Mastercard setup through Stripe

No live payment result is claimed until it has been measured in the configured
Stripe account.

## 15. Delivery Plan

| Phase | Duration | Deliverable |
|---|---:|---|
| Security containment | Variable | Trusted repository and reviewed developer hosts |
| Foundation engineering | 3 to 5 weeks | Landing, sign-in, Stripe trial, read-only app, billing contracts |
| Product and API contracts | 2 to 3 weeks | Durable resources, role matrix, event contracts |
| Operational workflow | 4 to 6 weeks | Engagements, approvals, safe assessments, progress |
| Evidence and reporting | 3 to 4 weeks | Findings, reports, intelligence, audit views |
| Hardening and beta | 2 to 3 weeks | Accessibility, performance, security, deployment |

The expected operational MVP is 16 to 23 weeks for two frontend engineers, one
backend engineer, one product designer, and fractional security, compliance,
and quality support.

## 16. Release Boundaries

### 16.1 Foundation release

- Public landing page
- Stripe-backed Team offer
- Isolated account registration and existing-user sign-in
- Stripe-hosted 14-day trial checkout
- Subscription status and customer portal
- Authenticated read-only overview
- Real health and tenant-scoped activity data
- Explicit empty, unavailable, and unconfigured states

### 16.2 Operational MVP

- Tenant-safe engagement lifecycle
- Approved-scope assessment creation
- Canonical safe execution
- Durable progress events
- Findings review
- Reports and exports
- Threat intelligence
- Audit viewer

### 16.3 Not in the initial releases

- Arbitrary command console
- VM provisioning, snapshots, or GUI control
- Raw secret access
- Full SOC, SIEM, EDR, IDS, incident, and forensics console
- Autonomous agent steering
- External attack-flow control
- Production social-engineering delivery
- Full color-team assurance scorecards
- Quantum-readiness workspace
- Client-data ingestion
- Dataset administration
- Full RAG administration
- Detection-rule workbench
- Native mobile applications

## 17. Launch Gates

Public trial traffic is prohibited until all gates pass:

The foundation implementation addresses portions of registration, schema
ordering, entitlement, and container validation. The list below remains a set
of unmet launch gates until each item has measured evidence and explicit
sign-off.

1. Repository incident review is complete.
2. Production signing secrets are mandatory and verified.
3. Registration creates isolated tenants and verified identities.
4. Billing schema is applied through Alembic.
5. Stripe Checkout and webhook state transitions pass adversarial tests.
6. Subscription entitlement is enforced on every protected API route.
7. Offensive capabilities are absent from the public foundation deployment.
8. Tenant isolation passes negative tests.
9. Card data is absent from Vorsyghta systems and logs.
10. Legal entity, Team price, currency, tax, refund, renewal, and cancellation
    terms are approved.
11. Privacy, subprocessor, retention, and acceptable-use documents are current.
12. Trial reminders and payment-failure notifications are operational.
13. Backup, restore, reconciliation, alerting, and incident procedures are
    verified.
14. A controlled OnePay UK Mastercard acceptance test has been measured if that
    compatibility is marketed.

## 18. Acceptance Criteria

- A visitor can understand the product without unsupported claims.
- A user can sign in without exposing a bearer token to browser JavaScript.
- A billing owner can start a card-required 14-day Stripe trial.
- A redirect without a valid webhook cannot activate access.
- A duplicate or out-of-order Stripe event cannot grant incorrect access.
- A OnePay-issued Mastercard is treated as a normal card, not a second gateway.
- A trialing or active tenant can view only tenant-scoped real data.
- A non-entitled, suspended, or unknown tenant fails closed.
- No operational action bypasses engagement or command-safety checks.
- A run survives refreshes and requests handled by different workers.
- Every result displays provenance.
- Missing upstream data never becomes fabricated success or zero.
- Public and trial routes meet WCAG 2.2 AA.
- Required checks pass with zero warnings.

## 19. Authoritative References

- Product overview: `README.md`
- License and tier boundaries: `docs/licensing/COMPONENT_MATRIX.md`
- Responsible use: `docs/compliance/policies/acceptable-use-policy.md`
- Current red-team audit: `security-audit/RED_TEAM_GAP_ANALYSIS_2026-08-26.md`
- Design reference: `design-md/sentry/DESIGN.md`
- API implementation: `vorsyghta/api/main.py` and `vorsyghta/api/routers/`
- Safe execution: `vorsyghta/core/attack_orchestrator.py`
- Command safety: `vorsyghta/vm/safety.py`
- Identity: `vorsyghta/security/rbac.py` and `vorsyghta/db/models/auth.py`
- Stripe trial guidance: `https://docs.stripe.com/payments/checkout/free-trials`
- Stripe webhook guidance: `https://docs.stripe.com/webhooks`
- Stripe customer portal: `https://docs.stripe.com/customer-management/integrate-customer-portal`
- OnePay UK account and Mastercard information: `https://onepay.co.uk/`
