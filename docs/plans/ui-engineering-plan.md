# Vorsyghta UI — Full Engineering Plan

Concrete, file-by-file implementation plan for the Vorsyghta web platform UI.

Four surfaces, one Next.js codebase:
- **Surface 1:** SOC Console (blue team analysts)
- **Surface 2:** Red Team Campaigns (operators)
- **Surface 3:** Client Portal (external clients, read-only)
- **Surface 4:** Internal Admin Panel (platform administrators)

---

## Tech Stack

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| Framework | Next.js 14 (App Router) | SSR for client portal, API routes as BFF |
| UI | React 18 + Tailwind CSS + shadcn/ui | Rapid, consistent, dark-theme SOC aesthetic |
| Server State | TanStack Query v5 | Caching, polling, optimistic updates |
| Client State | Zustand | Lightweight global state (auth, theme, filters) |
| Real-time | Server-Sent Events (SSE) | Simpler than WebSocket for one-way live feeds |
| Charts | Tremor | Purpose-built for dashboards, Recharts under the hood |
| Auth | NextAuth.js (Auth.js v5) | OAuth/OIDC, role-based, multi-tenant |
| Forms | React Hook Form + Zod | Type-safe validation matching FastAPI Pydantic models |
| Icons | Lucide React | Consistent icon set |
| Tables | TanStack Table v8 | Sorting, filtering, pagination for alert/incident tables |
| Syntax Highlighting | Shiki | YAML template viewer, log viewer |
| PDF Export | @react-pdf/renderer | Client portal report downloads |
| Testing | Vitest + Playwright | Unit + E2E |
| Package Manager | pnpm | Monorepo-friendly, fast |

---

## Architecture

```
vorsyghta-web/                     (Next.js app — new repo or monorepo package)
├── app/
│   ├── (soc)/                     ← Surface 1: SOC Console
│   ├── (campaigns)/               ← Surface 2: Red Team
│   ├── (portal)/                  ← Surface 3: Client Portal
│   ├── (admin)/                   ← Surface 4: Internal Admin
│   ├── (auth)/                    ← Login, callback, logout
│   ├── api/                       ← BFF routes (proxy to FastAPI)
│   └── layout.tsx                 ← Root layout (providers, theme)
├── components/
│   ├── ui/                        ← shadcn/ui primitives
│   ├── soc/                       ← SOC-specific components
│   ├── campaigns/                 ← Campaign-specific components
│   ├── portal/                    ← Client portal components
│   ├── admin/                     ← Admin components
│   └── shared/                    ← Cross-surface shared components
├── lib/
│   ├── api/                       ← API client functions
│   ├── auth/                      ← NextAuth config, role helpers
│   ├── hooks/                     ← Custom React hooks
│   ├── stores/                    ← Zustand stores
│   ├── types/                     ← TypeScript types (mirror Pydantic)
│   └── utils/                     ← Formatting, color mapping, etc.
├── styles/
│   └── globals.css                ← Tailwind + theme tokens
├── public/
├── middleware.ts                  ← Auth + tenant routing
├── next.config.mjs
├── tailwind.config.ts
├── tsconfig.json
├── package.json
└── playwright.config.ts
```

### Backend Changes Required

The existing FastAPI backend needs additions to support the UI:

```
vorsyghta/
├── api/
│   ├── routers/
│   │   ├── blue_team.py           ← NEW — SOC endpoints
│   │   ├── campaigns.py           ← NEW — Red team campaign endpoints
│   │   ├── portal.py              ← NEW — Client portal endpoints
│   │   ├── admin.py               ← NEW — Admin endpoints
│   │   └── auth.py                ← NEW — JWT issuance/validation
│   ├── main.py                    ← EDIT — Register new routers, add CORS origins
│   └── websocket.py               ← NEW — SSE/WebSocket for live feeds
└── core/
    └── auth.py                    ← NEW — JWT, role definitions, tenant scoping
```

---

## Part 1: Foundation & Auth

### Problem

The FastAPI backend has no authentication, no blue team API router, no campaign API router, and CORS is wildcard. The UI needs auth, role-based access, and structured API endpoints.

### File-by-file changes

#### 1. New file: `vorsyghta/core/auth.py`

JWT-based auth with role definitions and tenant scoping.

```python
class UserRole(str, Enum):
    ANALYST = "analyst"        # SOC console access
    OPERATOR = "operator"      # Red team campaigns
    ADMIN = "admin"            # Full access
    CLIENT = "client"          # Portal access, scoped to their tenant

class AuthContext(BaseModel):
    user_id: str
    email: str
    role: UserRole
    tenant_id: Optional[str]   # For client portal scoping
    permissions: List[str]

def create_access_token(user_id: str, role: UserRole, tenant_id: Optional[str]) -> str
def verify_token(token: str) -> AuthContext
def require_role(*roles: UserRole) -> Callable  # FastAPI dependency
def require_tenant(tenant_id: str) -> Callable  # Scopes data to tenant
```

Key decisions:
- JWT with short-lived access tokens (15 min) + long-lived refresh tokens (7 days).
- Roles map to the four UI surfaces. `ANALYST` can only access `/api/blue-team/*`, `OPERATOR` can only access `/api/campaigns/*`, etc.
- Tenant scoping for `CLIENT` role — all queries filtered by `tenant_id`.
- Secrets from environment variables (`JWT_SECRET`, `JWT_ALGORITHM=HS256`).

#### 2. New file: `vorsyghta/api/routers/auth.py`

```python
router = APIRouter(prefix="/api/auth", tags=["auth"])

@router.post("/login")
async def login(email: str, password: str) -> TokenResponse

@router.post("/refresh")
async def refresh(refresh_token: str) -> TokenResponse

@router.get("/me")
async def get_current_user(ctx: AuthContext = Depends(get_auth_context)) -> UserInfo

@router.post("/logout")
async def logout(refresh_token: str) -> None
```

Phase 1: Simple email/password against a local users table or config file.
Phase 2: OAuth via GitHub / Microsoft Entra ID (for ZestPayment integration).

#### 3. New file: `vorsyghta/api/routers/blue_team.py`

Exposes all blue team CLI functionality as REST endpoints. Each CLI command maps to an endpoint.

```python
router = APIRouter(prefix="/api/blue-team", tags=["blue-team"])

# Dashboard
@router.get("/dashboard")
async def get_dashboard(ctx = Depends(require_role(UserRole.ANALYST))) -> DashboardData

# SIEM
@router.get("/siem/stats")
@router.get("/siem/alerts")
@router.post("/siem/search")
@router.get("/siem/connect")

# IDS
@router.get("/ids/rules")
@router.post("/ids/inspect")
@router.get("/ids/stats")

# EDR
@router.post("/edr/monitor")
@router.get("/edr/stats")

# Triage
@router.get("/triage/alerts")
@router.get("/triage/stats")

# Incident Response
@router.post("/incident/create")
@router.get("/incident/{incident_id}")
@router.get("/incidents")
@router.post("/incident/{incident_id}/execute")
@router.get("/incident/{incident_id}/report")
@router.post("/incident/{incident_id}/lesson")

# Threat Hunting
@router.get("/hunt/hypotheses")
@router.post("/hunt/search")

# Log Analysis
@router.post("/logs/parse")
@router.post("/logs/search")

# Forensics
@router.post("/forensics/collect")
@router.get("/forensics/{case_id}/report")
@router.get("/forensics/stats")
```

Each endpoint delegates to the existing blue team modules (`SIEMSimulator`, `IDSDetector`, `EDRAgent`, `AlertTriage`, `IncidentResponse`, `ThreatHunter`, `LogAnalyzer`, `ForensicsCollector`). The logic already exists — this is a thin REST wrapper.

#### 4. New file: `vorsyghta/api/routers/campaigns.py`

```python
router = APIRouter(prefix="/api/campaigns", tags=["campaigns"])

@router.get("/")                         # List campaigns
@router.get("/{campaign_id}")            # Campaign detail + metrics
@router.get("/{campaign_id}/dashboard")  # Real-time dashboard data
@router.post("/")                        # Create campaign
@router.post("/{campaign_id}/cancel")    # Cancel campaign
@router.get("/templates")                # List YAML templates
@router.get("/templates/{name}")         # Get template content
@router.post("/templates")               # Create/update template
@router.post("/generate")                # AI content generation
@router.post("/deploy")                  # Deploy campaign
```

Delegates to existing `ThreatDeploymentEngine`, `CampaignAnalyticsEngine`, `RealTimeDashboard`, and `YAMLConfigLoader`.

#### 5. New file: `vorsyghta/api/routers/portal.py`

```python
router = APIRouter(prefix="/api/portal", tags=["portal"])

@router.get("/{tenant}/overview")          # Engagement summary
@router.get("/{tenant}/reports")           # Generated reports
@router.get("/{tenant}/reports/{id}")      # Download report
@router.get("/{tenant}/simulations")       # Simulation results
@router.get("/{tenant}/compliance")        # Compliance status
@router.get("/{tenant}/recommendations")   # Remediation recommendations
```

All endpoints require `UserRole.CLIENT` and scope data by `tenant_id`. Read-only — no POST/PUT/DELETE.

#### 6. New file: `vorsyghta/api/routers/admin.py`

```python
router = APIRouter(prefix="/api/admin", tags=["admin"])

@router.get("/health")              # System health (API, SIEM, DB, LLM)
@router.get("/config")              # Current config.yaml contents
@router.put("/config")              # Update config
@router.get("/users")               # List users
@router.post("/users")              # Create user
@router.put("/users/{id}")          # Update user role
@router.get("/templates")           # All templates
@router.post("/templates/validate") # Validate YAML template
@router.get("/deployments")         # Client deployment configs
@router.get("/rules/ids")           # IDS rules
@router.post("/rules/generate")     # Detection rule generator
```

Requires `UserRole.ADMIN`.

#### 7. New file: `vorsyghta/api/websocket.py`

SSE endpoints for real-time data push.

```python
router = APIRouter(prefix="/api/stream", tags=["realtime"])

@router.get("/alerts")
async def stream_alerts(request: Request, ctx = Depends(require_role(UserRole.ANALYST))):
    """SSE stream of new alerts as they arrive from SIEM/triage engine."""
    # Polls SIEM/triage every N seconds, yields new alerts as SSE events

@router.get("/incidents/{incident_id}")
async def stream_incident_updates(...):
    """SSE stream of incident playbook step completions."""

@router.get("/campaigns/{campaign_id}")
async def stream_campaign_metrics(...):
    """SSE stream of campaign engagement metrics."""

@router.get("/hunts")
async def stream_hunt_results(...):
    """SSE stream of hunt execution progress."""
```

SSE chosen over WebSocket for Phase 1 because:
- One-way data flow (server → client) is sufficient for all live feeds.
- SSE works over standard HTTP, no upgrade handshake, simpler proxy/load balancer config.
- Auto-reconnect built into the browser `EventSource` API.
- Phase 2 can add WebSocket for bidirectional needs (e.g., collaborative incident response).

#### 8. Edit: `vorsyghta/api/main.py`

- Register new routers: `auth_router`, `blue_team_router`, `campaigns_router`, `portal_router`, `admin_router`, `sse_router`.
- Update CORS to read allowed origins from environment (`CORS_ORIGINS=https://vorsyghta.com,https://www.vorsyghta.com`).
- Add JWT auth middleware.
- Update health check to include SIEM, DB, and LLM provider status.

#### 9. Edit: `vorsyghta/api/routers/__init__.py`

Import and export all new routers.

### Dependencies (backend)

```
# requirements.txt additions
PyJWT>=2.8.0
passlib[bcrypt]>=1.7.4
python-multipart>=0.0.6       # For form-based login
sse-starlette>=1.8.0          # SSE support for FastAPI
```

---

## Part 2: Frontend Foundation

### File-by-file changes

#### 1. Project initialization

```bash
pnpm create next-app@latest vorsyghta-web --typescript --tailwind --app --src-dir
cd vorsyghta-web
pnpm add @tanstack/react-query @tanstack/react-table zustand lucide-react \
  react-hook-form zod @hookform/resolvers tremor next-auth@beta \
  @react-pdf/renderer shiki date-fns clsx tailwind-merge
pnpm add -D @types/node vitest @testing-library/react @playwright/test
```

#### 2. `tailwind.config.ts`

Define theme tokens matching the design system:

```typescript
const config = {
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        base: { DEFAULT: "#0a0e14", surface: "#11161f", elevated: "#1a2030" },
        border: "#1e2738",
        // Semantic colors
        critical: "#ef4444",
        high: "#f97316",
        medium: "#eab308",
        low: "#22c55e",
        info: "#3b82f6",
        quantum: "#a855f7",
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "monospace"],
      },
    },
  },
};
```

#### 3. `lib/types/index.ts`

TypeScript types mirroring FastAPI Pydantic models. Generated from OpenAPI schema.

```typescript
// Auto-generated from FastAPI /openapi.json
// Run: pnpm openapi-typescript http://localhost:8000/openapi.json -o lib/types/api.ts

// Manual types for UI state
export type Priority = "P1" | "P2" | "P3" | "P4";
export type Severity = "critical" | "high" | "medium" | "low";
export type IncidentStatus = "open" | "investigating" | "contained" | "eradicated" | "resolved" | "closed";
export type CampaignStatus = "draft" | "active" | "completed" | "cancelled";
export type UserRole = "analyst" | "operator" | "admin" | "client";

// Core domain types
export interface Alert { ... }
export interface Incident { ... }
export interface HuntHypothesis { ... }
export interface Campaign { ... }
export interface DashboardData { ... }
```

#### 4. `lib/api/client.ts`

Centralized API client with auth token injection and error handling.

```typescript
const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const token = getAccessToken();
  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(token && { Authorization: `Bearer ${token}` }),
      ...options?.headers,
    },
  });
  if (!res.ok) throw new ApiError(res.status, await res.json());
  return res.json();
}

// SSE helper
export function createSSEStream(path: string, onEvent: (data: string) => void): () => void {
  const es = new EventSource(`${API_BASE}${path}`);
  es.onmessage = (e) => onEvent(e.data);
  return () => es.close();
}
```

#### 5. `lib/api/` — API function modules

One file per domain:

| File | Functions |
|------|-----------|
| `lib/api/siem.ts` | `searchLogs`, `getAlerts`, `getSiemStats`, `testSiemConnection` |
| `lib/api/ids.ts` | `getRules`, `inspectPacket`, `getIdsStats` |
| `lib/api/edr.ts` | `monitorProcess`, `getEdrStats` |
| `lib/api/triage.ts` | `getTriagedAlerts`, `getTriageStats` |
| `lib/api/incidents.ts` | `createIncident`, `getIncident`, `listIncidents`, `executeStep`, `getReport`, `addLesson` |
| `lib/api/hunts.ts` | `getHypotheses`, `executeHunt` |
| `lib/api/logs.ts` | `parseLogs`, `searchLogs` |
| `lib/api/forensics.ts` | `collectEvidence`, `getCaseReport`, `getForensicsStats` |
| `lib/api/campaigns.ts` | `listCampaigns`, `getCampaign`, `getDashboard`, `createCampaign`, `cancelCampaign`, `getTemplates`, `generateContent`, `deployCampaign` |
| `lib/api/portal.ts` | `getOverview`, `getReports`, `getSimulations`, `getCompliance`, `getRecommendations` |
| `lib/api/admin.ts` | `getHealth`, `getConfig`, `updateConfig`, `getUsers`, `getTemplates`, `validateTemplate`, `generateRule` |
| `lib/api/auth.ts` | `login`, `refresh`, `getMe`, `logout` |

Each function is a thin wrapper around `apiFetch` with typed return values.

#### 6. `lib/auth/options.ts`

NextAuth.js configuration.

```typescript
export const authOptions: NextAuthOptions = {
  providers: [
    CredentialsProvider({
      name: "Vorsyghta",
      credentials: { email: {}, password: {} },
      async authorize(credentials) {
        const res = await apiFetch("/api/auth/login", {
          method: "POST",
          body: JSON.stringify(credentials),
        });
        return { ...res.user, accessToken: res.access_token };
      },
    }),
    // Phase 2: GitHubProvider, AzureADProvider
  ],
  callbacks: {
    async jwt({ token, user }) {
      if (user) token.accessToken = user.accessToken;
      return token;
    },
    async session({ session, token }) {
      session.accessToken = token.accessToken;
      return session;
    },
  },
  pages: { signIn: "/auth/login" },
};
```

#### 7. `middleware.ts`

Role-based route protection.

```typescript
export function middleware(request: NextRequest) {
  const token = request.cookies.get("next-auth.session-token")?.value;
  const path = request.nextUrl.pathname;

  // Parse role from JWT (without verifying — just for routing)
  const role = parseRoleFromToken(token);

  // Route guards
  if (path.startsWith("/soc") && !["analyst", "admin"].includes(role))
    return NextResponse.redirect("/auth/login");
  if (path.startsWith("/campaigns") && !["operator", "admin"].includes(role))
    return NextResponse.redirect("/auth/login");
  if (path.startsWith("/admin") && role !== "admin")
    return NextResponse.redirect("/auth/login");
  if (path.startsWith("/portal") && !["client", "admin"].includes(role))
    return NextResponse.redirect("/auth/login");
}
```

#### 8. `lib/stores/` — Zustand stores

| Store | State |
|-------|-------|
| `authStore.ts` | `user`, `role`, `tenantId`, `login()`, `logout()` |
| `themeStore.ts` | `theme: "dark" \| "light"`, `toggle()` |
| `filterStore.ts` | `severity`, `priority`, `status`, `timeRange` — shared filter state for SOC |
| `notificationStore.ts` | `notifications[]`, `unreadCount`, `add()`, `markRead()` |
| `liveAlertStore.ts` | `alerts[]`, `connected: boolean`, `connect()`, `disconnect()` — SSE-fed |

---

## Part 3: SOC Console (Surface 1)

### Pages

| Route | File | Description |
|-------|------|-------------|
| `/soc` | `app/(soc)/page.tsx` | Dashboard — KPI cards, live alert feed, MITRE heatmap, active incidents |
| `/soc/alerts` | `app/(soc)/alerts/page.tsx` | Triage queue — sortable table, priority badges, bulk actions |
| `/soc/alerts/[id]` | `app/(soc)/alerts/[id]/page.tsx` | Alert detail — MITRE mapping, related events, recommended action |
| `/soc/incidents` | `app/(soc)/incidents/page.tsx` | Incident list with status timeline |
| `/soc/incidents/[id]` | `app/(soc)/incidents/[id]/page.tsx` | Incident detail — playbook stepper, timeline, artifacts |
| `/soc/hunts` | `app/(soc)/hunts/page.tsx` | Hunt hypotheses, execution, results |
| `/soc/siem` | `app/(soc)/siem/page.tsx` | SIEM search — query bar, results, saved searches |
| `/soc/logs` | `app/(soc)/logs/page.tsx` | Log analysis — upload, parse, correlate |
| `/soc/forensics` | `app/(soc)/forensics/page.tsx` | Forensic cases, evidence, chain of custody |
| `/soc/triage` | `app/(soc)/triage/page.tsx` | Triage queue with priority scores |

### Layout

```
app/(soc)/layout.tsx
```

Sidebar navigation with:
- Dashboard, Alerts, Triage, Incidents, Threat Hunting, SIEM Search, Log Analysis, Forensics
- User badge (name, role)
- SIEM connection status indicator
- Notification bell with unread count

### Key Components

#### `components/soc/live-alert-feed.tsx`

SSE-connected real-time alert feed.

```tsx
export function LiveAlertFeed() {
  const { alerts, connected, connect } = useLiveAlertStore();

  useEffect(() => {
    const disconnect = createSSEStream("/api/stream/alerts", (data) => {
      useLiveAlertStore.getState().add(JSON.parse(data));
    });
    return disconnect;
  }, []);

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          {connected ? <GreenDot /> : <RedDot />}
          <h3>Live Alerts</h3>
        </div>
      </CardHeader>
      <CardContent>
        {alerts.map(alert => <AlertRow key={alert.id} alert={alert} />)}
      </CardContent>
    </Card>
  );
}
```

#### `components/soc/kpi-cards.tsx`

Four KPI cards: P1 count, P2 count, FP rate, Confirmed hunts. Animated counters with Tremor.

#### `components/soc/mitre-heatmap.tsx`

Grid of MITRE ATT&CK techniques (14 tactics × techniques) colored by detection coverage. Green = covered, yellow = partial, red = gap. Clicking a cell opens a hunt for that technique.

#### `components/soc/incident-playbook-stepper.tsx`

Vertical stepper showing NIST 800-61 phases:
- Each phase has steps with status icons (pending, in-progress, done, automated)
- Click a step to execute it (POST to `/api/blue-team/incident/{id}/execute`)
- Inline result entry

#### `components/soc/alert-table.tsx`

TanStack Table with:
- Columns: Priority, Score, Title, Severity, MITRE, Source, Timestamp, FP, Action
- Server-side sorting, filtering, pagination
- Row click → alert detail drawer
- Bulk actions: acknowledge, escalate, mark FP

#### `components/soc/forensic-timeline.tsx`

Chronological timeline of evidence artifacts with:
- Timestamp, artifact type icon, source, hash verification badge
- Chain of custody expandable section per artifact
- MITRE technique tags

#### `components/soc/hunt-result-card.tsx`

Card showing:
- Hypothesis ID, MITRE technique, status (confirmed/disproved/pending)
- Findings count, affected systems
- IOC list with copy buttons
- "Create Incident" button if confirmed

### Hooks

| Hook | Description |
|------|-------------|
| `useDashboard` | Fetches `/api/blue-team/dashboard`, polls every 30s |
| `useAlerts(filters)` | Fetches triaged alerts with TanStack Query |
| `useIncident(id)` | Fetches incident detail, subscribes to SSE for step updates |
| `useHuntResults()` | Fetches hunt results, subscribes to SSE for progress |
| `useSiemSearch(query)` | Debounced SIEM search |
| `useLiveAlerts()` | SSE connection + alert store |

---

## Part 4: Red Team Campaigns (Surface 2)

### Pages

| Route | File | Description |
|-------|------|-------------|
| `/campaigns` | `app/(campaigns)/page.tsx` | Campaign list with status cards |
| `/campaigns/[id]` | `app/(campaigns)/[id]/page.tsx` | Campaign monitor — live metrics, funnel, timeline |
| `/campaigns/templates` | `app/(campaigns)/templates/page.tsx` | YAML template browser with syntax highlighting |
| `/campaigns/create` | `app/(campaigns)/create/page.tsx` | Campaign creation wizard |
| `/campaigns/generate` | `app/(campaigns)/generate/page.tsx` | AI content generation interface |

### Key Components

#### `components/campaigns/campaign-funnel.tsx`

Sankey/alluvial diagram showing:
```
Sent → Delivered → Opened → Clicked → Credentials Submitted
```
Using Tremor's funnel chart. Numbers + percentages at each stage.

#### `components/campaigns/live-metrics.tsx`

SSE-fed real-time metrics cards:
- Emails Sent, Opened, Clicked, Credentials Submitted
- Engagement rate (computed)
- Sparkline trend (last 10 minutes)

#### `components/campaigns/template-editor.tsx`

YAML editor with:
- Shiki syntax highlighting
- Schema validation (Zod schema matching `YAMLConfigLoader`)
- Save / Validate / Preview tabs
- Template variable picker (insert `{target_name}`, `{company}`, etc.)

#### `components/campaigns/campaign-wizard.tsx`

Multi-step form:
1. Select template (from template list or upload YAML)
2. Configure target profile (role, department, industry, awareness level)
3. Select channels (email, SMS, social)
4. Set schedule and duration
5. Compliance approval checkbox
6. Review & deploy

---

## Part 5: Client Portal (Surface 3)

### Pages

| Route | File | Description |
|-------|------|-------------|
| `/portal/[tenant]` | `app/(portal)/[tenant]/page.tsx` | Overview — engagement summary, timeline, key findings |
| `/portal/[tenant]/reports` | `app/(portal)/[tenant]/reports/page.tsx` | Report list with download buttons |
| `/portal/[tenant]/simulations` | `app/(portal)/[tenant]/simulations/page.tsx` | Simulation results with MITRE coverage |
| `/portal/[tenant]/compliance` | `app/(portal)/[tenant]/compliance/page.tsx` | Compliance status (PCI-DSS, NDPR, CBN) |
| `/portal/[tenant]/recommendations` | `app/(portal)/[tenant]/recommendations/page.tsx` | Prioritized remediation list |

### Design

- **Light theme** — clean, corporate, trustworthy
- **Branded per tenant** — tenant logo, color accent, custom subdomain
- **Read-only** — no edit/create/delete operations
- **Export-first** — PDF/CSV download on every page
- **No operational data** — no live alerts, no IR playbooks, no raw logs

### Key Components

#### `components/portal/compliance-status.tsx`

Grid of compliance frameworks (PCI-DSS, NDPR, CBN) with:
- Status badge: Compliant / Partially Compliant / Non-Compliant
- Findings count per framework
- Expandable detail with specific control gaps

#### `components/portal/report-download.tsx`

PDF/CSV export button using `@react-pdf/renderer`:
- Executive summary PDF
- Technical findings PDF
- Compliance report PDF
- Raw data CSV

#### `components/portal/simulation-results.tsx`

Card list of simulations run against the tenant:
- Scenario name, threat type, date, success rate
- MITRE techniques covered
- Click → detail view with recommendations

---

## Part 6: Internal Admin Panel (Surface 4)

### Pages

| Route | File | Description |
|-------|------|-------------|
| `/admin` | `app/(admin)/page.tsx` | System health — API, SIEM, DB, LLM provider status |
| `/admin/config` | `app/(admin)/config/page.tsx` | Edit config.yaml via form |
| `/admin/users` | `app/(admin)/users/page.tsx` | User management table |
| `/admin/templates` | `app/(admin)/templates/page.tsx` | Template management |
| `/admin/rules` | `app/(admin)/rules/page.tsx` | Detection rule generator |
| `/admin/deployments` | `app/(admin)/deployments/page.tsx` | Client deployment configs |

### Key Components

#### `components/admin/system-health.tsx`

Grid of service status cards:
- API server (healthy/degraded/down)
- SIEM connection (platform, URL, last check)
- Database (Cosmos DB / PostgreSQL)
- LLM providers (list with status per provider)
- VM operators (if configured)
- Neo4j (for RAG)

Each card has a refresh button and last-checked timestamp.

#### `components/admin/config-editor.tsx`

Form-based config editor with sections matching `config.yaml`:
- LLM Providers (add/remove providers, set API keys)
- Safety Settings (thresholds, blocked content types)
- Logging (level, format, destinations)
- Defense Team (SIEM config, EDR config)
- Quantum (scan targets, migration standards)

Changes are validated against the Pydantic config schema before saving.

#### `components/admin/rule-generator.tsx`

Detection rule generation interface:
1. Select MITRE technique (dropdown with search)
2. Select target platform (Splunk, Elastic, Sentinel, Sigma)
3. Configure rule parameters
4. Generate → preview generated rule
5. Validate → run rule validator
6. Export → download rule file

---

## Part 7: Shared Components

### `components/shared/` — Cross-surface components

| Component | Used By | Description |
|-----------|---------|-------------|
| `severity-badge.tsx` | SOC, Campaigns, Portal | Color-coded severity badge |
| `mitre-badge.tsx` | SOC, Campaigns, Portal | MITRE technique ID badge with tooltip |
| `status-badge.tsx` | All | Generic status badge (open/closed/active/etc.) |
| `data-table.tsx` | SOC, Admin, Portal | Reusable TanStack Table wrapper |
| `loading-skeleton.tsx` | All | Skeleton loaders matching component shapes |
| `empty-state.tsx` | All | "No data" illustration with optional CTA |
| `error-boundary.tsx` | All | React error boundary with fallback UI |
| `page-header.tsx` | All | Title, subtitle, actions slot |
| `sidebar-nav.tsx` | SOC, Campaigns, Admin | Collapsible sidebar with active state |
| `topbar.tsx` | All | Search, notifications, user menu |
| `command-palette.tsx` | SOC, Admin | Cmd+K command palette for quick navigation |
| `date-range-picker.tsx` | SOC, Campaigns, Portal | Time range selector |
| `json-viewer.tsx` | SOC, Admin | Collapsible JSON tree with syntax highlighting |
| `yaml-viewer.tsx` | Campaigns, Admin | YAML syntax highlighting with Shiki |
| `confirm-dialog.tsx` | All | Confirmation modal for destructive actions |
| `toast.tsx` | All | Toast notifications (success, error, info) |

---

## Part 8: Design System

### `styles/globals.css`

```css
@tailwind base;
@tailwind components;
@tailwind utilities;

@layer base {
  :root {
    --color-bg: 10 14 20;
    --color-surface: 17 22 31;
    --color-elevated: 26 32 48;
    --color-border: 30 39 56;
    --color-text-primary: 225 231 239;
    --color-text-secondary: 139 149 167;
  }
}

@layer components {
  .card { @apply bg-surface border border-border rounded-lg; }
  .btn-primary { @apply bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-md; }
  .btn-danger { @apply bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-md; }
  .input { @apply bg-elevated border border-border rounded-md px-3 py-2 text-text-primary; }
}
```

### Color Mapping (severity → Tailwind)

```typescript
// lib/utils/colors.ts
export const severityColors: Record<Severity, string> = {
  critical: "text-red-500 bg-red-500/10 border-red-500/30",
  high: "text-orange-500 bg-orange-500/10 border-orange-500/30",
  medium: "text-yellow-500 bg-yellow-500/10 border-yellow-500/30",
  low: "text-green-500 bg-green-500/10 border-green-500/30",
};

export const priorityColors: Record<Priority, string> = {
  P1: "text-red-500 bg-red-500/10",
  P2: "text-orange-500 bg-orange-500/10",
  P3: "text-yellow-500 bg-yellow-500/10",
  P4: "text-blue-500 bg-blue-500/10",
};
```

---

## Part 9: Testing

### Frontend Tests

| Type | Tool | Files |
|------|------|-------|
| Unit | Vitest | Component rendering, hook behavior, utility functions |
| Integration | Vitest + MSW | API mocking, TanStack Query hooks |
| E2E | Playwright | Full user flows per surface |

#### E2E Test Suites

```
tests/e2e/
├── soc/
│   ├── dashboard.spec.ts          # Dashboard loads, KPIs render
│   ├── alert-triage.spec.ts       # View alerts, mark FP, escalate
│   ├── incident-flow.spec.ts      # Create incident, execute steps, generate report
│   └── threat-hunt.spec.ts        # List hypotheses, execute, view results
├── campaigns/
│   ├── campaign-list.spec.ts      # List campaigns, filter by status
│   └── campaign-detail.spec.ts    # View live metrics, funnel chart
├── portal/
│   └── client-portal.spec.ts      # Login as client, view reports, download PDF
└── admin/
    ├── system-health.spec.ts      # Health page loads, shows service status
    └── config-edit.spec.ts        # Edit config, validate, save
```

### Backend Tests

```
tests/unit/
├── test_auth.py                   # JWT creation, verification, role checks
├── test_blue_team_router.py       # Each endpoint with mock blue team modules
├── test_campaigns_router.py       # Campaign endpoints with mock engine
├── test_portal_router.py          # Portal endpoints with tenant scoping
├── test_admin_router.py           # Admin endpoints
└── test_sse.py                    # SSE stream endpoints
```

### Verification

```bash
# Backend
pytest tests/unit/test_auth.py tests/unit/test_blue_team_router.py -v
pytest tests/unit/test_campaigns_router.py tests/unit/test_portal_router.py -v
ruff check vorsyghta/core/auth.py vorsyghta/api/routers/blue_team.py
mypy vorsyghta/core/auth.py

# Frontend
pnpm vitest run
pnpm playwright test
pnpm tsc --noEmit
pnpm lint
```

---

## Part 10: Deployment

### Frontend

| Environment | Platform | URL |
|-------------|----------|-----|
| Production | Vercel | `vorsyghta.com` |
| Staging | Vercel (preview) | `staging.vorsyghta.com` |
| Local | `next dev` | `localhost:3000` |

### Environment Variables (frontend)

```bash
NEXT_PUBLIC_API_URL=https://api.vorsyghta.com
NEXTAUTH_URL=https://vorsyghta.com
NEXTAUTH_SECRET=<random-32-char-string>
```

### Backend

The FastAPI backend runs on the existing infrastructure (Huawei Cloud CCE or Docker). Add:

```bash
JWT_SECRET=<random-32-char-string>
JWT_ALGORITHM=HS256
JWT_ACCESS_EXPIRE_MINUTES=15
JWT_REFRESH_EXPIRE_DAYS=7
CORS_ORIGINS=https://vorsyghta.com,https://www.vorsyghta.com
```

### Docker Compose (local dev)

Add to existing `docker-compose.yml`:

```yaml
services:
  web:
    build: ./vorsyghta-web
    ports:
      - "3000:3000"
    environment:
      - NEXT_PUBLIC_API_URL=http://localhost:8000
      - NEXTAUTH_URL=http://localhost:3000
      - NEXTAUTH_SECRET=dev-secret-change-in-production
    depends_on:
      - api
```

---

## Implementation Order

### Phase 1: Foundation (Week 1-2)

1. Backend auth (`vorsyghta/core/auth.py`, `vorsyghta/api/routers/auth.py`)
2. Blue team API router (`vorsyghta/api/routers/blue_team.py`) — all endpoints
3. SSE router (`vorsyghta/api/websocket.py`)
4. Register routers in `api/main.py`, update CORS
5. Next.js project init, Tailwind, shadcn/ui
6. Auth flow (login page, NextAuth config, middleware)
7. API client (`lib/api/client.ts`) + type generation from OpenAPI
8. Zustand stores
9. Shared components (badges, tables, layout shells)

### Phase 2: SOC Console (Week 3-4)

1. SOC layout with sidebar
2. Dashboard page (KPI cards, MITRE heatmap, active incidents)
3. Live alert feed (SSE-connected)
4. Alerts table + detail drawer
5. Triage queue
6. Incident list + detail with playbook stepper
7. Threat hunting page
8. SIEM search page
9. Log analysis page
10. Forensics page

### Phase 3: Red Team Campaigns (Week 5-6)

1. Campaigns layout
2. Campaign list with status cards
3. Campaign detail with live metrics + funnel
4. Template browser with YAML viewer
5. Campaign creation wizard
6. AI content generation interface

### Phase 4: Client Portal (Week 7-8)

1. Portal layout (light theme, branded)
2. Overview page
3. Reports page with PDF export
4. Simulations page
5. Compliance status page
6. Recommendations page

### Phase 5: Internal Admin (Week 9-10)

1. Admin layout
2. System health dashboard
3. Config editor
4. User management
5. Template management
6. Detection rule generator
7. Deployment configs viewer

### Phase 6: Polish & Deploy (Week 11-12)

1. E2E test suites (Playwright)
2. Performance optimization (code splitting, lazy loading, image optimization)
3. SEO for landing page + client portal
4. Vercel deployment + custom domain
5. Production CORS + JWT secrets
6. Monitoring (Vercel Analytics + existing Prometheus/Grafana)

---

## Scope Estimate

### Backend

| File | Type | Lines (est.) |
|------|------|-------------|
| `vorsyghta/core/auth.py` | New | ~200 |
| `vorsyghta/api/routers/auth.py` | New | ~150 |
| `vorsyghta/api/routers/blue_team.py` | New | ~400 |
| `vorsyghta/api/routers/campaigns.py` | New | ~250 |
| `vorsyghta/api/routers/portal.py` | New | ~150 |
| `vorsyghta/api/routers/admin.py` | New | ~200 |
| `vorsyghta/api/websocket.py` | New | ~150 |
| `vorsyghta/api/main.py` | Edit | ~30 changed |
| `vorsyghta/api/routers/__init__.py` | Edit | ~10 changed |
| Backend tests | New | ~800 |
| **Backend total** | | **~2,340** |

### Frontend

| Area | Files | Lines (est.) |
|------|-------|-------------|
| Foundation (config, auth, API client, stores, types) | ~20 | ~1,500 |
| Shared components | ~15 | ~1,200 |
| SOC Console (10 pages + 8 components + 6 hooks) | ~24 | ~3,500 |
| Red Team Campaigns (5 pages + 4 components) | ~9 | ~1,500 |
| Client Portal (5 pages + 3 components) | ~8 | ~1,000 |
| Internal Admin (6 pages + 3 components) | ~9 | ~1,200 |
| E2E tests | ~8 | ~600 |
| **Frontend total** | **~93** | **~10,500** |

### Grand total: ~12,840 lines across ~105 files

---

## Risks & Open Questions

### Backend

- **Auth complexity:** Phase 1 uses simple JWT + password. Phase 2 needs OAuth (GitHub, Entra ID). The `AuthContext` abstraction supports both, but the user store needs to be designed for Phase 2 from the start.
- **SSE vs WebSocket:** SSE is simpler but one-way. If we need collaborative incident response (multiple analysts editing the same incident), we'll need WebSocket. Mitigation: design the SSE router so it can be upgraded to WebSocket without changing the frontend event handling.
- **Blue team router is a thin wrapper:** All blue team modules are in-memory (no persistence yet). The router endpoints will work but data won't survive restarts. Mitigation: Phase 2 adds Cosmos DB persistence (already deployed — `vorsyghta-blueteam-db` with containers for incidents, alerts, forensic-artifacts, hunt-results, triage-results).
- **Rate limiting:** No rate limiting on the API. The UI's TanStack Query polling could hammer the backend. Mitigation: add `slowapi` rate limiter to FastAPI, set sensible polling intervals (30s for dashboard, 5s for live feeds via SSE).

### Frontend

- **OpenAPI type generation:** The FastAPI OpenAPI schema doesn't cover all blue team modules yet (they're CLI-only). The blue team router needs to be implemented first, then types can be generated. Mitigation: implement the router first, then run type generation.
- **Theme complexity:** SOC console is dark, client portal is light. Need to support both themes in the same Next.js app. Mitigation: use `darkMode: "class"` in Tailwind and toggle the `dark` class on the root element per surface.
- **Real-time data volume:** If the SIEM is producing hundreds of alerts per minute, the SSE stream could overwhelm the browser. Mitigation: server-side filtering (only P1/P2 alerts on SSE), client-side throttling (max 100 alerts in the live feed, oldest dropped).
- **Client portal tenant isolation:** Must ensure clients can only see their own data. Mitigation: `require_tenant` dependency on all portal endpoints, tenant_id from JWT (not from URL path), server-side query filtering.
- **YAML editor:** Building a good YAML editor in-browser is non-trivial. Mitigation: use Shiki for highlighting + a simple textarea. Phase 2 can integrate Monaco Editor for full IDE-like experience.

### Deployment

- **Vercel + FastAPI on different domains:** CORS and cookie domain issues. Mitigation: use `SameSite=Lax` cookies, configure CORS origins explicitly, consider a reverse proxy (nginx/Caddy) that serves both under the same domain.
- **Environment variable management:** Next.js needs `NEXT_PUBLIC_*` for client-side vars. The API URL must be public. JWT secret must stay server-side only. Mitigation: NextAuth handles this correctly — the JWT secret is only used in API routes/middleware, never exposed to the client.
