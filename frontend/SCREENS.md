# Vorsyghta Frontend Screens

> Verified inventory of every `page.tsx` route under `frontend/src/app`.
> Last verified: 2026-10-24 (37 route files: 36 rendered screens + 1 redirect stub).

## Public / Marketing (7)

| Route | File | Notes |
|---|---|---|
| `/` | `src/app/page.tsx` | Landing page |
| `/brand` | `src/app/brand/page.tsx` | Brand guidelines (Mood components) |
| `/pricing` | `src/app/pricing/page.tsx` | Pricing |
| `/start-trial` | `src/app/start-trial/page.tsx` | Trial signup entry |
| `/legal/terms` | `src/app/legal/terms/page.tsx` | Terms of service |
| `/legal/privacy` | `src/app/legal/privacy/page.tsx` | Privacy policy |
| `/legal/acceptable-use` | `src/app/legal/acceptable-use/page.tsx` | Acceptable use |

## Auth (3)

| Route | File | Notes |
|---|---|---|
| `/sign-in` | `src/app/sign-in/page.tsx` | Sign-in; OIDC/Authentik flow target |
| `/register` | `src/app/register/page.tsx` | Registration |
| `/forgot-password` | `src/app/forgot-password/page.tsx` | Password recovery request |

**Gap:** there is no `/reset-password` (token redemption) screen. The reset
flow currently ends at request-time only.

## Individual Onboarding (5)

| Route | File |
|---|---|
| `/onboarding` | `src/app/onboarding/page.tsx` |
| `/onboarding/profile` | `src/app/onboarding/profile/page.tsx` |
| `/onboarding/use-cases` | `src/app/onboarding/use-cases/page.tsx` |
| `/onboarding/environments` | `src/app/onboarding/environments/page.tsx` |
| `/onboarding/review` | `src/app/onboarding/review/page.tsx` |

## Enterprise Onboarding (11)

| Route | File |
|---|---|
| `/onboarding-enterprise` | `src/app/onboarding-enterprise/page.tsx` |
| `/onboarding-enterprise/welcome` | `src/app/onboarding-enterprise/welcome/page.tsx` |
| `/onboarding-enterprise/org` | `src/app/onboarding-enterprise/org/page.tsx` |
| `/onboarding-enterprise/identity` | `src/app/onboarding-enterprise/identity/page.tsx` |
| `/onboarding-enterprise/team` | `src/app/onboarding-enterprise/team/page.tsx` |
| `/onboarding-enterprise/environments` | `src/app/onboarding-enterprise/environments/page.tsx` |
| `/onboarding-enterprise/integrations` | `src/app/onboarding-enterprise/integrations/page.tsx` |
| `/onboarding-enterprise/compliance` | `src/app/onboarding-enterprise/compliance/page.tsx` |
| `/onboarding-enterprise/workspace` | `src/app/onboarding-enterprise/workspace/page.tsx` |
| `/onboarding-enterprise/verify` | `src/app/onboarding-enterprise/verify/page.tsx` |
| `/onboarding-enterprise/review` | `src/app/onboarding-enterprise/review/page.tsx` |
| `/onboarding-enterprise/first-value` | `src/app/onboarding-enterprise/first-value/page.tsx` |

## App Area (10 real screens + 1 stub)

| Route | File | Notes |
|---|---|---|
| `/app` | `src/app/app/page.tsx` | Live-data workspace home |
| `/(app)/dashboard` | `src/app/(app)/dashboard/page.tsx` | **Redirect stub** → `/app`. Legacy "Command Dashboard" mock was removed (no-fabrication rule). |
| `/app/templates` | `src/app/app/templates/page.tsx` | Scenario templates index |
| `/app/templates/[category]/[name]` | `src/app/app/templates/[category]/[name]/page.tsx` | Template detail (dynamic) |
| `/app/environments` | `src/app/app/environments/page.tsx` | Environments |
| `/app/intelligence` | `src/app/app/intelligence/page.tsx` | Threat intelligence |
| `/app/exercises` | `src/app/app/exercises/page.tsx` | Exercises |
| `/app/disclosures` | `src/app/app/disclosures/page.tsx` | Disclosures |
| `/app/findings` | `src/app/app/findings/page.tsx` | Findings |
| `/app/settings/billing` | `src/app/app/settings/billing/page.tsx` | Billing settings |

## Known Gaps / Watch Items

1. **No `/reset-password` screen** — forgot-password flow has no token
   redemption UI. The real API's password-reset completion has no frontend
   surface yet.
2. **`/(app)/dashboard`** is a permanent redirect stub; the `(app)` route group
   contains nothing else. Candidate for removal once no external links
   reference it.
3. Auth screens (`sign-in`, `register`, `forgot-password`) are covered by
   `tests/e2e/auth.spec.ts`; onboarding and app screens have no e2e coverage.
