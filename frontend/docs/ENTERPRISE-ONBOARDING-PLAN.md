# Enterprise Comprehensive Onboarding Plan

## Current state
4 steps:
1. Organization profile
2. Use cases
3. Environments
4. Review & activate

Gaps vs state-of-the-art enterprise SaaS onboarding:
- No welcome / progress overview with estimated time
- No account verification / email validation
- No legal & data residency selection
- No SSO / identity provider setup
- No seat management / team invites
- No security posture / compliance mapping depth
- No integration connector configuration
- No workspace / project scaffolding
- No guided first value milestone
- No admin preferences / audit logging config

## State of art references
Okta, Snowflake, Databricks, SentinelOne: progressive profiling, value-based steps, role-based paths, in-product tours after activation, self-serve + assisted options, compliance attestation.

## Proposed comprehensive journey
Total 9 steps, role-aware branching, saves to tenant as you go.

Step 0 - Welcome & Progress
Step 1 - Account verification & legal acceptance
Step 2 - Organization profile & data residency
Step 3 - Security & compliance mapping
Step 4 - Identity & access, SSO/SCIM
Step 5 - Team, roles & invites
Step 6 - Environments & connectors selection
Step 7 - Integrations & data sources
Step 8 - Workspace configuration & first project scaffold
Step 9 - Guided first value & activation review

Each step has save & continue, back navigation, skip where safe, and contextual help.

Screens mapped to routes:
- /onboarding-welcome
- /onboarding/verify
- /onboarding/org
- /onboarding/compliance
- /onboarding/identity
- /onboarding/team
- /onboarding/environments-v2
- /onboarding/integrations
- /onboarding/workspace
- /onboarding/first-value
- /onboarding/review-enterprise

## Enterprise considerations
- Role-based paths: CISO sees compliance & identity first; Analyst sees workspace first.
- Data residency selection mandatory for regulated regions.
- SSO setup with guided metadata upload.
- SCIM provisioning toggle.
- Acceptable use attestation with explicit sanctioned-target checkbox per environment.
- Audit log retention preference.
- First value milestone: create first exercise or import first environment, not just activate.

Screens will use MoodNav, MoodHero, MoodCard components with new brand palette.
