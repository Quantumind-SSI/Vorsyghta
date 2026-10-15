# Vorsyghta Frontend UI/UX Kit

## Overview
Vorsyghta frontend is a Next.js 16 marketing and SaaS application for authorized security validation. It uses a deep slate midnight canvas with orange primary action and warm paper surfaces, aligned to the Futuristic Megastructures Control Centre moodboard and hero video. The kit consolidates design tokens, components, pages, and assets from the codebase and design system.

**Assets**
- Hero video: `frontend/public/videos/hero.mp4`
- Logo: `../logo.jpeg`
- No raster images in public; UI is CSS-driven with CSS grid patterns.

## Design Tokens

### CSS Variables `globals.css :root`
Structural base
- `--midnight: #0b0f14`
- `--ink-violet: #1e293b`
- `--violet-deep: #2c3e50`
- `--violet-mid: #2bbfd7`
- `--violet-soft: #b9d4e2`

Surfaces
- `--warm: #e8e0d5`
- `--warm-deep: #d8cfc2`
- `--paper: #f5f3f0`
- `--white: #ffffff`

Signal
- `--lime: #ff7a1a`
- `--lime-dark: #7a3a00`
- `--pink: #4fb3c6`
- `--red: #b32638`
- `--green: #1f6a4a`
- `--amber: #f59e0b`

Hairlines & type
- `--hairline-dark: #2c3e50`
- `--hairline-light: #d1c7b8`
- `--muted-dark: #6b7280`
- `--muted-light: #5c6a6e`
- `--radius-sm: 4px`
- `--radius-md: 8px`
- `--radius-lg: 16px`
- `--page-width: 1280px`
- `--font-sans: "Inter", "Segoe UI", system-ui, Helvetica, Arial, sans-serif`
- `--font-display: "Inter", "Segoe UI", system-ui, Helvetica, Arial, sans-serif`
- `--font-mono: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace`

### TypeScript Tokens `src/lib/design/tokens.ts`
palette: midnight, inkViolet, violetDeep, violetMid, violetSoft, warm, paper, white, lime, limeDark, pink, red, green, amber, hairlineDark, hairlineLight, mutedDark, mutedLight

provenanceColors
- Measured: #3fd6d0
- Simulated: #ff8a00
- Generated: #7fb3fa
- Validated: #1f6a4a
- Unavailable: #5c6a6e

radius sm/md/lg, spacing xs/sm/md/lg/xl

## Visual Language

From `design-md/sentry/DESIGN.md` updated to moodboard:
- Two-polarity canvas: deep slate midnight for marketing, warm paper for transactional pages.
- Orange primary action for CTAs and keyword highlights, cyan for secondary signals and provenance.
- Teal secondary punctuation for critical severity.
- Uppercase eyebrow and button caps with tracking, industrial grid overlays.
- Megastructure control-room textures, steel grid patterns, orange accent bars.

## Components

### Brand-aligned
- `MoodNav` src/components/brand/MoodNav.tsx – sticky midnight nav with blurred backdrop, orange primary.
- `MoodHero` src/components/brand/MoodHero.tsx – full-bleed hero with video background, grid overlay, orange CTA.
- `MoodCard` src/components/brand/MoodCard.tsx – console data panel with steel border and orange/cyan accent.

### Public
- `PublicHeader` src/components/public-header.tsx
  Wordmark + desktop-nav + desktop-actions + mobile <details> menu.
  Navigation: Workflow, Evidence, Safety, Pricing, Docs.
  CTAs: Sign in, Start trial.

- `PublicFooter` src/components/public-footer.tsx
  Rule divider, wordmark, evidence-first tagline, footer nav.

- `PillarStrip` src/components/pillar-strip.tsx
  Principle strip: Self-hostable, Local model support, MITRE ATT&CK mapping, Open-core repository.

### Auth & Onboarding
- `SignInForm` src/components/sign-in-form.tsx
- `RegisterForm` src/components/register-form.tsx
- `OnboardingForm` src/components/onboarding-form.tsx
- `OnboardingStepNav` src/components/onboarding-step-nav.tsx

### Data & App
- `DataPanel` src/components/data-panel.tsx
- `BadgeProvenance` src/components/badge-provenance.tsx
  Renders provenance badge with color from tokens.

- `BillingActionForm` src/components/billing-action-form.tsx
- `SubmitButton` src/components/submit-button.tsx

### UI primitives from globals.css
- `.button` base with variants:
  - `--primary`: midnight fill, pink shadow
  - `--secondary`: outline midnight
  - `--light`: white fill, lime shadow
  - `--outline-dark`: violet-mid outline
  - `--small`
- `.eyebrow` mono uppercase lime
- `.page-width` container
- Section variants: `.section-dark`, `.section-light`, `.section-warm`
- Hero: `.hero`, `.hero__video`, `.hero__content`, `.evidence-contract`
- Workflow grid: `.workflow-grid`
- Provenance list: `.provenance-list`, `.provenance-list__marker`
- Capability grid: `.capability-grid`
- Safety card: `.safety-card`
- Pricing cards: `.price-card`, `.price-card--team`, `.price-card--enterprise`
- Auth panel: `.auth-panel`, `.auth-panel__context`, `.auth-panel__form`
- App shell: `.application-shell`, `.app-header`, `.dashboard-grid`, `.data-panel`
- Status chips: `.status-chip--good/warn/bad/idle`

## Page Inventory

Marketing
- `/` src/app/page.tsx – Hero with video `/videos/hero.mp4`, workflow, evidence, capability, safety, final CTA
- `/pricing` src/app/pricing/page.tsx – Pricing hero + 3 cards Team, Enterprise, Mission
- `/start-trial` src/app/start-trial/page.tsx
- `/sign-in` src/app/sign-in/page.tsx
- `/register` src/app/register/page.tsx
- `/forgot-password` src/app/forgot-password/page.tsx

Legal
- `/legal/terms`
- `/legal/privacy`
- `/legal/acceptable-use`

Onboarding wizard
- `/onboarding` – step nav
- `/onboarding/profile`
- `/onboarding/use-cases`
- `/onboarding/environments`
- `/onboarding/review`

App
- `/(app)/dashboard` src/app/(app)/dashboard/page.tsx
- `/app` src/app/app/page.tsx
- `/app/findings`
- `/app/templates`
- `/app/templates/[category]/[name]`
- `/app/environments`
- `/app/exercises`
- `/app/intelligence`
- `/app/disclosures`
- `/app/settings/billing`

## Layout Patterns

- Marketing shell: `PublicHeader` + `main` + `PublicFooter`
- Auth shell: `.account-shell` with `.auth-panel` two-column context + form
- App shell: `.application-shell` with `.app-header` and `.app-main` centered
- Section bands: dark/light/warm with `page-width` inner
- Grid systems: 12-col dashboard, 5-col workflow, 3-col capability/pricing

## Assets Usage

- Hero video autoPlay muted loop playsInline with poster placeholder `/videos/hero-poster.jpg`
- Moodboard backgrounds cropped to `frontend/public/backgrounds/` for section textures: hero-bridge.jpg, control-room.jpg, platform.jpg, pillar-thumb.jpg, dark-towers.jpg, cloud-tower.jpg, control-panel.jpg, observer.jpg
- Decorative elements are steel grid overlays, orange accent bars, and CSS masks.
- Wordmark mark is CSS shape with orange border and rotation.

## Responsive Breakpoints
From CSS:
- max-width 960px: hide desktop nav, grid stacks
- max-width 720px: page width shrink, hero min-height auto
- max-width 430px: compact typography, single column

## Implementation Notes

- Next.js 16 with React 19, TypeScript 7, pnpm.
- Styles are global CSS variables, no CSS modules.
- Design system docs live in `design-md/sentry/DESIGN.md` with Sentry-inspired language.
- Provenance system is central to UI: Measured, Simulated, Generated, Validated, Unavailable.

## Kit Deliverables

This document, the token files, and the component source constitute the full UI/UX kit for Vorsyghta frontend. Use `globals.css` for CSS variables, `src/lib/design/tokens.ts` for TS constants, and the component directory for reusable UI.
