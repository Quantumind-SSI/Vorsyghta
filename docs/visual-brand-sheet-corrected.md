# Vorsyghta Visual Brand Sheet — Production Accurate

**Source of truth**
- docs/visual-brand-identity.md
- docs/content-bible.md
- frontend/src/app/globals.css
- frontend/src/app/brand/page.tsx

This sheet corrects copy, hex values and principles to match measured code.

## Brand Essence

Positioning: Industrial control-room cyber operations. Authorized use, evidence first.

Mood: Futuristic Megastructures, control-room, steel canvas with warm paper surfaces. High contrast midnight backgrounds, grid overlays, subtle motion.

Hero copy, measured:
Eyebrow: Authorized use / evidence first
H1: Run authorized security validation. Keep the evidence.
Lead: Vorsyghta helps security teams scope, execute, observe, and report controlled adversarial assessments with human approval and explicit result provenance.
Tagline: Run authorized security validation. Keep the evidence.

Do NOT use: See. Verify. Act.

## Color Palette — Measured Tokens

Structural
- Midnight Canvas #0b0f14 — primary backgrounds, nav, hero base
- Ink Violet #1e293b — body text on warm
- Violet Deep #2c3e50 — borders, hairlines
- Violet Mid / Signal Cyan #2bbfd7 — signal / provenance
- Violet Soft #b9d4e2 — subtle text

Surfaces
- Warm #e8e0d5
- Warm Deep #d8cfc2
- Paper #f5f3f0
- White #ffffff

Signal / Actions
- Primary Action Orange #ff7a1a — CTAs, highlights, live dot
- Lime Dark #7a3a00
- Pink Accent #4fb3c6 — secondary accent, shadows
- Red #b32638 / Red Soft #fbeef0
- Green #1f6a4a / Green Soft #e4f7ee
- Amber #f59e0b / Amber Soft #fff4d6

Hairlines & Muted
- Hairline Dark #2c3e50
- Hairline Light #d1c7b8
- Muted Dark #6b7280
- Muted Light #5c6a6e

Note: Ink Violet is #1e293b, not #1e29hce.

## Typography — Measured

- Sans / Display: "Inter", "Segoe UI", system-ui, Helvetica, Arial, sans-serif
- Mono: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace

Usage:
Headlines: font-display weight 900, letter-spacing -0.045em to -0.02em, line-height 0.93-1.05
Eyebrow / kicker: font-mono uppercase, letter-spacing 0.13em, weight 800, color #ff7a1a
Body: font-sans 16px, line-height 1.55
UI labels: font-mono for provenance, evidence states, IDs

## Logo & Wordmark — Measured

Wordmark class `.wordmark`:
Uppercase, font-display weight 900, letter-spacing 0.03em
Mark: 2rem circle, border 1px solid #ff7a1a, rotated -8deg, rounded 50% 50% 4px 50%
Color: #ff7a1a on dark backgrounds

No separate SVG logo is committed; wordmark is CSS-constructed.

## Principles Strip — Measured

From content-bible.md §7:
Self-hostable · Local model support · MITRE ATT&CK mapping · Open-core repository

Do NOT use: Security by Design, Evidence First, Operational Intelligence, Scalable Resilience unless explicitly approved as marketing copy.

## Components — Measured

Buttons
Base: uppercase, weight 850, border 2px, radius 4px
Primary: #0b0f14 bg, white text, shadow 4px 4px 0 #4fb3c6
Light: white bg, #0b0f14 text, shadow 4px 4px 0 #ff7a1a
Outline dark: transparent, #2bbfd7 border
Hover: translate -2px -2px

Evidence Contract Card
Border 1px #2bbfd7, background rgba(21,15,35,0.8), rotated 1.5deg, shadow 11px 11px 0 rgba(250,127,170,0.18)

Principle Strip
Background #ff7a1a, text #0b0f14, monospace uppercase, 4-column grid, borders midnight

Data Panels / MoodCard
Border 1px hairline-light, background #f5f3f0, radius 8px
Status chips: good/warn/bad/idle with green/amber/red

## Layout & Motion

Page width var(--page-width: 1280px), 3rem gutters
Section spacing clamp(5rem, 9vw, 9rem)
Grid overlay 48px/52px with 4% white, mix-blend overlay, hero and brand sections only
Shadow hard: 7px 7px 0 #0b0f14
Motion: --motion-fast 140ms, --motion-base 260ms, --motion-slow 600ms

## Usage Guidelines

- Always pair midnight backgrounds with white/lime text; never use pure black.
- Use grid overlay sparingly — hero and brand sections only.
- Provenance states must be color-coded consistently: Measured, Simulated, Generated, Validated, Unavailable.
- Orange is primary action only. Cyan is signal/provenance.
- Maintain hard shadows for cards.
- No gradients except hero overlays and radial accents in auth.

## Assets Inventory

- /frontend/public/videos/hero.mp4 — hero background video
- /frontend/public/videos/hero-poster.jpg — poster
- /frontend/public/backgrounds/control-room.jpg — brand background

References:
docs/visual-brand-identity.md
docs/content-bible.md
frontend/src/app/globals.css
frontend/src/app/brand/page.tsx
