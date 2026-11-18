# Vorsyghta Visual Brand Identity

**Version:** 1.0  
**Last Updated:** 2026-11-08  
**Source:** frontend/src/app/globals.css, frontend/src/app/brand/page.tsx, frontend/src/components/brand/*, frontend/src/app/page.tsx hero

> This document codifies the visual system currently implemented in the Next.js frontend. It is derived from measured code, not aspirational mockups. All colors, typography and motion tokens are sourced from `globals.css` and brand components.

---

## 1. Brand Essence

**Positioning:** Industrial control-room cyber operations. Authorized use, evidence first.

**Mood:** Futuristic Megastructures, control-room, steel canvas with warm paper surfaces. High contrast midnight backgrounds, grid overlays, subtle motion.

**Hero narrative:** The hero section uses a full-bleed video `/videos/hero.mp4` ~5.3MB, autoplay muted loop, with brightness 0.55 contrast 1.05, overlaid with a dark gradient and 48px grid. Headline: *Run authorized security validation. Keep the evidence.* Eyebrow: *Authorized use / evidence first*.

The video asset is present but content not transcribed here; in production it depicts a control-room / megastructure environment consistent with the moodboard.

---

## 2. Color System

All tokens defined in `frontend/src/app/globals.css :root`.

### Structural
- `--midnight: #0b0f14` — primary backgrounds, nav, hero base
- `--ink-violet: #1e293b` — body text on warm
- `--violet-deep: #2c3e50` — borders, hairlines
- `--violet-mid: #2bbfd7` — signal cyan / accent
- `--violet-soft: #b9d4e2` — subtle text

### Surfaces
- `--warm: #e8e0d5` — page background
- `--warm-deep: #d8cfc2`
- `--paper: #f5f3f0` — cards, light sections
- `--white: #ffffff`

### Signal / Actions
- `--lime: #ff7a1a` — primary action orange, selection, eyebrow, live dot
- `--lime-dark: #7a3a00`
- `--pink: #4fb3c6` — secondary accent, shadows
- `--red: #b32638`, `--red-soft: #fbeef0`
- `--green: #1f6a4a`, `--green-soft: #e4f7ee`
- `--amber: #f59e0b`, `--amber-soft: #fff4d6`

### Hairlines & Muted
- `--hairline-dark: #2c3e50`
- `--hairline-light: #d1c7b8`
- `--muted-dark: #6b7280`
- `--muted-light: #5c6a6e`

### Brand page mapping
From `frontend/src/app/brand/page.tsx` MoodCard system:
- Primary Action: Orange #ff7a1a — CTAs, highlights
- Signal Cyan: #2bbfd7 — Provenance, chips
- Midnight Canvas: #0b0f14 — Marketing background
- Warm Paper: #f5f3f0 — Transactional surfaces
- Steel Border: #2c3e50 — Card hairlines
- Control Room: moodboard crop — Dashboard texture

---

## 3. Typography

Tokens from globals.css:
- `--font-sans: "Inter", "Segoe UI", system-ui, Helvetica, Arial, sans-serif`
- `--font-display: "Inter", "Segoe UI", system-ui, Helvetica, Arial, sans-serif`
- `--font-mono: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace`

Usage:
- Headlines: font-display, weight 900, letter-spacing -0.045em to -0.02em, line-height 0.93-1.05
- Eyebrow / kicker: font-mono, uppercase, letter-spacing 0.13em, weight 800, color --lime
- Body: font-sans 16px, line-height 1.55
- UI labels: font-mono for provenance, evidence states, IDs

---

## 4. Logo & Wordmark

Wordmark class `.wordmark`:
- Uppercase, font-display, weight 900, letter-spacing 0.03em
- Mark: 2rem circle, border 1px solid --lime, rotated -8deg, rounded 50% 50% 4px 50%
- Color: --lime on dark backgrounds

No separate SVG logo file is committed; wordmark is CSS-constructed.

---

## 5. Layout & Grid

- Page width: `var(--page-width: 1280px)`, centered with 3rem gutters
- Section spacing: `clamp(5rem, 9vw, 9rem)`
- Grid overlay: 48px / 52px grid with 4% white, mix-blend overlay, used in hero and mood hero
- Shadows: `--shadow-hard: 7px 7px 0 var(--midnight)` for cards, hard-edged industrial look

---

## 6. Components

### Buttons
- Base: uppercase, weight 850, border 2px, radius 4px
- Primary: `--midnight` bg, white text, shadow 4px 4px 0 var(--pink)
- Light: white bg, midnight text, shadow 4px 4px 0 --lime
- Outline dark: transparent, --violet-mid border
- Hover: translate -2px -2px

### Evidence Contract Card
- Border 1px --violet-mid, background rgba(21,15,35,0.8), rotated 1.5deg, shadow 11px 11px 0 rgba(250,127,170,0.18)
- Used on landing hero to surface provenance contract

### Principle Strip
- Background --lime, text --midnight, monospace uppercase
- 4-column grid, borders midnight

### Data Panels / MoodCard
- Border 1px hairline-light, background --paper, radius 8px
- Status chips: good/warn/bad/idle with green/amber/red backgrounds
- MoodCard accent bars: orange/cyan/steel

### Forms
- Inputs: border --hairline-light, background --white/paper, focus ring --pink 35%
- Labels weight 800, size 0.83rem

---

## 7. Motion

Tokens:
- `--motion-fast: 140ms`
- `--motion-base: 260ms`
- `--motion-slow: 600ms`
- `--ease-out-soft: cubic-bezier(0.22,1,0.36,1)`
- `--ease-snap: cubic-bezier(0.34,1.56,0.64,1)`

Reveals use CSS view-timeline, stagger via `reveal-stagger`. Ambient hero geometry drifts slowly. Respects `prefers-reduced-motion`.

---

## 8. Hero Section

Implemented in `frontend/src/app/page.tsx` and `MoodHero` component.

- Full viewport hero, min-height 720px
- Background video `/videos/hero.mp4` with `autoPlay muted loop playsInline`, opacity 0.35, object-fit cover
- Overlay gradient 100deg rgba(11,15,20,0.85) → rgba(11,15,20,0.45)
- Grid overlay 52px
- Copy left, evidence contract right
- Decorative rotated squares in pink/lime at corners
- Headline mark highlight: inline background --lime, color --midnight, rotate -1deg

Video asset exists at `frontend/public/videos/hero.mp4` 5.3MB. Visual content per moodboard: futuristic control room / megastructure.

---

## 9. Page Types

- **Marketing shell**: dark sections `--ink-violet`, light sections `--paper`, warm sections `--warm`
- **Account shell**: background `--ink-violet` with radial gradients pink/lime
- **App shell**: background `--warm`, header `--midnight`

---

## 10. Usage Guidelines

- Always pair midnight backgrounds with white/lime text; never use pure black.
- Use grid overlay sparingly — hero and brand sections only.
- Provenance states must be color-coded consistently: Measured, Simulated, Generated, Validated, Unavailable.
- Orange is primary action only. Cyan is signal/provenance.
- Maintain hard shadows for cards to reinforce industrial/control-room feel.
- No gradients except hero overlays and radial accents in auth.
- Typography hierarchy: display for H1/H2, sans for body, mono for metadata/IDs.

---

## 11. Assets Inventory

- `/frontend/public/videos/hero.mp4` — hero background video
- `/frontend/public/videos/hero-poster.jpg` — poster
- `/frontend/public/backgrounds/control-room.jpg` — brand background image
- No external font files; system fonts via Inter fallback

---

## 12. References

- `frontend/src/app/globals.css` — design tokens
- `frontend/src/app/brand/page.tsx` — brand system definition
- `frontend/src/components/brand/MoodHero.tsx` — hero component
- `frontend/src/app/page.tsx` — landing hero implementation
- `docs/content-bible.md` — brand copy and messaging

---

**Maintained by:** Design / Frontend  
**Next review:** 2026-12-08
