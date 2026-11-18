# Vorsyghta Visual Brand Generation Prompts

**Version:** 1.0
**Source:** docs/visual-brand-identity.md, docs/content-bible.md, frontend/src/app/globals.css

> Use these prompts with an image/LMM to generate visual assets consistent with the measured brand system. All colors and tokens are sourced from code.

## Brand constraints

Mood: Industrial control-room cyber operations. Futuristic megastructures, steel canvas with warm paper surfaces. High contrast midnight backgrounds, grid overlays, subtle motion. Authorized use / evidence first.

Palette:
- Midnight canvas #0b0f14
- Warm paper #f5f3f0
- Warm #e8e0d5
- Steel border #2c3e50
- Signal cyan #2bbfd7
- Primary action orange #ff7a1a
- Pink accent #4fb3c6
- Ink violet #1e293b

Typography: Inter for display/sans, SFMono-Regular for metadata/eyebrows.
Eyebrow: uppercase mono, letter-spacing 0.13em, color #ff7a1a.
Headlines weight 900, -0.045em tracking.

Style: 48px/52px grid overlay, hard-edged shadows 7px 7px 0 midnight, rotated cards, no gradients except hero overlays.

## Master generation prompt

Generate a visual brand kit for Vorsyghta, an industrial control-room cyber operations platform. Brand essence: futuristic megastructures, control-room, steel canvas with warm paper surfaces, high contrast midnight backgrounds, grid overlays, subtle motion. Authorized use / evidence first.

Color palette: Midnight canvas #0b0f14, warm paper #f5f3f0, warm #e8e0d5, steel border #2c3e50, signal cyan #2bbfd7, primary action orange #ff7a1a, pink accent #4fb3c6, ink violet #1e293b. Use midnight backgrounds with lime/orange accents, never pure black. Hard-edged shadows: 7px 7px 0 midnight.

Typography: Inter for display and sans, SFMono-Regular for metadata/eyebrows. Eyebrow uppercase mono, letter-spacing 0.13em, color #ff7a1a. Headlines weight 900, -0.045em tracking.

Style cues: 48px/52px grid overlay, control-room dashboards, steel panels, warm paper cards, rotated squares in pink/lime at corners, evidence contract cards rotated ~1.5deg with hard shadow.

Deliverables: hero background illustration in the mood of a futuristic control room/megastructure with grid overlay, wordmark mockup, button set primary/light/outline, evidence contract card, principle strip, data panel with status chips, landing page moodboard.

Constraints: no gradients except hero overlays, maintain industrial control-room feel, keep orange for primary actions only, cyan for provenance/signal.

## Per-asset prompts

### 1. Hero background
Generate a futuristic control-room / megastructure hero background for Vorsyghta. Midnight canvas #0b0f14 base, subtle 52px grid overlay with 4% white mix-blend. Depict steel beams, illuminated control panels, soft ambient glow in signal cyan #2bbfd7 and primary orange #ff7a1a. Industrial, not cinematic. Aspect 16:9.

### 2. Wordmark mockup
Show the Vorsyghta wordmark uppercase, Inter weight 900, letter-spacing 0.03em, color #ff7a1a on midnight #0b0f14 background. Include CSS-constructed mark: 2rem circle, 1px solid #ff7a1a, rotated -8deg, rounded 50% 50% 4px 50%. Minimal, industrial.

### 3. Button set
Three buttons on warm paper #f5f3f0:
- Primary: midnight #0b0f14 bg, white text, shadow 4px 4px 0 #4fb3c6
- Light: white bg, midnight text, shadow 4px 4px 0 #ff7a1a
- Outline dark: transparent, border 2px #2c3e50
Uppercase, weight 850, radius 4px.

### 4. Evidence Contract Card
Card with border 1px #2bbfd7, background rgba(21,15,35,0.8), rotated 1.5deg, shadow 11px 11px 0 rgba(250,127,170,0.18). On midnight background. Mono labels for provenance states.

### 5. Principle Strip
Strip background #ff7a1a, text #0b0f14, mono uppercase. 4-column grid with midnight borders. Items: Self-hostable · Local model support · MITRE ATT&CK mapping · Open-core repository.

### 6. Data Panel / MoodCard
Card border 1px #d1c7b8, background #f5f3f0, radius 8px. Status chips good/warn/bad/idle with green/amber/red. Accent bars orange/cyan/steel.

## Usage notes
- Always pair midnight backgrounds with white/lime text; never use pure black.
- Use grid overlay sparingly — hero and brand sections only.
- Orange is primary action only. Cyan is signal/provenance.
- Maintain hard shadows for cards.
- Provenance states must be color-coded consistently: Measured, Simulated, Generated, Validated, Unavailable.

References:
- docs/visual-brand-identity.md
- docs/content-bible.md
- frontend/src/app/globals.css
