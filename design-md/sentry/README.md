# Ciicerone Design System (Sentry-inspired)

This folder holds the design system adopted for **Ciicerone** — the enterprise
AI-powered cybersecurity threat simulation platform.

## Why this theme

Ciicerone is a security/threat-alerting product with a developer + enterprise
dual audience, heavy on audit logs, MITRE ATT&CK references, and code (Python /
FastAPI / YAML scenario definitions). The Sentry-inspired design language maps
onto that almost 1:1:

| Ciicerone trait | Sentry design match |
|---|---|
| Security/threat-alerting product | "Debugging console wearing a leather jacket" — observability + alerting aesthetic |
| Developer + enterprise dual audience | Two-polarity canvas: dark midnight hero for marketing, white for dense reference/pricing tables |
| Threat detection / red team | Electric lime (`#c2ef4e`) used as a syntax-highlight chip on keywords — reads like a console "alert" marker |
| Audit logs, MITRE ATT&CK, code-heavy | Monaco code tier, console-prompt cadence (uppercase eyebrows + 0.2px tracking) |
| Enterprise deployment | Pricing-card rhythm with inverted "featured" tier, hairline borders, dense transactional surfaces |
| Python/FastAPI technical tone | Deep violet-midnight canvas (`#150f23`) + violet accents — serious, technical, not flashy |

## Contents

- [`DESIGN.md`](./DESIGN.md) — full token set (colors, typography, rounded,
  spacing, components) plus prose adapted for Ciicerone. The token values are
  copied verbatim from the upstream Sentry-inspired system; only the
  intro/component examples have been rewritten to reference Ciicerone surfaces
  (threat console, MITRE ATT&CK navigator, audit-log viewer, deployment/pricing
  matrix, FastAPI / YAML code blocks).

## Upstream source

Adapted from the Sentry-inspired design analysis in the
[awesome-design-md](https://github.com/VoltAgent/awesome-design-md) collection at
`design-md/sentry/`. Original preview and download options:
https://getdesign.md/sentry/design-md

## Verifying changes

After editing `DESIGN.md`, run the design.md linter to catch broken token
references, contrast issues, and orphaned tokens:

```bash
npx @google/design.md lint design-md/sentry/DESIGN.md
```
