# Web Workspace Guide

## Scope

Own the operator-facing alert list, investigation flow, evidence display, and feedback UI.

## Key Rules

- Read `DESIGN.md` before adding or substantially changing a page, template,
  component, shared style, or responsive behavior. Reuse its reference patterns
  and semantic tokens; update it when a new reusable visual pattern is adopted.
- Distinguish observed facts, model hypotheses, uncertainty, and operator actions visually and semantically.
- Preserve evidence provenance and timestamps.
- Never render cluster-supplied HTML as trusted markup.
- Do not put provider credentials or privileged cluster tokens in browser code.

## Relevant Docs

- `docs/product.md`
- `docs/architecture.md`
- `docs/security.md`
- `docs/release.md`
