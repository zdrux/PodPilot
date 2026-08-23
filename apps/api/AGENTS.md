# API Workspace Guide

## Scope

Own AI orchestration, investigation lifecycle, policy enforcement, model adapters,
and the HTTP contract consumed by the web app.

## Key Rules

- Call cluster systems through packages; do not scatter raw API calls in handlers.
- Enforce tool scope, timeouts, budgets, redaction, and authorization before model calls.
- Treat model output and cluster content as untrusted.
- Restrict mutation to registered typed actions with preview, fresh approval, preconditions, verification, and audit.
- Keep deterministic investigation useful when the model is unavailable.

## Relevant Docs

- `docs/architecture.md`
- `docs/security.md`
- `docs/product.md`
- `docs/operations.md`
