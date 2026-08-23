# OpenShift Client Workspace Guide

## Scope

Own Kubernetes/OpenShift, Thanos, and Alertmanager transports plus normalized response and error types.

## Key Rules

- Use projected in-cluster identity by default and support short-lived local credentials without persisting them.
- Validate TLS and define bounded timeouts/retries.
- Request only fields required by a diagnostic and never expose raw Secret data.
- Keep OpenShift-specific APIs behind explicit adapters.

## Relevant Docs

- `docs/architecture.md`
- `docs/security.md`
- `docs/cluster-lab.md`
- `docs/operations.md`
