# OpenShift Deployment Guide

## Scope

Own namespace-scoped workload configuration, service identity, RBAC, network policy, and deployment manifests.

## Key Rules

- Keep the base manifests read-only. The `overlays/poc-cluster-admin/` exception is for the disposable SNO lab only.
- Apply the base first, then the additive PoC overlay; the overlay does not duplicate the base resources.
- Never include the PoC cluster-admin overlay in a production installation path.
- Keep `storage/sno-local/` separate from the base; it is a single-node lab fixture, not a production default.
- Keep `auth/poc-htpasswd/` separate from the base. Group membership expresses
  PodPilot application roles and must not grant direct mutation rights.
- Never commit tokens or generated credentials.
- Validate changes server-side and audit effective access.
- Pin production images by digest once workload manifests exist.
- `build/sno-binary/` and `overlays/sno-milestone-one/` are disposable-lab delivery paths; apply the reusable base first.

## Relevant Docs

- `docs/security.md`
- `docs/operations.md`
- `docs/cluster-lab.md`
- `docs/release.md`
