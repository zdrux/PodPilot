# OpenShift Deployment Guide

## Scope

Own namespace-scoped workload configuration, service identity, RBAC, network policy, and deployment manifests.

## Key Rules

- Keep the base manifests read-only. The `overlays/poc-cluster-admin/` exception is for the disposable SNO lab only.
- `base/` owns portable namespace, service identity, and read-only cluster and
  monitoring RBAC. `overlays/remote-poc/` is the methodical remote installation path.
- Never include the PoC cluster-admin overlay in a production installation path.
- Keep `storage/sno-local/` separate from the base; it is a single-node lab fixture, not a production default.
- Keep `auth/poc-htpasswd/` separate from the base. Group membership expresses
  elevated PodPilot application roles and must not grant direct mutation rights.
- Never commit tokens or generated credentials.
- Validate changes server-side and audit effective access.
- Pin production images by digest once workload manifests exist.
- `build/sno-binary/` and `overlays/sno-milestone-one/` are disposable-lab delivery paths; do not mix them with the remote overlay.

## Relevant Docs

- `docs/security.md`
- `docs/operations.md`
- `docs/cluster-lab.md`
- `docs/release.md`
