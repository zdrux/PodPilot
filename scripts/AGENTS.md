# Scripts Workspace Guide

## Scope

Own safe, repeatable local development and operator helpers.

## Key Rules

- Never print tokens, kubeconfig contents, private keys, or other credentials.
- Write generated credentials outside the repository and keep their lifetime short.
- Verify the target cluster and resulting identity before running a caller's command.
- Do not weaken TLS validation or silently fall back to an administrator identity.

## Relevant Docs

- `docs/operations.md`
- `docs/security.md`
- `docs/cluster-lab.md`
