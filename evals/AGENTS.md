# Evaluations Workspace Guide

## Scope

Own sanitized incident fixtures, expected evidence, scoring, safety cases, and regression suites.

## Key Rules

- Use synthetic or explicitly sanitized data only.
- Score evidence use, diagnosis quality, uncertainty, and safety independently.
- Include prompt-injection content in adversarial fixtures and assert it is treated as data.
- Never snapshot live credentials, kubeconfigs, raw Secrets, or sensitive customer data.

## Relevant Docs

- `docs/product.md`
- `docs/security.md`
- `docs/release.md`
