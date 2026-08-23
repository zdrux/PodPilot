# ocp-inventory Reuse Assessment

Last reviewed: 2026-08-22
Update when: code is imported from `ocp-inventory` or the PodPilot UI architecture changes.

The adjacent `C:\Users\zdrux\Desktop\projects\ocp-inventory` repository is a
useful design reference, not a foundation to fork wholesale. PodPilot should
selectively extract small, reviewed pieces while keeping its troubleshooting,
evidence, approval, and provider boundaries purpose-built.

## Reuse

- The dashboard's visual language: sidebar, cards, status badges, tables, modal
  patterns, responsive layout, and empty/loading/error states.
- FastAPI/Jinja template mounting and server-rendered navigation patterns.
- Server-Sent Events heartbeat/reconnect behavior, rewritten as a small module.
- Tested resource-quantity parsing and formatting helpers.
- The idea of Kubernetes dynamic API discovery, implemented with the maintained
  official `kubernetes.dynamic.DynamicClient`.

Every extracted item must retain its source attribution, receive focused tests,
and be adapted to PodPilot's accessibility and Content Security Policy needs.

## Rewrite

- Data model and migrations around investigations, evidence, action proposals,
  approvals, audit events, model profiles, and curated memory.
- Cluster client, Alertmanager/Thanos adapters, diagnostic packs, and remediation executor.
- Settings and secret handling.
- Frontend JavaScript as small feature modules rather than one monolithic file.

## Do Not Carry Forward

- Plaintext cluster-token persistence or user-supplied long-lived cluster credentials.
- Disabled TLS verification or suppressed certificate warnings.
- Hard-coded session secrets or anonymous users receiving administrator privileges.
- Remote CDN runtime dependencies for scripts, fonts, or icons.
- Startup-time, hand-written schema migrations.
- Fleet inventory, licensing, LDAP, compliance, and scheduled discovery features
  that do not support the PodPilot investigation workflow.

No code is copied merely because it exists. The extraction unit is a small,
testable behavior or visual pattern with an explicit PodPilot owner.
