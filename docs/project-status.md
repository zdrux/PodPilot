# PodPilot Project Status

Last reviewed: 2026-08-23
Update when: a milestone is completed, the deployed version changes, a release
gate changes, a material blocker is discovered, or the immediate next work is
selected.

## Resume Here

PodPilot 0.6.0 / Milestone 6 is implemented and deployed on the disposable SNO
lab. The repository was clean at the last handoff. Start a new session by reading
this file and `AGENTS.md`, then verify `git status --short` before making changes.

The product is an OpenShift-first investigation and Day-2 operations companion.
It presents active Alertmanager signals, builds bounded evidence-backed
investigations from live cluster state, adds a schema-validated model
interpretation when the provider is available, and can execute only registered
remediation actions after a fresh, explicit approval.

## Implemented

- OpenShift OAuth-protected dashboard with Viewer, Investigator, Approver, and
  Breakglass attribution through disposable htpasswd lab users.
- Alertmanager queue with expected Watchdog separation and durable
  investigations.
- Bounded Pod status, event, current/previous log, owner-chain, rollout, and node
  scheduling evidence.
- Provider-neutral model boundary with an OpenAI Responses API implementation,
  server-side Secret storage, capability probing, structured output, redaction,
  and deterministic fallback.
- Typed remediation for one controller-owned failed Pod replacement and one
  Deployment, StatefulSet, or DaemonSet rollout restart.
- Server dry-run, exact UID/resourceVersion preconditions, ten-minute preview
  expiry, Approver-only two-step confirmation, atomic single execution,
  post-action verification, sibling-action cancellation, and audit events.
- Explicit preview cancellation by the investigation creator or an Approver,
  automatic expiry, source-alert reconciliation from complete Alertmanager
  snapshots, and read-only stale or missing target reconciliation.
- Approval rechecks the source alert immediately before claiming an action. An
  unavailable or truncated Alertmanager snapshot fails closed without
  cancelling or authorizing the preview.
- SQLite/Alembic persistence on the SNO-local PVC. Schema head is
  `0004_remediation_actions`.

## Last Verified State

- Application version: `0.6.0`.
- OpenShift lab version: `4.22.9` on the documented Hyper-V SNO.
- Deployment: `ai-ops/podpilot`, last observed `1/1` Available.
- Automated suite: 35 tests passing with 82% aggregate coverage.
- Live Milestone 6 exercise verified creator cancellation with no workload
  mutation, `remediation.cancel` attribution, automatic cancellation after the
  exact fixture target changed, and automatic cancellation after the source
  alert left Alertmanager. Reconciler audit events recorded `target_stale` and
  `source_alert_not_active` under `system:reconciler`.
- The disposable CrashLoop workload namespace and synthetic PrometheusRule were
  removed after validation.
- Latest implementation commit: `523f460` (`Add remediation lifecycle
  reconciliation`). OpenShift build `podpilot-18` was built from that commit.

These observations are a handoff snapshot, not a substitute for checking the
current repository and cluster state.

## Important Safety State

- The SNO PoC service account has cluster-admin only through the explicit
  `poc-cluster-admin` overlay. Production manifests must default to read-only.
- Model output, alert text, events, logs, annotations, and retrieved memory are
  untrusted evidence and cannot define executable operations.
- The browser submits only an opaque action ID. The server owns the target,
  operation, preconditions, expiry, and verifier.
- Cancellation grants no execute authority. Lifecycle closure uses an atomic
  preview-ready transition and records the actor, reason, detail, and timestamp.
- Absence from a bounded, truncated Alertmanager response is not accepted as
  proof that an alert resolved.
- Pod DELETE preview carries `dryRun: ["All"]` in `DeleteOptions` and the query
  parameter because live SNO testing found the query-only Python-client form was
  not sufficient on this OpenShift path.
- Never commit model tokens, kubeconfigs, cluster credentials, pull secrets, or
  private keys.

## Known Limitations

- Single-cluster, single-replica PoC with SNO-local storage and no production
  backup or high-availability design.
- The application uses the broad PoC identity; a production action service and
  narrow action-specific identity are not implemented.
- Only CrashLoop-correlated workload replacement and rollout restart are
  registered remediation domains.
- Investigation-scoped chat and curated cluster memory are specified in the PRD
  but not yet implemented.
- Rule-state and PromQL correlation, Routes, ClusterOperators, networking,
  storage, and version-aware Service Mesh packs remain future capability packs.
- The lab binary build publishes `:latest`; immutable release promotion and a
  tested database rollback process remain open.

## Candidate Next Work

No next milestone is formally selected. The highest-value candidates are:

1. Add investigation-scoped follow-up chat that can request only registered,
   bounded diagnostic checks and must cite evidence.
2. Introduce curated cluster memory with source, scope, owner, confidence, and
   review/expiry metadata before adding retrieval to investigations.
3. Add the next diagnostic capability pack with fixtures and release gates;
   Routes and ClusterOperators are narrower choices than Service Mesh.
4. Split production observation and action identities, then replace the lab
   `:latest` build flow with immutable image promotion.
5. Add a background reconciliation loop so preview expiry and alert resolution
   do not depend on an operator loading the dashboard or investigation detail.

Before selecting work, reconcile these candidates with `docs/prd.md`, record the
decision in `docs/decisions.md`, and update this file in the same change.

## Verification Entry Points

- Repository and tests: commands in `AGENTS.md` and `docs/release.md`.
- SNO connection and deployment: `docs/cluster-lab.md` and
  `docs/operations.md`.
- System boundaries: `docs/architecture.md` and `docs/security.md`.
- Product scope and acceptance criteria: `docs/prd.md`.
- Fast file ownership map: `docs/codebase-map.md`.
