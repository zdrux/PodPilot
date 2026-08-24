# PodPilot Project Status

Last reviewed: 2026-08-23
Update when: a milestone is completed, the deployed version changes, a release
gate changes, a material blocker is discovered, or the immediate next work is
selected.

## Resume Here

PodPilot 0.8.0 / Milestone 8 is implemented and deployed on the disposable SNO
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
- `TargetDown` investigations with namespace and Service scope receive a
  persisted two-step safe diagnostic plan. An Investigator can run bounded
  Service/EndpointSlice/Pod topology and recent target-Pod event checks once.
- Check results become confirmed, cited observations and trigger a fresh model
  interpretation when the configured provider is ready. The plan and evidence
  remain useful without the model.
- Investigation-scoped chat persists attributed, redacted messages and labels
  evidence-based, general-guidance, and insufficient-evidence answers. The API
  validates model citations against the investigation's persisted observation
  IDs and withholds uncited factual claims.
- Chat may propose only the literal `run_queued_checks` intent while registered
  checks remain queued. The proposal cannot execute anything; an Investigator
  must use the separate existing check control and its CSRF, atomic claim, scope,
  and audit gates.
- SQLite/Alembic persistence on the SNO-local PVC. Schema head is
  `0006_investigation_chat`.

## Last Verified State

- Application version: `0.8.0`.
- OpenShift lab version: `4.22.9` on the documented Hyper-V SNO.
- Deployment: `ai-ops/podpilot`, last observed `1/1` Available.
- Automated suite: 46 tests passing with 83% aggregate coverage.
- Live Milestone 6 exercise verified creator cancellation with no workload
  mutation, `remediation.cancel` attribution, automatic cancellation after the
  exact fixture target changed, and automatic cancellation after the source
  alert left Alertmanager. Reconciler audit events recorded `target_stale` and
  `source_alert_not_active` under `system:reconciler`.
- The disposable CrashLoop workload namespace and synthetic PrometheusRule were
  removed after validation.
- Live Milestone 7 upgraded the pre-existing `TargetDown` investigation
  `c1443ddc-cc0a-45e4-b91c-8bf2601a11cd` in place and successfully ran both
  checks under `podpilot-breakglass`, followed by a ready model interpretation.
- The independent TargetDown fixture investigation ran both checks under
  `podpilot-investigator`, found ready Service topology, rejected a second run,
  and recorded planner, execution, and reanalysis audit events. Its namespace
  and platform PrometheusRule were removed after validation.
- Live Milestone 8 chat on investigation
  `c1443ddc-cc0a-45e4-b91c-8bf2601a11cd` returned a ready evidence-based answer
  with 12 server-validated citations and no unavailable tool intent after its
  checks had completed. Audit records contain attribution and citation IDs but
  no message body.
- A fresh TargetDown fixture investigation
  `389d29c6-8801-4bed-bbcb-e856ca0fde1f` returned a ready
  `run_queued_checks` proposal and rendered the separate run control. Both checks
  remained queued after the chat turn, proving the proposal did not execute.
  The fixture namespace and PrometheusRule were removed afterward.
- Latest implementation commit: `f0b2dea` (`Add evidence-cited investigation
  chat`). OpenShift build `podpilot-20` was built from that commit and deployed
  at image digest `sha256:bbed3ed37fcf32506a9fe5e2d111bf0a4ea382f2de7237e7934a55462f879269`.

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
- The model and browser cannot submit diagnostic tool names, targets, selectors,
  query text, or commands. Normal code owns the plan, budget, and exact inputs.
- Chat receives no Kubernetes credentials or generic tool channel. Citations and
  the single available intent are validated by normal code; executing proposed
  checks always requires a separate operator request.
- The production-base observer role adds EndpointSlice read access but no new
  mutation or Secret permission.
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
- Chat is limited to one investigation, a 20-message history, one non-executing
  safe-check intent, and non-streaming responses. Cross-investigation retrieval
  and curated cluster memory are not implemented.
- The first executable plan is fixed to scoped `TargetDown` Service topology and
  Pod events. It does not yet inspect Prometheus rule state/target metadata or
  perform an active DNS, TCP, TLS, or HTTP probe.
- Rule-state and PromQL correlation, Routes, ClusterOperators, networking,
  storage, and version-aware Service Mesh packs remain future capability packs.
- The lab binary build publishes `:latest`; immutable release promotion and a
  tested database rollback process remain open.

## Candidate Next Work

No next milestone is formally selected. The highest-value candidates are:

1. Complete the `TargetDown` pack with Prometheus rule/target metadata and a
   tightly controlled active reachability probe from an approved location.
2. Introduce curated cluster memory with source, scope, owner, confidence, and
   review/expiry metadata before adding retrieval to investigations.
3. Add the next diagnostic capability pack with fixtures and release gates;
   Routes and ClusterOperators are narrower choices than Service Mesh.
4. Split production observation and action identities, then replace the lab
   `:latest` build flow with immutable image promotion.
5. Add streaming and conversation summarization only after evaluation proves
   they preserve citation, redaction, attribution, and tool-intent boundaries.

Before selecting work, reconcile these candidates with `docs/prd.md`, record the
decision in `docs/decisions.md`, and update this file in the same change.

## Verification Entry Points

- Repository and tests: commands in `AGENTS.md` and `docs/release.md`.
- SNO connection and deployment: `docs/cluster-lab.md` and
  `docs/operations.md`.
- System boundaries: `docs/architecture.md` and `docs/security.md`.
- Product scope and acceptance criteria: `docs/prd.md`.
- Fast file ownership map: `docs/codebase-map.md`.
