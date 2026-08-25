# PodPilot Project Status

Last reviewed: 2026-08-24
Update when: a milestone is completed, the deployed version changes, a release
gate changes, a material blocker is discovered, or the immediate next work is
selected.

## Resume Here

PodPilot 0.11.0 is implemented and deployed on the disposable SNO lab. Milestone
10 remains the investigation baseline; 0.11 adds the multi-provider model registry.
That release is committed at `717737a`. A portable remote-cluster PoC deployment
path is prepared and locally validated but has not yet been exercised on a second
cluster. Start a new session by reading this file and `AGENTS.md`, then verify
`git status --short` before making changes.

The product is an OpenShift-first investigation and Day-2 operations companion.
It presents active Alertmanager signals, builds bounded evidence-backed
investigations from live cluster state, adds a schema-validated model
interpretation when the provider is available. Registered remediation lifecycle
records remain, but execution now awaits a separate approval-gated action service.

## Implemented

- OpenShift OAuth-protected dashboard with Viewer, Investigator, Approver, and
  Breakglass attribution through disposable htpasswd lab users.
- Alertmanager queue with expected Watchdog separation and durable
  investigations.
- Bounded Pod status, event, current/previous log, owner-chain, rollout, and node
  scheduling evidence.
- Provider-neutral model boundary with OpenAI Responses and strict-schema Chat
  Completions implementations, capability probing, structured output, redaction,
  and deterministic fallback. Multiple endpoint profiles live in SQLite with one
  tested active profile. Per-profile API tokens remain under opaque keys in the
  fixed OpenShift Secret and are dynamically created, rotated, and removed without
  a Pod restart. TLS modes include system trust, custom CA, and a visibly insecure
  PoC-only override. Capability probing now separately validates the live Ask
  PodPilot planning and answer schemas, shows an explicit result notification,
  emits sanitized phase/outcome events for provider troubleshooting, and gives
  Chat Completions models one bounded field/type-only schema correction attempt.
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
  persisted three-step safe diagnostic plan. An Investigator can run bounded
  passive Thanos rule/scrape correlation, Service/EndpointSlice/Pod topology,
  and recent target-Pod event checks once.
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
- Standalone Ask PodPilot conversations can investigate symptoms without an alert.
  Up to three schema-validated planning rounds select at most six total bounded
  resource, ConfigMap, or Pod-log reads. Earlier observations feed later rounds so
  discovery can lead to exact container logs; a final pass answers from persisted, redacted evidence with
  server-validated citations. Secrets, access reviews, arbitrary subresources,
  commands, network probes, and mutations are denied.
- Ask PodPilot conversations are private to their creating OpenShift user. Users
  can start and delete their own conversations; other users receive a not-found
  response rather than conversation metadata. Questions are unlimited per
  conversation: the model receives the ten most recent messages plus a bounded
  deterministic digest of earlier messages. Per-question collection remains
  bounded to six reads, and each user is throttled to ten questions per minute.
- The chat UI uses larger operational text, exposes New conversation and Delete
  conversation controls, and submits with Enter while reserving Shift+Enter for
  a newline.
- Ad-hoc Pod-log reads report authorization, missing-target, and invalid-stream
  failures separately. A missing retained previous container stream falls back to
  bounded current logs and preserves that distinction as a limitation. Evidence
  citations scroll, focus, and highlight their matching provenance card.
- Ask PodPilot opens the bounded conversation viewport at the newest response.
  Chat messages render safe CommonMark with readable system prose typography,
  distinct monospace code, and styled tables; raw HTML remains escaped and unsafe
  link schemes are not activated.
- The application runs as `ai-ops/podpilot-investigator`, bound to OpenShift
  `cluster-reader`. The separate `ai-observer` identity retains cluster-admin only
  as disposable-lab development and break-glass access.
- The monitoring check submits only fixed `ALERTS` and `up` instant-query shapes
  to the TLS-validated, authenticated in-cluster Thanos endpoint. Exact alert
  labels are escaped, responses are capped at 64 KiB and 20 retained series, and
  results are redacted before becoming evidence.
- SQLite/Alembic persistence on the SNO-local PVC. Schema head is
  `0009_model_registry`.
- A remote Kustomize overlay composes the read-only base, explicit
  `openshift-monitoring` Alertmanager API Role, group-based OAuth GUI admission,
  default-StorageClass PVC, and single-replica workload. The accompanying runbook
  covers Docker/Podman build and push, versioned internal-registry ImageStreamTag
  selection, out-of-band Secrets, existing LDAP-synchronized elevated-role
  mapping, server dry-run, RBAC checks, rollout, and rollback. Every authenticated user receives Viewer;
  each elevated application role accepts multiple existing groups; no remote
  Group or membership is created by PodPilot.

## Last Verified State

- Application version: `0.11.0`.
- OpenShift lab version: `4.22.9` on the documented Hyper-V SNO.
- Deployment: `ai-ops/podpilot`, last observed `1/1` Available.
- Automated suite: 95 tests passing with 82% aggregate branch coverage.
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
- Live Milestone 9 fixture investigation
  `9bdee782-bc08-418e-9922-cec6f66b3f16` ran all three checks under
  `podpilot-breakglass`. Thanos returned one matching firing `ALERTS` series and
  zero matching `up` series, so the deterministic result correctly left target
  discovery unresolved. All checks succeeded, the model status was ready, and
  three `diagnostic.execute` events recorded the exact registered tools. The
  fixture namespace and PrometheusRule were removed afterward.
- Live Milestone 10 conversation `cd23e2dd-de0e-4abd-a289-b00e57d09c19`
  used one `get_resource` intent to read the exact running PodPilot Pod, persisted
  one observation, returned one validated citation, and recorded attributed
  `adhoc.message` and `adhoc.answer` audit events. A deliberately under-scoped
  preceding question failed collection without inventing evidence or attempting a
  mutation.
- Live iterative-log conversation `108dc517-38e7-45e5-b1df-f910bfb1e49a`
  replayed the question "are there any errors in the kube api server pods logs?".
  Round 1 discovered the static Pod and its containers; round 2 collected the
  bounded current `kube-apiserver` container log. The final answer cited both
  persisted observations and reported the observed etcd warnings with explicit
  time-window and sidecar limitations.
- The conversation-management update was built as OpenShift build `podpilot-25`
  at image digest
  `sha256:e01ec69288037e394ae35053ba61cde4663b1bcc3e7bef4ac9be6b157a3fb142`.
  The `0008_conversation_management` migration ran during rollout and the live
  readiness endpoint reported a healthy database. A clean in-app browser reached
  the expected OpenShift OAuth login boundary; authenticated visual behavior is
  covered by rendered-template and interaction tests rather than transferring a
  lab credential into that browser session.
- The Alertmanager log and citation-navigation correction was deployed as
  OpenShift build `podpilot-26` at image digest
  `sha256:7b379db9e0c30f6d4b08862e8ba1ec74f882a1d9df233d89ddd273d9faf0daac`.
  Live replay of the exact previous-log read confirmed Kubernetes had no retained
  previous `alertmanager` stream; the deployed broker fell back to current logs,
  collected 1,692 bounded characters, and returned the explicit retention
  limitation. The deployment remained `1/1` Available.
- The chat presentation update was deployed as OpenShift build `podpilot-27` at
  image digest
  `sha256:5f6e96fdc3d1c32ccb19c5765955a15e87cb153426e266cef0d498c2849a08ce`.
  Live rendering of the latest stored conversation confirmed a real Markdown
  table, the structured chat container, and the newest-message scroll marker.
- The degraded Alertmanager collection state was traced to an inert RoleBinding
  that referenced `monitoring-alertmanager-view` as a ClusterRole. The corrected
  `openshift-monitoring/podpilot-alertmanager-api-view` binding references the
  existing namespaced Role. Live collection then returned a complete snapshot of
  five alerts, and the obsolete binding was removed.
- The model registry was deployed as OpenShift build `podpilot-29` at image digest
  `sha256:1244c165107ce2f545bab9e83aeafa9ea58a20041f165ac8222d817162889b62`.
  The init container upgraded the live PVC from `0008_conversation_management` to
  `0009_model_registry`, preserving the ready OpenAI profile as active with its
  existing `api_key`. A live, OAuth-attributed API exercise created a temporary
  Chat Completions profile, patched its opaque token key into the fixed credential
  Secret, deleted the profile and key, and confirmed the API container did not
  restart. The database and Secret returned to the original single-profile state.

These observations are a handoff snapshot, not a substitute for checking the
current repository and cluster state.

## Important Safety State

- The normal runtime is `podpilot-investigator` with `cluster-reader`. Live audit
  confirmed Pod-log and ConfigMap reads and denied Secrets, `pods/exec`, and
  Deployment patch. `ai-observer` has cluster-admin only through the explicit
  `poc-cluster-admin` overlay and is not the application identity.
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
- Alert labels are never treated as PromQL or network destinations. The server
  owns the query shape and escapes exact-match values. No DNS, TCP, TLS, or HTTP
  connection is made to the alert `instance` or selected Service.
- The application-level Ask broker denies mutations and Secrets even though the
  runtime also has one narrowly resource-named model-credential Secret permission.
- Pod DELETE preview carries `dryRun: ["All"]` in `DeleteOptions` and the query
  parameter because live SNO testing found the query-only Python-client form was
  not sufficient on this OpenShift path.
- Never commit model tokens, kubeconfigs, cluster credentials, pull secrets, or
  private keys.

## Known Limitations

- Single-cluster, single-replica PoC with SNO-local storage and no production
  backup or high-availability design.
- A production action service and narrow action-specific identity are not
  implemented. Existing remediation execution is intentionally unavailable from
  the reader runtime until that boundary exists.
- Only CrashLoop-correlated workload replacement and rollout restart are
  registered remediation domains.
- Investigation chat is limited to one investigation, a 20-message history, one
  non-executing safe-check intent, and non-streaming responses. Standalone Ask
  PodPilot conversations are unlimited and use rolling context, but responses
  remain non-streaming and curated cluster memory is not implemented.
- The first executable plan is fixed to scoped `TargetDown` passive monitoring
  signals, Service topology, and Pod events. It does not inspect full rule
  definitions or perform an active DNS, TCP, TLS, or HTTP probe.
- Active probing requires an administrator-owned destination registry, a
  dedicated no-token identity, explicit egress policy, redirect/DNS-rebinding
  defenses, rate limits, and adversarial fixtures before it is safe to add.
- Full rule-definition inspection, ad hoc PromQL, Routes, ClusterOperators,
  networking, storage, and version-aware Service Mesh packs remain future
  capability packs.
- The lab binary build publishes `:latest`; immutable release promotion and a
  tested database rollback process remain open.

## Candidate Next Work

No next milestone is formally selected. The highest-value candidates are:

1. Introduce curated cluster memory with source, scope, owner, confidence, and
   review/expiry metadata before adding retrieval to investigations.
2. Add the next diagnostic capability pack with fixtures and release gates;
   Routes and ClusterOperators are narrower choices than Service Mesh.
3. Design an administrator-owned probe-target registry and dedicated no-token,
   egress-restricted probe identity before considering active reachability.
4. Implement the separate approval-gated action executor identity, then replace
   the lab `:latest` build flow with immutable image promotion.
5. Evaluate streaming responses against the existing citation, redaction,
   attribution, rolling-context, and tool-intent boundaries.

Before selecting work, reconcile these candidates with `docs/prd.md`, record the
decision in `docs/decisions.md`, and update this file in the same change.

## Verification Entry Points

- Repository and tests: commands in `AGENTS.md` and `docs/release.md`.
- SNO connection and deployment: `docs/cluster-lab.md` and
  `docs/operations.md`.
- System boundaries: `docs/architecture.md` and `docs/security.md`.
- Product scope and acceptance criteria: `docs/prd.md`.
- Fast file ownership map: `docs/codebase-map.md`.
