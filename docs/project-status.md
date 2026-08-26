# PodPilot Project Status

Last reviewed: 2026-08-26
Update when: a milestone is completed, the deployed version changes, a release
gate changes, a material blocker is discovered, or the immediate next work is
selected.

## Resume Here

PodPilot 0.11.0 remains deployed on the disposable SNO lab. The 0.12.0 working tree
is implemented and locally tested at schema head `0012_multi_cluster_ask`, but has
not been deployed. It adds Ask-only multi-cluster routing, secret-backed cluster
management, immutable one-to-ten-cluster conversation selections, cluster-attributed
evidence, and curated-memory prompt integration governed by explicit cluster targets,
required tags, or global scope. Start a new session by reading this file and
`AGENTS.md`, then verify `git status --short` before making changes.

The product is an OpenShift-first investigation and Day-2 operations companion.
It presents active Alertmanager signals, builds bounded evidence-backed
investigations from live cluster state, adds a schema-validated model
interpretation when the provider is available. Registered remediation lifecycle
records remain, but execution now awaits a separate approval-gated action service.

## Implemented

- Ask PodPilot cluster registry with Approver/Breakglass management, exact key/value
  tags, connection testing, soft disable, a dedicated resourceName-restricted cluster
  credential Secret, default-on TLS verification, and an explicit visible/audited
  per-cluster insecure exception. The runtime cluster is registered automatically and its
  persisted display name can be changed without modifying its deployment-managed identity.
- New Ask conversations select one to ten clusters through a searchable picker. The
  immutable selection is retained in history; changing it starts another conversation.
  One shared twelve-read budget fans out across selected clusters, partial failures remain
  scoped limitations, and all evidence/citations identify their source cluster. Alert,
  investigation, dashboard, remote metrics, and remediation routing are unchanged.
- Curated memory now supports global entries, explicit cluster sets, and all-required
  tag matches with explicit-or-tag OR semantics. Eligible nonrestricted chunks are supplied
  to standalone Ask planning and answers as cluster-labeled guidance, never live evidence,
  tool authority, or current-state citations.

- Curated cluster-memory foundation with immutable versions, heading-aware chunks,
  SQLite FTS5/BM25 search, reviewed/enabled/expiry eligibility, cluster and
  namespace scope, restricted-entry authorization, Approver management controls,
  Investigator retrieval preview, redaction, and content-free audit metadata.
  The 0.12 targeting and Ask augmentation rules above supersede the original
  single-cluster preview-only boundary.

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
  a Pod restart. Transport modes include system trust, custom CA, a visibly
  insecure HTTPS override, and explicit plain HTTP restricted to Kubernetes
  Service DNS endpoints. Capability probing now separately validates the live Ask
  PodPilot planning and answer schemas, shows an explicit result notification,
  emits sanitized phase/outcome events for provider troubleshooting, and gives
  Chat Completions models one bounded field/type-only schema correction attempt.
  The compatibility boundary safely defaults a missing descriptive plan summary,
  uses a smaller synthetic answer budget during probes, canonicalizes known
  Kubernetes/OpenShift Kind and apiVersion pairs, and keeps model-authored plan
  caveats separate from trusted evidence-collection limitations.
  Approvers can delete active or inactive profiles in the GUI. Active deletion
  selects the most recently probed ready fallback when available, otherwise the
  application continues in its deterministic model-free mode.
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
  IDs and withholds uncited factual claims. It now shares the bounded Ask read
  broker, persists alert-scoped resource and Pod-log observations into the
  incident, and audits read targets without evidence bodies.
- Chat may propose only the literal `run_queued_checks` intent while registered
  checks remain queued. The proposal cannot execute anything; an Investigator
  must use the separate existing check control and its CSRF, atomic claim, scope,
  and audit gates.
- Standalone Ask PodPilot conversations can investigate symptoms without an alert.
  Up to five schema-validated planning rounds select at most twelve total bounded
  resource, ConfigMap, Pod-log, or HTTP-probe reads. Earlier observations feed later rounds so
  discovery can lead to exact container logs; a final pass answers from persisted, redacted evidence with
  server-validated citations. HTTP probes are unauthenticated, SNI-aware, TLS-verified,
  response-bounded, and do not follow redirects. Secrets, access reviews, arbitrary
  subresources, commands, authenticated probes, and mutations are denied.
- Unambiguous StorageClass inventory and supported namespaced built-in list
  questions use deterministic read plans. Failed-Job incident questions seed an
  exact `batch/v1` Job read from persisted alert labels before optional follow-up
  planning, preventing empty or malformed model intents from blocking basic work.
- The read broker now builds a five-minute safe catalog from live Kubernetes API
  discovery. Explicit inventory questions compile from that catalog, and model
  planning receives question-relevant plural resource names for core,
  OpenShift, and installed CRD objects. Normal code resolves versions, group
  collisions, scope, and verbs. Lists paginate and persist compact, explicitly
  truncated collection evidence rather than one observation per object.
- Model planning now infers natural-language goals while the server derives collection
  decisions from typed intents. Unsupported
  operational no-read answers receive one structured repair attempt; when live
  discovery identifies a safe matching inventory or health target, a repeated
  refusal falls back to the discovery-compiled read without expanding broker or
  RBAC permissions.
- Cluster-wide inventory LISTs no longer require the operator to invent a
  namespace. OpenShift API 403 responses identify the investigator ServiceAccount,
  verb, resource, and scope in the answer. List evidence retains all collected
  names separately from compact details, so detail compaction no longer falsely
  claims that additional objects exist; internal observation paths are removed
  from displayed Markdown.
- Ask PodPilot snapshots active model-profile status before its SQLAlchemy
  session closes. A configured but non-ready profile now produces a persisted,
  attributed setup message with its real provider status instead of raising a
  detached-instance error during chat creation.
- Explicit inventory LISTs now default to 500 objects and accept a deployment
  setting up to 1,000. Kubernetes pagination is no longer capped at the old five
  50-object pages. The API renders every collected name into a cited Markdown
  table for list requests and suppresses redundant model-authored completeness
  caveats; the model is not responsible for reproducing the actual inventory.
- Projected resource search can scan beyond the ordinary LIST evidence window while
  returning only a bounded match set. Route URL questions compile to exact `spec.host`
  searches, and planner guidance covers named GETs, label selectors, Route hosts,
  Route backend Services, and follow-up reads from discovered coordinates.
- Cross-group plural collisions use matching `apiVersion`/`Kind` coordinates during
  discovery preflight. OpenShift browser Route questions select
  `routes.route.openshift.io`, never an incidental Knative Route; rejected ambiguity does
  not consume the cluster-read budget.
- Route backend Service references are grounded from projected `spec.to.name` data, allowing
  exact Route-to-Service follow-up reads. Edge, reencrypt, passthrough, and unsecured Route
  behavior has a deterministic cited answer when model follow-up planning is incomplete.
- Route, HTTP-5xx, and connectivity investigations follow a deterministic bounded traffic graph
  through the exact Service, selected Pods, EndpointSlices, and Endpoints. Relevant healthy
  backend containers receive bounded log inspection, so a malformed later ReadPlan cannot
  prevent basic workload evidence collection.
- Explicit cross-namespace Pod TCP/connectivity questions deterministically collect both exact
  Pods, both Namespace label sets, and bounded NetworkPolicies from both namespaces. Policy
  evidence retains ingress/egress selectors and ports for additive source-egress and
  destination-ingress analysis while disclosing that configuration alone cannot prove a drop.
- HTTPS troubleshooting probes keep verification enabled by default but may explicitly
  select `tls_verify=false` for private, self-signed, or component-managed certificates.
  SNI is preserved and both evidence and limitations state that server identity was not verified.
- Ask PodPilot can request typed CPU, memory, network, restart, PVC-utilization, and
  readiness trends for exact Pod/namespace/PVC scopes. Server-owned PromQL is sent through
  authenticated Thanos range queries; the model receives bounded normalized samples and
  statistics but never PromQL control or the ServiceAccount token.
- Deployment metric scope aggregates all owned ReplicaSet Pods, including rollout overlap.
  Top-10 CPU/memory rankings support namespace, Deployment, and node scope; common namespace
  ranking questions compile directly to typed metric reads before model planning. Node scope supports
  total workload trends and rankings with
  namespace/Pod/container attribution. Standard monitoring still cannot identify arbitrary
  host processes; that would require separate process-exporter/eBPF or node diagnostics.
  Overall node-exporter CPU/memory utilization can be paired with those rankings to reveal
  pressure not explained by monitored workload containers.
- Ask PodPilot conversations are private to their creating OpenShift user. Users
  can start and delete their own conversations; other users receive a not-found
  response rather than conversation metadata. Questions are unlimited per
  conversation: the model receives the ten most recent messages plus a bounded
  deterministic digest of earlier messages. Per-question collection remains
  bounded to twelve reads, and each user is throttled to ten questions per minute.
- The chat UI uses larger operational text, exposes New conversation and Delete
  conversation controls, and submits with Enter while reserving Shift+Enter for
  a newline.
- Ask questions are persisted as recoverable jobs and processed by the
  single-replica worker. Submission clears the composer immediately and adds an
  optimistic user turn plus pulsating assistant placeholder. Owner-only SSE
  updates report real discovery, planning, collection, and answer phases; reloads
  recover progress from SQLite, and interrupted jobs are requeued on startup.
  Runs have an overall configurable execution deadline; the worker and owner-only
  status streams atomically fail stale jobs, while the browser stops progress
  animation after a bounded delivery grace period.
- Ad-hoc Pod-log reads report authorization, missing-target, and invalid-stream
  failures separately. A missing retained previous container stream falls back to
  bounded current logs and preserves that distinction as a limitation. Evidence
  citations now show the tool, summary, first technical fact, and stable evidence
  ID; they open, focus, highlight, and expand the matching provenance card. Drawer
  cards expose exact OpenShift coordinates, material object fields, probe SNI/TLS
  diagnostics, metric bounds, container identity, bounded excerpts, and the full
  persisted redacted payload. A server-side guard rejects provider claims that a
  TLS-stage certificate failure or sidecar-only logs prove an application backend
  serves plain HTTP.
- Trust-only HTTPS probe failures now receive one deterministic, evidence-visible
  retry with verification disabled while preserving URL, Host, SNI, method, and
  connection override. Unready, restarting, and non-running containers become
  prioritized exact log candidates. Bounded logs from any container are classified
  into general operational findings with occurrence/signature counts, timestamps,
  samples, paths, and endpoints; material signals automatically trigger exact Pod,
  Pod-Event, and applicable previous-log reads inside the existing budget. The model
  receives findings plus completed checks and must distinguish correlation from root cause.
  Missing certificate/key assets are correlated across neighboring traceback lines, so a
  PEM path separated from its `FileNotFoundError` remains a required cited log finding.
- Ask replies now keep confidence as a short hover/focus pill beside the timestamp
  and collapse cited observations into one rounded on-demand vertical timeline; the redundant
  inspected-target disclosure is no longer rendered. Ask session,
  reply, and evidence timestamps display in fixed `EST (-4)` while persistence stays UTC.
- Final-answer evidence is compacted into a provider-only bounded view that prioritizes
  current reads and caps Pod logs, objects, findings, and total bytes without changing
  persisted provenance. Citation-bearing heading-only or extremely brief answers receive
  one bounded correction, as do evidence-based answers missing current Pod-log citations. A
  second failure uses deterministic Route/TLS, inventory, or cited-observation output. Current
  structured log findings are always composed into the reply with exact coordinates, bounded
  technical details, and citations, so a Route fallback cannot hide them. Equivalent displayed
  limitations are semantically deduplicated.
- Pod discovery now emits bounded exact log candidates. Planner-selected opaque
  IDs are bound to observed namespace/Pod/container coordinates before execution;
  invented targets receive one budget-free repair, followed by a disclosed
  server-owned fallback across at most three relevant candidates. This improves
  discover-then-log autonomy without expanding the investigator ServiceAccount.
  Direct unobserved Pod-log targets and literal future-value placeholders are now
  rejected before cluster collection. Named GET targets must originate in the
  operator question or collected evidence, and model activation probes verify a
  synthetic discovery-to-exact-log-candidate sequence.
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
  `0010_adhoc_runs`.
- A remote Kustomize overlay composes the read-only base, explicit
  `openshift-monitoring` Alertmanager API Role, group-based OAuth GUI admission,
  default-StorageClass PVC, and single-replica workload. The accompanying runbook
  covers Docker/Podman build and push, versioned internal-registry ImageStreamTag
  selection, out-of-band Secrets, existing LDAP-synchronized elevated-role
  mapping, server dry-run, RBAC checks, rollout, and rollback. Every authenticated user receives Viewer;
  each elevated application role accepts multiple existing groups; no remote
  Group or membership is created by PodPilot.

## Last Verified State

- Deployed application version: `0.11.0`; current source version: `0.12.0`.
- OpenShift lab version: `4.22.9` on the documented Hyper-V SNO.
- Deployment: `ai-ops/podpilot`, last observed `1/1` Available.
- Local automated suite: 247 tests passing with 84% aggregate branch coverage.
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
  remain non-streaming. Curated memory can now be managed and searched, but is not
  yet retrieved into investigation or chat model context.
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

1. Add bounded answer-time memory retrieval and a server-validated knowledge
   citation contract without allowing memory to influence tool or action policy.
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
