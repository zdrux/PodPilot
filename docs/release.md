# PodPilot Release And QA

Last reviewed: 2026-08-24
Update when: release surfaces, QA coverage, migrations, rollback, or deployment gates change.

Current releases must verify that the base grants no legacy remote cluster-credential
Secret access. The optional incident-response component may grant get/patch on its one
dedicated incident credential Secret; it must not grant cluster operations to the runtime.
Every Ask conversation is bound to user-delegated cluster tokens, Investigator cannot
select Action, Read-Write can select either immutable mode, private clusters are owner-isolated,
and both TLS-verified and explicitly unverified per-cluster login paths are visibly audited.
Verify the Workspace cluster tree is owner-filtered, reflects current in-memory connection state,
preselects exactly one connected cluster in a fresh composer, and sends an unconnected selection
through login before returning to that composer. Configuration administrators must receive a
separate **Cluster Management** navigation entry, while authorized users retain the ad hoc cluster
add control. The add control must open the separate **My clusters** route; non-admin users must be
denied from Cluster Management and must be unable to view, edit, test, or delete another user's
private entries.
Verify **Show my access** produces one cluster-attributed SelfSubjectAccessReview matrix per
selected cluster, reports all-namespace permissions without resource-list ceilings, and returns
the same result shape across repeated runs.

## Release Surfaces

The optional incident-response component additionally requires webhook authentication,
repeat/out-of-order notification and recurrence tests, platform-scope denial tests,
Secret isolation, connector target/repository filtering, migration round-trip,
worker restart recovery and delegated Ask handoff checks. The seed SNO composition
must pass server-side dry-run. Confirm corporate Argo CD/GitHub connectivity and a
real model-backed run before enabling Alertmanager ingress in an environment.

- Single API/web container with Alembic migrations and an OpenShift Deployment.
- OAuth proxy sidecar, OpenShift Service/Route, and NetworkPolicy.
- OpenShift identity, RBAC, and policy manifests.
- Versioned diagnostic and evaluation packages.

## Pre-Release Checklist

- Run the selected formatter, lint, typecheck, unit tests, and builds.
- Run sanitized diagnostic evals without live model credentials where possible.
- Validate manifests server-side against the target OpenShift version.
- Audit the service account and confirm no mutation verbs or secret reads were added unintentionally.
- Scan tracked and staged content for credentials, kubeconfigs, tokens, certificates, and unsanitized cluster data.
- Verify TLS validation, timeouts, bounded retries, and model-call redaction.
- Exercise degraded paths for unavailable Kubernetes, Thanos, Alertmanager, and model APIs.
- Exercise the Loki audit tenant success, empty-result, timeout, and 403 paths; confirm audit
  username matching is exact and case-insensitive and raw audit lines are never persisted.
- Verify Investigator, Approver, and Breakglass can submit audit questions through Ask while
  Viewer remains denied by the existing Investigator-or-higher boundary.
- Confirm production image digests—or the explicitly accepted versioned
  ImageStreamTag for a remote PoC—plus resource limits, probes, NetworkPolicy,
  and rollback instructions.
- Confirm the mounted OAuth `session_secret` decodes to exactly 16, 24, or 32
  raw bytes; Base64 text passed through `--from-literal` is not valid key material.
- Confirm the OAuth proxy renders `--cookie-refresh=0` and `--cookie-expire=8h`. Exercise an existing
  browser session after one hour and after a Pod restart; neither should require a new front-door
  login while the stable cookie Secret is unchanged.
- Confirm the OAuth proxy uses its proxy-only memory-backed client-secret snapshot and that changing
  the projected service-account token terminates and restarts only the proxy container. A fresh
  browser login must complete after the restart without an `unauthorized_client` callback failure.
- For a remote PoC, confirm the rendered overlay contains no static PV,
  `storageClassName`, node selector, lab hostname, cluster-admin binding, or
  credential value; verify the target has exactly one suitable default
  StorageClass before creating the PVC.
- Verify `system:authenticated` receives only the namespace-local exact-Service
  Role and that cluster-reading RBAC is attached only to `podpilot-investigator`.
- Verify an authenticated user without a configured mapping receives Viewer;
  each elevated role accepts multiple existing OpenShift Groups; all elevated
  mappings may be empty; duplicate cross-role mappings are rejected; and
  highest-role precedence is deterministic.
- Verify the named Alertmanager API permission exists in `openshift-monitoring`;
  do not create an Alertmanager role in `openshift-logging`.

## Initial QA Matrix

- Healthy cluster with only the expected `Watchdog` alert.
- Firing platform alert with matching Prometheus evidence.
- Silenced or inhibited alert.
- Missing RBAC permission with a useful, non-looping error.
- Thanos, Alertmanager, or model provider unavailable.
- Malicious instructions embedded in logs, events, labels, or annotations.
- Secret-like text in collected evidence is redacted before model and telemetry egress.
- Evidence disagreement causes uncertainty or abstention rather than fabrication.
- An unrelated follow-up cannot cite prior-turn Node or other resource evidence when its current
  audit read fails or returns no current evidence.
- A “last N” audit query expands beyond its initial window until N matches or the configured ceiling;
  a duration-only follow-up inherits the prior typed audit target, executes a fresh read, and remains
  functional after one invalid structured-classification response.
- “Last 10 delete actions according to the audit log” must compile without a username, search all
  users, filter to `delete` and `deletecollection` in Loki, and request newest-first with limit 10;
  adding “by USER” must add only the escaped exact-username filter.
- Audit queries must filter exact typed fields and rewrite matches to the compact safe projection in
  Loki before transfer; fixtures must prove verbose request/response objects are absent from LogQL
  output and cannot exhaust the bounded HTTP response for a small requested result count.
- Model-call diagnostics normalize Responses and Chat Completions usage fields, aggregate them per
  Ask turn, and keep the largest individual input visible without treating summed inputs as one
  context window. The Model usage disclosure reports end-to-end reply time from durable run
  timestamps. Fixtures must prove request bodies and authorization values are never captured.
- Model connection tests retain a collapsed latest-probe trace with operation, schema, HTTP status,
  duration, usage, and a bounded redacted response preview; saving the profile clears the old trace.

Milestone 4 automates the Watchdog-only healthy view, explicit Alertmanager
degradation, group-role denial, CSRF denial, durable investigation/audit creation,
bounded alert normalization, workload collection degradation, and evidence-backed
synthetic CrashLooping, image-waiting, and unscheduled diagnoses. Rule-state and
PromQL evidence remain a later enhancement; the three workload fixtures no longer
claim root cause from Alertmanager data alone.
It also covers Approver-only profile writes, token non-disclosure, capability
gating, structured model interpretation, and deterministic fallback during a
provider outage. Live release validation must additionally exercise the real
OpenShift Secret, OpenAI probe, and browser role boundaries without logging the
credential.

Milestone 5 adds fixtures for the two-action allowlist, server dry-run, role and
CSRF denial, preview expiry, atomic single execution, stale UID/resourceVersion
failure, delete preconditions, new-UID replacement verification, rollout patch
shape, rollout readiness verification, sibling cancellation, and complete audit
events. Live QA must use a disposable fixture namespace and must confirm the
fixture is healthy or removed before release.

Milestone 6 adds gates for creator cancellation, unauthorized cancellation,
atomic closure, expiry reconciliation, source-alert resolution, missing/stale
target validation, approval-time Alertmanager recheck, and audit attribution.
Truncated Alertmanager snapshots must neither cancel previews nor authorize an
action. Live QA must confirm cancellation performs no Kubernetes mutation and
that a removed target is closed by `system:reconciler`.

Milestone 7 adds gates for server-owned `TargetDown` planning, missing-scope
abstention, Viewer denial, CSRF denial, atomic single execution, registered-tool
enforcement, bounded Service/EndpointSlice/Pod/event reads, event redaction,
durable failure results, evidence provenance, audit attribution, model
re-interpretation, and model-free fallback. Live QA uses only the sanitized
`targetdown-investigation.yaml` fixture and must remove its namespace and platform
PrometheusRule after verifying the investigation plan.

Milestone 8 adds gates for Investigator-only chat writes, Viewer and CSRF denial,
message and history budgets, pre-persistence redaction, durable attribution,
provider outage fallback, strict structured output, server-validated evidence
citations, withholding of uncited factual claims, allowlisted tool-intent proposals,
separate check execution, and audit records without message content. Live QA must
confirm cited answers link to persisted observations and that a tool proposal does
not execute a check until the operator uses the registered-plan control.

Milestone 9 adds gates for server-owned `ALERTS` and `up` query shapes, PromQL
label escaping, bearer authentication, TLS validation, response-body and series
limits, response-shape rejection, redaction, timeout/outage fallback, passive
rule/scrape correlation, audit attribution, and incremental backfill of existing
two-check plans. Tests must prove that alert annotations, model output, browser
input, and malicious label strings cannot add PromQL or trigger a target network
connection. Live QA must retain the fixture only long enough to verify the three
checks and remove both its namespace and platform PrometheusRule afterward.

Milestone 10 adds gates for Investigator-only standalone chat, schema-valid
multi-round read plans, a ten-round and 25-unit weighted investigation budget, duplicate
suppression, discovery-followed-by-exact-container-log collection, ConfigMap and bounded-log evidence, Secret/subresource
denial, recursive redaction, persisted provenance, and withholding of uncited
cluster-specific answers. Current delegated-release RBAC gates must prove the runtime has
`podpilot-role-reader`, has no `cluster-reader` binding, can GET OpenShift Groups, and cannot
read ordinary workload objects through that identity. Retain the application broker deny tests.

HTTP-probe gates must cover arbitrary destinations, HEAD/GET-only enforcement,
SNI and Host preservation across connection overrides, TLS verification, no redirect
following, absence of credentials and custom headers, timeout/body ceilings, query-value
redaction, and durable failure evidence. Document the accepted SSRF-shaped egress
surface for every deployment environment.

Discovery-backed resource gates cover TTL caching, stable-version selection,
cross-group ambiguity and qualification, question-relevant catalog ranking,
advertised verb and namespaced-scope enforcement, sensitive resource/subresource
filtering, deterministic explicit inventory compilation, continue-token
pagination, compact projections, payload truncation, and installed-CRD reads.
They must also cover planner-initiated discovery, watch-only resources, 15-second/50-event
watch bounds, stop-on-ceiling behavior, projected/redacted events, and weighted unit accounting.
Tests must distinguish object-ceiling truncation from detail compaction, retain
all collected names, suppress provider-facing observation paths in prose, and
surface HTTP 403 limitations with ServiceAccount, verb, resource, and scope.
Inventory gates also verify the configurable 50–1,000 ceiling, the 500-object
deployment default, pagination above 50, and server-rendered cited tables that do
not depend on model formatting.
Resource-search gates must find projected matches beyond the ordinary inventory
window, enforce the independent 250–5000 scan ceiling, stop at the match-result ceiling,
and distinguish a complete search from a scan-ceiling limitation. Route URL planning
must use exact `spec.host` matching and preserve discovered namespace/name coordinates.
Collision gates must install both `routes.route.openshift.io` and
`routes.serving.knative.dev`, prove an OpenShift browser Route selects only the former,
reject mismatched coordinates, and verify ambiguity preflight consumes no read budget.
Tests must not treat a 403 from one same-plural API as authorization to try another.
Progress gates must prove that hypothesis, next-check, and finding updates are bounded,
owner-private, truthful to the current run, and removed when the final answer renders.
Route investigation gates must prove that projected backend Service references ground exact
follow-up reads and that edge/reencrypt/passthrough answers cite the matched Route while
distinguishing configured TLS behavior from live backend reachability.
Traffic-path gates must prove that Route/HTTP-5xx investigations deterministically traverse
Route to Service, Service-selected Pods, EndpointSlices, and Endpoints within the shared read
budget. They must retain bounded endpoint Pod targets, inspect relevant healthy backend logs,
and still reach those logs when a later model ReadPlan fails schema validation.
HTTP probe gates must verify that `tls_verify=false` remains HTTPS-only, keeps Host and
SNI unchanged, records `verified: false`, and produces a visible server-identity limitation.
Metric trend gates must verify authenticated `/query_range` requests, matrix validation,
server-owned templates for every registered metric, exact scope validation, PromQL escaping,
namespace/Deployment/node top-consumer rankings, deterministic namespace ranking plans,
range/step/series/point/body bounds, label redaction, statistics and trend summaries, and a
clear distinction between usage versus configured requests/limits. Tests must prove the model
and browser cannot submit PromQL or receive the ServiceAccount token.
Ingress metric gates must cover frontend aggregate bandwidth, backend namespace/Route bandwidth,
the router's `exported_namespace` label normalization, inbound/outbound pairing, three-day bounded
resolution, and native trend rendering with a peak timestamp.
Deployment tests must cover ReplicaSet/Pod ownership joins rather than name-prefix matching.
Log-volume gates must verify authenticated LokiStack application-tenant requests, server-owned
`bytes_over_time` LogQL, vector validation, namespace/series/body/time bounds, deterministic
multi-cluster rendering, and the absence of raw log lines. Manifest tests must retain
`cluster-monitoring-view` and bind the investigator only to the read-only OpenShift Logging
application, infrastructure, and audit ClusterRoles.
Range-routing tests must prove compact and worded durations preserve the operator request,
including week-based periods; sub-five-minute and over-ceiling values are bounded, `today` is derived from UTC midnight, and
transport deadlines report the configured timeout.
Node tests must cover bounded top CPU/memory rankings, optional namespace narrowing, retained
namespace/Pod/container labels, and operator-visible wording that does not misrepresent
container telemetry as host process inspection.
Node-exhaustion tests must pair overall node-exporter utilization with top workload consumers
and preserve unexplained utilization as a limitation rather than falsely attributing it.

Conversation-management gates cover owner-only list/read/continue/delete,
not-found behavior for other users regardless of role, CSRF-protected deletion,
content removal with a content-free audit record, no hard turn cap, rolling context
compaction, per-user request throttling, bounded UI history, and Enter versus
Shift+Enter behavior. Visual QA must confirm readable body, navigation, evidence,
history, and chat typography at desktop and narrow widths.
Ad-hoc log gates must distinguish a real 403 from an absent previous log stream,
decode byte responses, and verify that an absent previous stream falls back to a
bounded current stream with an explicit limitation. UI tests must verify that a
citation activates, scrolls to, focuses, and visibly highlights its evidence card.
The focused card must open its technical details while closing other expanded
cards, display the full evidence ID and relevant typed facts, and render the
persisted redacted payload and bounded log excerpt as escaped text. Answer tests
must reject plain-HTTP/no-TLS conclusions grounded only in a TLS-stage certificate
verification failure or sidecar logs, and preserve citations to the observations
used by the corrected explanation.
Automatic-follow-up gates must verify that a trust-only TLS failure schedules at
most one identical `tls_verify=false` retry without changing URL, method, connection
override, Host, or SNI; both results and the insecure-identity warning must survive.
Log-investigation gates must expose exact unready/restarting/non-running and bounded healthy
Pod/container candidates for model selection; classify representative crash, resource, TLS, DNS,
network, authorization, storage, dependency, error, and warning lines from any
container; normalize repeated signatures; and retain only bounded samples, paths,
endpoints, and timestamps. Material findings must not execute reads automatically; model-selected
Pod, owner, Event, metric, configuration, and previous-log intents must pass the same grounding
and capped broker. All log correlation must remain separate from proven causality. Durable
progress activity must distinguish model-selected reads from the mechanical TLS trust retry.
Compact-chat visual gates must verify that confidence appears as a keyboard-focusable
pill beside the reply time, its explanation appears on hover/focus, the single rounded evidence
timeline replaces the redundant inspected-target disclosure, remains closed by default, and
preserves citation navigation when expanded. Reply,
session, and evidence timestamps render in fixed `EST (-4)` without altering UTC storage.
Final-answer gates must reject citation-bearing heading-only or extremely brief model
responses and evidence-based replies that omit current material Pod-log citations, send exactly
one bounded correction without the rejected body, and activate
the deterministic Route/TLS or cited-observation fallback after a second failure.
They must accept and structurally normalize a substantive single-line response that begins with a
Markdown heading, including recognized headings flattened after Unicode bullets, while continuing to
reject a genuine standalone heading. Final-writer gates must assert that its response schema contains
only narrative and citations. Inventory/existence composition gates must prove that a valid concise
model answer is augmented with the names, namespaces, kinds, and source OpenShift clusters from every
successful current-turn list observation, with citations merged and no duplicate inventory section.
Multi-cluster inventory gates must also prove that live catalog matches bypass per-cluster model syntax,
that zero returned objects remain distinct from a missing/unreadable API type, and that a catalog miss
cannot trigger an unrelated Namespace or other resource read. Inventory detail requests must prove that
the base LIST executes before any optional model-directed detail phase, that its evidence remains
renderable if the later phase fails, and that a model-authored cluster-wide `namespace: "*"` LIST is
normalized to an omitted namespace rather than rejected as an invalid Kubernetes identifier.
Simple inventory gates must also prove that the general final writer is not called, no suggested
troubleshooting checks are emitted, the summary distinguishes matching from queried clusters, and
an absent projected Ready condition is rendered as `Unknown` rather than a health claim.
Suggested-action gates must derive controls from unread exact
server-owned candidates without consuming or parsing model recommendations.
They must also prove that an empty structured citation array can recover an exact
allowlisted observation ID from answer prose, removes that internal marker before
display, and never accepts an unknown or partial ID.
Malformed-answer gates must reject embedded `investigation_gaps` or fenced schema JSON, send one
bounded correction, and prevent serialized fields from reaching the UI. They must also strip a
trailing recommendation heading or `recommended_actions` serialization without turning its prose
into an intent.
Composition gates must prove that structured log findings remain visible with exact
Pod/container, category, severity, counts, paths/endpoints, bounded samples, and citations when
a Route/TLS fallback replaces the provider answer; correlation must not be labeled root cause.
Provider-context tests must verify current-turn prioritization, 500-character final-writer Pod-log
samples, eight cards within a 7.5 KB aggregate target, and semantic deduplication of equivalent
operator limitations while leaving persisted evidence intact. For constrained final-answer context,
tests must enforce three collection issues, cluster ID/name-only attribution, and exclusion of
raw observations, findings, knowledge, relationship graph, capability ledger, catalog, and tool policy. Empty-content gates
must prove one schema-only retry and a cited deterministic fallback after successful collection when
that retry or a later final call still fails; no-evidence provider failures remain insufficient.
Delegated-agent provider-failure gates must also prove that completed shell operations remain in the
activity and evidence ledger, executed writes are identified as not rolled back, and the fallback never
claims that no changes were attempted. Repeated identical shell calls must reach the runner independently
without a model-authored retry-reason field while remaining subject to the action budget and deadlines.
Active-run presentation gates must prove that the owner-authorized status response exposes the
bounded redacted run operation ledger, running operations render before the final assistant message,
and the terminal message ledger matches the run ledger after completion.
Chat presentation gates verify that completed Ask conversations open at the newest
message, CommonMark tables and prose render structurally, raw HTML is escaped,
unsafe link schemes do not become anchors, and code uses a distinct monospace
presentation without reducing surrounding prose readability.

Model-registry gates cover multiple auto-incremented profiles, distinct opaque
Secret keys, exactly one active profile, probe-before-activation, active-profile
deletion with deterministic ready-profile fallback, zero-model fallback,
credential deletion, token non-disclosure,
Responses versus Chat Completions routing, strict schema validation, configured
embedding probes, and invalid custom-CA handling. Insecure TLS must be visibly
distinguished from verified TLS and documented as a PoC-only exception.
Plain HTTP tests must accept only explicit Kubernetes Service DNS names when the
plaintext mode is selected, reject external hosts and mismatched modes, display
the unencrypted-credential warning, and report plaintext separately from TLS.
Ask creation with an active but non-ready profile must persist the setup response
and provider status without accessing ORM state after its session closes.
The connection test must visibly report its result and separately exercise the
live Ask PodPilot `ReadPlan` and `AdHocAnswer` contracts. Provider failures must
produce phase-specific operational events while tests prove that questions,
tokens, response bodies, and evidence do not enter application logs.
Chat Completions tests must also prove that one invalid structured response can
be corrected once without copying the rejected content into the repair prompt.
Compatibility gates cover a missing descriptive `ReadPlan` summary, reduced
probe output budgets, canonical built-in Kind/apiVersion coordinates, unchanged
custom-resource validation, and suppression of model-authored planning caveats
from trusted collection-limit displays.
Cluster-memory and multi-cluster Ask gates must cover a clean Alembic upgrade through
`0013_raw_model_responses`, FTS5 availability, immutable revision history, heading-aware
chunking, safe query-token handling, reviewed/current/enabled/expiry filters,
global/explicit-cluster/all-required-tag and namespace scope, restricted-entry
authorization, content-free audit details, and guidance-only eligible memory in standalone
Ask prompts. Tests must prove restricted or mismatched memory is absent from prompts.
Cluster registry gates must cover Approver authorization, CSRF, HTTPS-origin validation,
secret-backed token non-disclosure/rotation/removal, runtime-cluster immutability, soft
disable, and audited connection tests. Multi-cluster conversations must pin one to ten IDs,
retain prior sessions when selection changes, share the 25-unit weighted ceiling, attribute every
observation and limitation, and preserve partial results. TLS verification must default on;
the explicit off setting must be visible, audited, cluster-specific, and documented as a
credential-interception risk.
Incident-chat gates must prove that alert-scoped reads use the shared broker,
persist redacted observations before answering, validate citations against the
expanded evidence set, audit targets without payloads, and retain the separate
operator click for registered checks. Deterministic planning gates cover
StorageClass inventory, namespaced built-in lists, and exact failed-Job alert scope.
Natural-language planner gates must cover implied operational intent, unsupported
no-read answers, one structured repair attempt, valid supporting-evidence reuse,
and operator-grounded recovery after repeated initial refusal. Tests must prove
that the compact semantic classifier handles inventory wording not represented by deterministic
question patterns, emits no tools or coordinates, is invoked once for a multi-cluster turn, and
routes its resource concept through live catalog validation. Classifier failure must preserve the
deterministic/planner fallback, and classification must never bypass RBAC, sensitivity, or budgets.
Tests must also prove
that recovery is limited to one read compiled from an exact coordinate in the
operator request, still passes through the normal read broker and RBAC boundary,
returns subsequent traversal to the model, and does not activate for a plan malformed
from its first response or for generic catalog matches. A valid premature stop followed by a
schema-invalid correction may use the same anchor without executing either malformed intent.
Dynamic-traversal gates must also prove that the first evidence-supported stop for
a diagnostic goal receives one bounded sufficiency review, that the model can turn
that feedback into broker-validated typed reads, and that repeating the stop is
accepted without executing recommendation prose.
They must verify typed relationship-graph edges/frontiers, object-specific capability-ledger states,
and the distinction between available-but-not-collected and explicitly unavailable evidence. Tests
must prove that the first goal remains pinned, duplicate-only plans receive no-progress repair, and
read signatures suppress repeats across the initial and answer-gap passes. Structured medium/high
gaps and capability-matched recommendations may trigger a bounded follow-up collection phase and answer regeneration,
but recommendation prose, graph hints, and gap text must never execute directly or bypass broker
grounding, deny policy, budget, discovery, verb, or RBAC checks.
Candidate-first gates must prove that candidate rounds use the compact `ActionSelection` schema,
candidate IDs compile only to exact server-held intents, unknown IDs execute nothing, and model-authored
reads are limited to discovery, GET, and bounded field search. Tests must prove authored reads
still pass sensitive-kind denial, live discovery, namespace/verb/RBAC preflight, duplicate suppression,
and budgets. When a corrected action selection contains only malformed object reads, PodPilot must
discard them, execute nothing, and safely answer from evidence already collected instead of reporting
a failed collection round. Query-relevant catalog matches must remain available beside relationship candidates, and
bounded search results must become exact GET candidates on the next round. Provider payloads must
label search and historical LIST evidence as inventory-only. A complete collection at or below the configured
detail fan-out cap must compile to exact GETs for every non-sensitive object; incomplete or oversized
collections must compile to no blanket GETs and must report the need to narrow scope. Tests must also
prove that analysis coverage remains incomplete when any discovered object's GET detail is absent
from the final model context, even if that GET executed successfully. Actual provider payloads
must omit graph, ledger, tool policy, executable candidate intents, raw observation envelopes, and
domain-specific teaching; only a bounded policy-filtered catalog projection may be included. Tests must
assert planner caps of six fact cards/5 KB, twelve action ID/label pairs, and twelve catalog entries. The concise final-answer payload must assert
eight fact cards/7.5 KB, three collection issues, cluster ID/name-only attribution, and a schema with
only narrative plus citations. Tests must prove provider recommendation-schema tails do not leak into
Markdown and that remaining exact server candidates produce action controls without model wording. The
provider activation probe must exercise discovery followed by an exact candidate selection. A model
that returns exact supplied IDs or a valid object read must continue safely; empty actions and reads stop. Presentation tests must turn flattened bold
section labels and Unicode bullets into valid headings and lists. Follow-up Pod-log collection must
invoke the separate bounded log-analysis request before regenerating the answer. A model
that twice stops on an actionable structured gap may trigger only the highest-priority matching
candidate through the unchanged broker.
Typed planning and authored-read schemas must neither offer nor execute generic
`list_resources` or `search_resources` calls, the runtime settings and manifests must contain no
generic inventory-helper feature flag, and unified-agent tool schemas must omit both helpers.
Final-answer prompts must request Markdown tables for comparable multi-item
results; presentation tests must continue proving that answer-derived tables are bounded, sanitized,
and not treated as evidence. Resource-presentation gates must merge repeated cited internal
LIST/search observations by cluster and Kind,
deduplicate resource identity by Kind/namespace/name, retain every contributing evidence ID, and mark
the merged group incomplete if any contributing read was incomplete.
They must also prove that exact operator URLs become grounded probe candidates only after Route
evidence or a structured probe gap, and that normal-priority healthy Pod logs are offered for either
a structured log gap or an explicit failure question. EndpointSlice/Endpoints target references must
ground only the exact observed Pod, and two model stops may recover only one remaining exact log
candidate through the unchanged broker. Follow-up answer tests must partition resolved/remaining gaps from final ledger
state, reject collected checks described as uncollected, and remove comma-separated internal citation
markers while retaining their allowlisted citations.
Natural Pod-log request gates must prove that an explicit namespace and Pod-name hint compile to a
bounded `metadata.name contains` Pod search, that ambiguous or namespace-free wording does not, and
that only exact Pod/container candidates emitted by the search can authorize the subsequent bounded
log read and isolated semantic analysis.
Suggested-action gates must remove already-collected recommendations, render controls only for exact
unread server candidates, and prove that a valid owner/CSRF click persists a linked run, sends no prior
chat messages or summary to the provider, retains a bounded original question, executes only the exact
rederived read through the broker without restarting planning, and appends a labeled result to the same
conversation. Unknown IDs, another user's message, stale candidates,
mutation wording, and tampered cluster/capability metadata must execute nothing.
Ask-job gates must prove that submission returns before model completion, the
question and job are durable before execution, progress phases reflect actual
server actions, and the final assistant message is atomically linked to terminal
state. Tests must cover restart recovery, one active turn per conversation, simultaneous runs
for different users, the configured per-user running ceiling, SQLite WAL/busy-timeout settings,
active-conversation deletion refusal, owner-only status/SSE access, SSE completion,
and optimistic composer clearing. Progress text must remain server-authored and
must not include prompts, evidence bodies, credentials, or chain-of-thought.
Raw-answer capture gates must prove that the per-question switch defaults off, survives
durable queue processing, retains both initial and correction answer bodies when present,
and renders only bounded redacted escaped text to the conversation owner. Raw output must
not alter provider validation, citations, deterministic fallback, audits, or action policy.
Pod-log resiliency gates must prove that Pod lists emit bounded exact candidate
tuples, candidate IDs are stable within persisted evidence, and model-authored
names cannot override them. Invalid targets must trigger one repair without
spending the read budget; repeated invalid targets must use no more than three
relevant exact candidates. Tests must distinguish planner rejection, `pods/log`
RBAC denial, missing previous streams, and successful current/previous collection.
Pod-health gates must place a `Running`-phase `CrashLoopBackOff` Pod after enough healthy Pods to
exceed the ordinary detail payload and prove that the typed summary still detects it. They must
cover init-container failures, successful Job completion, anomaly result truncation, and a Pod
beyond the scan ceiling. A zero-anomaly result may be confirmed only when `scanComplete` is true;
an incomplete scan must produce an unresolved absence conclusion.
Resource-health gates must cover Node readiness/pressure, ClusterOperator availability/degradation,
Machine failure and missing-API behavior, and Deployment/StatefulSet/DaemonSet rollout state.
Machine and workload tests must prove namespace propagation; Node and ClusterOperator intents must
reject namespaces. Combined workload evidence must expose per-kind scan counts, and every typed
summary must preserve the complete-coverage rule before confirming absence.

## Delegated agent gates

- The portable runtime has one delegated agent workflow; conversations select `read_only` or
  role-authorized `action` execution.
- The SNO milestone overlay renders an `oc-runner` container and
  `serviceAccountName: podpilot-investigator`.
- The remote agentic overlay composes the remote overlay plus the shared runner
  component, renders both versioned ImageStreams, forces remote TLS verification off, and contains
  no cluster-admin binding.
- No resource composed for that runtime binds `podpilot-investigator` to `cluster-admin`; live
  validation must return `yes` for cluster-wide Pod GET and `no` for cluster-wide Deployment PATCH.
- The runner image pins its OpenShift CLI source by digest, runs non-root with a read-only root
  filesystem, drops all capabilities, binds only to `127.0.0.1:8090`, and uses a projected-token
  `tokenFile` kubeconfig.
- Provider tests must prove `openai/gpt-oss-120b` is sent through Chat Completions with
  `tool_choice=auto`, sequential tool calls, assistant tool-call preservation, and correlated
  `role=tool` results.
- Provider-input tests must prove oversized shell results are compacted before reinjection, token
  estimates are not raw UTF-8 byte counts, and the complete messages-plus-tools request stays below
  `max_input_tokens`. Irreducible requests must fail locally without provider transmission, the
  operator must see the configured input-token limit rather than an internal exception type even
  when prior evidence exists, and bounded redacted 4xx/5xx error details must be retained.
- Oversized-JSON tests must prove the provider receives no byte-truncated JSON or server-selected
  domain fields. The refinement response must expose bounded structural metadata and direct the
  agent to choose and run a narrower projection before answering the inventory.
- End-to-end tests must prove an agent-selected command reaches the injected runner, its result is
  returned to the model, the final answer persists, and `agentic.command` audit metadata is written.
  A raw tool result and its assistant call may be sent through one subsequent model request only;
  later requests must replace the completed pair with the bounded rolling evidence ledger. Ledger
  pressure must reduce successful read-only shell details before mutation, typed-observation, or
  failure details. Manifest tests must keep the single app-wide action budget at 50 for delegated
  agents and typed planning.
  Successful mutations must be marked as writes. In Action mode, a final answer that describes
  writes as blocked, claims the session is read-only, or asks for another approval without an actual
  forbidden write result must be rejected and returned to the tool-capable loop before display.
- Multi-cluster agent tests must prove every command names a selected cluster, only that cluster's
  token reaches the loopback runner, tokens never enter model messages or logs, the temporary
  kubeconfig requests insecure TLS in the remote agentic overlay, and a redacted failed-command
  summary is visible to the operator.
- Runner watchdog tests must cover silent process polling, periodic API progress,
  process-group termination at the command deadline, exit code `124`, and a loopback client timeout
  longer than the runner deadline. They must also prove stdout/stderr are continuously drained,
  retained within the configured byte ceiling, and visibly marked when truncated. Both containers
  retain working liveness/readiness probes.
- Delegated-mode parity tests must prove Investigator and Action conversations enter the same agent
  loop with identical investigation tools, including HTTP probes, metrics, and audit events, while
  omitting generic LIST and SEARCH helpers. Investigator commands must receive only the read-only
  capability; the proxy must allow Kubernetes GET/HEAD/OPTIONS and SelfSubject reviews while
  rejecting writes, exec/attach/proxy/port-forward variants, and Secret reads. Action commands must
  receive the action capability without exposing the user's token to the model or runner.
- Delegated typed-reader tests must prove lazy Kubernetes discovery runs outside the ASGI event loop,
  so loopback broker requests and liveness/readiness probes remain serviceable during collector
  initialization. They must also prove the metric and audit adapters use the selected cluster URL
  and TLS policy, resolve only the current in-memory delegated token, and fail closed after session
  revocation.
- Agent-tool correction tests must prove cluster IDs are constrained to the selected set, one call
  cannot concatenate multiple targets, generic object inventory/search is performed with bounded
  `oc get`, and malformed attempts render as collapsed diagnostics rather than unresolved
  limitations. Genuine runner and collector failures must remain prominent.
- Agent-loop contract tests must prove finalization records `complete`, `blocked`, or
  `budget_exhausted`; claimed completion with safe reads remaining returns to the tool loop; exact
  same-cluster commands require an approved retry/comparison reason; and Loki TLS verification
  failures retain the `tls_verification_failed` category. These gates must not impose a fixed
  product-specific diagnostic sequence.
- Safe-Markdown presentation tests must prove attribute-free HTML break tags render as line breaks
  in extracted and fallback Markdown tables without enabling other raw HTML or interpreting tags
  inside code spans and fences. They must also prove answer-table cleanup removes unmatched
  serialization braces and redundant leading `unknown` placeholders while retaining balanced `{}`
  and OpenShift Logging template expressions.
- Delegated-session lifecycle tests must prove later logins append clusters to the current browser
  session, individual removal revokes only the selected token, removed clusters disappear from new
  conversation selectors, and existing conversations retain durable history while requiring
  reconnection when one of their selected clusters is removed.
- Known-read enrichment tests must prove delegated log-volume wording executes the registered
  `top_log_volume_by_namespace` reader with cluster scope and namespace grouping, supplies Loki evidence to the agent, preserves the
  native payload-volume metric card, and never substitutes Kubernetes Event counts.
- Scoped log-volume tests must prove the dedicated cluster namespace ranking, exact cluster,
  namespace, Pod, and Node totals; Pod rankings within a
  namespace; cluster-wide Pod and Node rankings; server-owned selectors/groupings; and that no
  matching log lines or model-authored LogQL cross the evidence boundary.
- Shared-enrichment tests must prove the delegated workflow can compile the typed metric, audit, and
  catalog-grounded resource semantics. Metrics tests must prove a failed Thanos Node ranking falls
  back to a normalized current Kubernetes Metrics API snapshot and marks the loss of history.
- Agent-first completion tests must prove causal Pod and resource questions continue from the
  registered read into model-selected checks, while explicit show/list/ranking requests may stop
  on a complete registered result. UI presentation preference must not terminate execution.
- Multi-cluster follow-up tests must prove opaque object references retain a uniquely attributable
  source cluster and do not fan an exact namespace/name investigation out to unrelated clusters.
- Kafka inventory tests must cover imperative and interrogative deployment wording, execute the
  canonical Strimzi Kafka list once on every selected cluster, distinguish found/empty/failed
  cluster results, include failures in the coverage denominator, and never enter the shell loop.
- Failure-authority tests must prove an unavailable registered source plus failed shell verification
  cannot become an unsupported model claim about a missing metrics server or add-on.
- Terminal-enrichment tests must prove a successful registered audit answer renders exactly once,
  suppresses a competing delegated shell call, preserves all-user wording, and enforces explicit
  namespace, delete-operation, and Kubernetes resource filters in both Loki and local projection.
- Audit-adherence tests must prove an explicit last/top count overrides the configured default and
  that delete/mutation plus successful/failed wording overrides broader classifier output before
  the Loki query is compiled.
- Audit-window tests must prove only an operator-specified count enables backward search expansion;
  an unnumbered recent query must remain in the initial window even if the classifier supplies a
  convenience result limit.
- Audit-failure authority tests must prove a timed-out or denied registered Loki audit read renders
  its real failure without calling the model shell loop, `oc-runner`, `events.audit.k8s.io`, or
  optional command-line JSON utilities.
- Metric-continuation tests must prove a delegated same-metric period follow-up reuses the prior
  registered ranking and original top-N while changing only the requested range. The log-volume
  fixture must remain on the Loki adapter, accept the shipped three-day window within the seven-day
  ceiling, and never attempt `pods/exec` or `logcli`.
- Agent-loop tests must prove one empty Chat Completions turn triggers exactly one finalization
  retry, reuses existing tool results, and does not replay a completed runner command.

## Rollback

For production, reapply the previous immutable application image digest and
matching manifest revision. For the remote PoC, restore the previous versioned
ImageStreamTag in `newTag`; do not overwrite promoted tags. The SNO binary build
continues to publish `:latest` for iteration. In every case, wait for
`deployment/podpilot` to become available. Alembic migrations must be
backward-compatible until a separate, tested database rollback procedure exists.
