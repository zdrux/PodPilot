# PodPilot Release And QA

Last reviewed: 2026-08-24
Update when: release surfaces, QA coverage, migrations, rollback, or deployment gates change.

## Release Surfaces

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
- Confirm production image digests—or the explicitly accepted versioned
  ImageStreamTag for a remote PoC—plus resource limits, probes, NetworkPolicy,
  and rollback instructions.
- Confirm the mounted OAuth `session_secret` decodes to exactly 16, 24, or 32
  raw bytes; Base64 text passed through `--from-literal` is not valid key material.
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
multi-round read plans, a five-round and twelve-total-read budget, duplicate
suppression, discovery-followed-by-exact-container-log collection, ConfigMap and bounded-log evidence, Secret/subresource
denial, recursive redaction, persisted provenance, and withholding of uncited
cluster-specific answers. Audit both `cluster-reader` effective permissions and
the application broker deny tests before release.

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
Deployment tests must cover ReplicaSet/Pod ownership joins rather than name-prefix matching.
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
Log-investigation gates must prioritize exact unready/restarting/non-running
Pod/container candidates while also allowing bounded healthy backend candidates for an active
traffic-path investigation; classify representative crash, resource, TLS, DNS,
network, authorization, storage, dependency, error, and warning lines from any
container; normalize repeated signatures; and retain only bounded samples, paths,
endpoints, and timestamps. Material findings may perform only exact Pod, Pod-Event,
and applicable previous-log reads within the shared capped budget. A lone warning
must not expand automatically, and all log correlation must remain separate from
proven causality. The activity UI must label deterministic follow-ups.
Compact-chat visual gates must verify that confidence appears as a keyboard-focusable
pill beside the reply time, its explanation appears on hover/focus, evidence timelines
are closed by default and preserve citation navigation when expanded, and reply,
session, and evidence timestamps render in fixed `EST (-4)` without altering UTC storage.
Final-answer gates must reject citation-bearing heading-only or extremely brief model
responses, send exactly one bounded correction without the rejected body, and activate
the deterministic Route/TLS or cited-observation fallback after a second failure.
Provider-context tests must verify current-turn prioritization, bounded Pod-log excerpts,
per-observation and 96 KB total evidence ceilings, compact findings, and semantic
deduplication of equivalent operator limitations while leaving persisted evidence intact.
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
Cluster-memory gates must cover a clean Alembic upgrade through
`0011_cluster_memory`, FTS5 availability, immutable revision history, heading-aware
chunking, safe query-token handling, reviewed/current/enabled/expiry filters,
cluster and namespace scope, restricted-entry authorization, content-free audit
details, and the explicit absence of memory from model prompts in this phase.
Incident-chat gates must prove that alert-scoped reads use the shared broker,
persist redacted observations before answering, validate citations against the
expanded evidence set, audit targets without payloads, and retain the separate
operator click for registered checks. Deterministic planning gates cover
StorageClass inventory, namespaced built-in lists, and exact failed-Job alert scope.
Natural-language planner gates must cover implied operational intent, unsupported
no-read answers, one structured repair attempt, valid supporting-evidence reuse,
and discovery-backed fallback after repeated refusal. Tests must prove that the
fallback uses only a live policy-filtered catalog entry and still passes through
the normal read broker and RBAC boundary.
Ask-job gates must prove that submission returns before model completion, the
question and job are durable before execution, progress phases reflect actual
server actions, and the final assistant message is atomically linked to terminal
state. Tests must cover restart recovery, one active turn per conversation,
active-conversation deletion refusal, owner-only status/SSE access, SSE completion,
and optimistic composer clearing. Progress text must remain server-authored and
must not include prompts, evidence bodies, credentials, or chain-of-thought.
Pod-log resiliency gates must prove that Pod lists emit bounded exact candidate
tuples, candidate IDs are stable within persisted evidence, and model-authored
names cannot override them. Invalid targets must trigger one repair without
spending the read budget; repeated invalid targets must use no more than three
relevant exact candidates. Tests must distinguish planner rejection, `pods/log`
RBAC denial, missing previous streams, and successful current/previous collection.

## Rollback

For production, reapply the previous immutable application image digest and
matching manifest revision. For the remote PoC, restore the previous versioned
ImageStreamTag in `newTag`; do not overwrite promoted tags. The SNO binary build
continues to publish `:latest` for iteration. In every case, wait for
`deployment/podpilot` to become available. Alembic migrations must be
backward-compatible until a separate, tested database rollback procedure exists.
