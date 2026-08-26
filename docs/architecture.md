# PodPilot Architecture

Last reviewed: 2026-08-26
Update when: ownership boundaries, data flow, integrations, or trust boundaries change.

## Overview

PodPilot converts OpenShift operational signals into evidence-backed troubleshooting
investigations. Deterministic clients gather cluster resources, events, logs,
PromQL results, alert rules, and active alerts. Diagnostic tools normalize and
correlate that evidence before an AI layer explains likely causes and next steps.

The initial product is investigative by default and supports a small catalog of
approved remediations. Mutations cross a dedicated policy boundary and must not
be smuggled in through generic shell or unrestricted Kubernetes tools.

## Components

- **API/orchestrator**: accepts investigation requests, selects bounded diagnostic tools, enforces budgets and policy, and streams results.
- **Web UI**: Jinja2/HTMX views served by the API show alert context, streamed investigation progress, evidence provenance, uncertainty, and suggested operator actions.
- **OpenShift client**: reads the Kubernetes API plus Thanos and Alertmanager, validates TLS, and normalizes failures.
- **Diagnostics engine**: implements deterministic checks and correlation independent of any model provider.
- **Model adapter**: presents one internal contract over configured OpenAI-compatible endpoints, capability probes each profile, and turns normalized evidence into explanations while preserving citations and redaction rules.
- **Evaluation harness**: replays sanitized incidents and scores evidence use, diagnosis quality, safety, and abstention.

## Current Runtime

The current single Pod contains two containers. The OpenShift OAuth proxy is the
only network-facing container and forwards authenticated requests to FastAPI on
`127.0.0.1:8080`. FastAPI accepts the proxy-supplied username, resolves the
highest matching elevated role from deployment-configured OpenShift Group lists
or defaults the authenticated user to Viewer, renders the dashboard,
and persists schema state in SQLite on the `podpilot-data` PVC. An init container
runs Alembic before the application starts. The Service exposes only proxy port
4180, and the edge-terminated Route redirects HTTP to HTTPS.

The Alertmanager adapter uses the projected service
account token and OpenShift service CA to call the in-cluster v2 API. Dashboard
requests obtain a fresh snapshot; Alertmanager remains the source of truth and
PodPilot does not create a second alert store. Watchdog is separated from the
actionable queue, while collection failure produces an explicit degraded state.

An Investigator can create one durable investigation from an active fingerprint.
The API re-reads Alertmanager before creation, runs a deterministic alert-type
triage pack, stores the bounded alert snapshot and evidence-linked result, and
records an audit event. Analyze is protected by both application role and a
double-submit CSRF token.

Milestone 3 adds a read-only Kubernetes workload evidence adapter. For the three
initial workload-alert types it selects exactly one alert-identified Pod, collects
bounded status and recent events, follows at most three controller owner links,
and conditionally collects targeted logs for crash loops or at most 50 node
scheduling summaries for unscheduled Pods. Collection failures are retained as
limitations, and all event, status-message, image, and log text is redacted before
persistence. It contains no model call, PromQL query, chat, or cluster mutation.

The provider registry keeps endpoint metadata and capability results in SQLite;
tokens live only as per-profile data keys in the resourceName-restricted
`ai-ops/podpilot-model-credentials` Secret. An Approver can add, edit, probe,
activate, and delete endpoints without restarting the Pod. Exactly one successfully
probed profile is active. The API rereads its token key from the Secret for every
model call. Provider-neutral contracts route either to the official OpenAI
Responses API adapter (`store=false`) or a strict JSON-schema Chat Completions
adapter for compatible internal gateways. System trust, a SQLite-held custom CA,
or an explicitly insecure TLS mode can be selected per endpoint; insecure mode is
reported as accepted rather than verified.

Only a profile that passes endpoint, TLS acceptance, authentication, model,
structured-output, and configured embedding checks is usable. Streaming and tool
calling are recorded capabilities but are not required because the current agent
loop exchanges schema-validated read plans rather than provider-native tool calls.
Schema-validated interpretation is displayed separately from deterministic facts.
Provider failure preserves the deterministic investigation and records a bounded,
credential-free error.

The Ask-only cluster registry stores API origins, tags, lifecycle state, TLS policy,
and opaque credential keys in SQLite. Remote bearer tokens live under those keys in
the resourceName-restricted `ai-ops/podpilot-cluster-credentials` Secret. The runtime
cluster is registered automatically and continues to use its projected service-account
identity. An Approver can create, update, test, and disable remote entries; disabling
removes the usable token but retains metadata and historical attribution.

Every standalone Ask conversation stores an immutable ordered selection of one to ten
cluster IDs. Changing selection starts another conversation and preserves the old session.
The worker fans a question out across the selected enabled clusters within one shared
twelve-read ceiling, builds a separate Kubernetes client and discovery catalog for each,
and attributes every observation, read record, citation, limitation, and comparison to its
source cluster. A failed or disabled target becomes a cluster-specific limitation instead
of invalidating successful targets. This routing does not apply to Alertmanager, dashboard
health, alert investigations, metrics on remote clusters, or remediation in this release.

Cluster memory stores curated Markdown or text as immutable
versions in SQLite and indexes heading-aware bounded chunks with FTS5. Approvers
create, revise, enable, and disable entries; Investigators can preview retrieval.
Normal code filters candidates by current version, enabled and reviewed state,
expiry, optional namespace, sensitivity, and target eligibility before BM25 ranking.
An entry is eligible when it is global (no targets), explicitly selects the cluster,
or all of its required key/value tags match the cluster. Explicit and tag matches use
OR semantics. Search
input is tokenized into a bounded quoted expression rather than accepted as raw
FTS syntax. Restricted entries are visible only to Approvers and are never supplied
to Ask workers. Eligible internal entries are supplied to planning and answer prompts
with their applicable cluster identity and an explicit guidance-only trust label; they
cannot define tools, authorize reads, replace live evidence, or serve as citations for
current cluster state.

Milestone 5 adds a policy-owned typed action catalog. A crash-loop investigation
can generate at most two server-built proposals: delete the exact failed,
controller-owned Pod or restart its Deployment, StatefulSet, or DaemonSet. The
browser submits only an opaque action ID; it cannot provide a target, patch, or
command. Each proposal persists its target UID and resourceVersion, fixed API
operation, risk, expiry, server dry-run, verification query, and recovery note.

Approver-or-higher users must reveal a second confirmation control and press
**Approve and run** before execution. The API atomically claims the preview once,
re-reads resource identity, executes through the OpenShift adapter, polls bounded
postconditions, and stores before/API/verification/after results. Pod verification
requires a new Ready UID owned by the same direct controller and explicitly
excludes pre-existing healthy siblings. A rollout verifies its fixed restart
annotation, observed generation, and desired updated/Ready counts. Executing one
proposal cancels sibling previews; another mutation requires fresh evidence.

Milestone 6 adds a lifecycle reconciler around those proposals. Dashboard reads
expire overdue previews and, only from a complete Alertmanager snapshot, cancel
previews whose source fingerprint is no longer active. Investigation reads call a
read-only executor validation for the exact target UID/resourceVersion and close
missing or stale previews without issuing a dry-run or mutation. Approval fetches
Alertmanager again and fails closed if the alert cannot be proven active.
Investigation creators and Approvers may explicitly cancel previews; only
Approvers retain execution permission. Closure reason, actor, time, and detail
are persisted in the action result and audit stream.

Milestone 7 adds persisted `DiagnosticCheck` records and a server-owned tool
registry. A `TargetDown` investigation with namespace and Service labels receives
two queued checks: Service/EndpointSlice/Pod topology and bounded target-Pod
events. An Investigator can atomically claim the plan once. The OpenShift adapter
performs only fixed Kubernetes GET/LIST calls, redacts free text, and returns
portable evidence contracts. Results are appended to confirmed observations and
the model is called again with the expanded evidence. The model and browser
cannot add a tool, target, selector, command, or mutation. Existing compatible
investigations receive the plan lazily when opened after the schema upgrade.

Milestone 8 adds durable `ChatMessage` records and a provider-level structured
chat contract. The API composes bounded context from one investigation, redacts
the operator message before storage, and sends no Kubernetes credentials or
generic Kubernetes client to the provider. Incident chat now shares Ask
PodPilot's bounded read-plan broker: up to five planning rounds and twelve total
resource, ConfigMap, Event, Pod-log, or HTTP-probe reads run under the same read-only identity,
deny policy, normalization, redaction, and evidence cap. Trusted alert labels seed
exact scope for deterministic cases such as a failed Job, and newly collected
observations are persisted into the investigation before interpretation. Model
citations are intersected with that expanded observation-ID set; uncited
evidence-based claims are replaced with an insufficient-evidence response. The
server separately accepts only the literal `run_queued_checks` proposal while
queued `DiagnosticCheck` records exist, and that proposal still requires a
distinct operator click.

Milestone 9 adds a bounded Thanos query adapter and a third server-owned
`TargetDown` check. The diagnostics registry derives exact namespace, Service,
job, and instance matchers from the persisted normalized alert. The adapter sends
only fixed `ALERTS` and `up` instant-query shapes to the authenticated in-cluster
Thanos endpoint, validates its service certificate, caps time, body size, and
series count, and normalizes values and label provenance. It does not expose a
generic PromQL endpoint to the API, browser, or model. The later typed HTTP probe
is separate from PromQL and never attaches the service-account token or model
credentials to a request.

Ask PodPilot later reuses the authenticated adapter through `query_metrics`. The model
selects only a registered metric, pod/namespace/Deployment/node/PVC scope, exact coordinates, range, and
step. Normal code compiles server-owned PromQL and calls `/api/v1/query_range`, accepts only
matrix results, caps series/points/body/time, redacts labels, and persists normalized points
plus minimum, maximum, average, current, trend, unit, and completeness. Requested resolution
is increased automatically when necessary to keep the series within its point ceiling.
Deployment templates join `kube_replicaset_owner` and `kube_pod_owner`, avoiding unreliable
Pod-name-prefix inference. Node templates join workload series with `kube_pod_info`; top CPU
and memory queries support namespace, Deployment, and node scopes while retaining bounded
namespace/Pod/container labels and per-series rankings. Common namespace top-consumer
questions compile deterministically so a planner schema failure cannot prevent the typed query.
These are container/workload observations, not host process telemetry.
Overall node CPU/memory utilization comes from bounded node-exporter templates joined to
`node_uname_info`. Resource-exhaustion planning should collect both overall utilization and
top workload consumers; any unexplained difference may be host, kernel, cache, or unmonitored
work and must remain a limitation rather than being assigned to a Pod.

Milestone 10 adds standalone Ask PodPilot conversations and the reusable read
broker later shared by incident chat. Up to five
schema-validated planning rounds may select at most twelve total reads from
`get_resource`, `list_resources`, `search_resources`, `pod_logs`, `http_probe`, and
`query_metrics`; each round receives the bounded
observations from earlier rounds so resource discovery can lead to exact log reads.
Normal code validates the discovered resource, scope, verb, limits, duplicate
suppression, and deny policy. A five-minute, process-local discovery catalog
collapses duplicate versions within an API group, qualifies cross-group name
collisions, and ranks resources mentioned in the question ahead of the prompt
cap. The model proposes a plural resource name; server code resolves the current
apiVersion, Kind, namespaced scope, and advertised read verb. Unambiguous
inventory questions compile directly from that live catalog so a model cannot
omit the only required intent. The small built-in canonicalization table remains
only as a compatibility path for older model output.
The planner classifies natural-language intent as inventory, health, diagnosis,
logs, comparison, or explanation. Normal code derives the collection decision
from typed intents or clarification content instead of rejecting a useful plan
because a redundant discriminator disagreed. If an operational answer
has no valid evidence—or a matching safe catalog target exists but the model
declines to read it—the API supplies structured feedback and retries planning
once. A second refusal falls back to the read compiled from live discovery. This
fallback is generic across served resources; it does not grant a model a client
or require a static list of OpenShift object types.
ConfigMaps, bounded logs, and unauthenticated HTTP/HTTPS probes are intentional
evidence sources. HTTP probes may target any model-selected URL, but remain typed:
HEAD or bounded GET only, no redirects, request bodies, credentials, or custom headers.
TLS verification defaults on, but an individual HTTPS troubleshooting probe may disable
it for private, self-signed, or component-managed certificates; evidence then explicitly
states that server identity was not verified. The URL hostname supplies both HTTP Host and TLS SNI; an optional
connection-host override supports passthrough Route testing against a specific
router address. Secrets, access-review resources, arbitrary subresources, commands,
and mutations remain rejected. A final model pass receives normalized, redacted
observations, and cluster-specific answers are withheld unless they cite persisted
evidence IDs. A planning-round failure is recorded as an explicit limitation.
Evidence-derived automatic continuations already queued by normal code still complete within
the shared budget; a failed model plan cannot cancel deterministic traffic traversal or log
correlation.
List reads follow Kubernetes continue tokens within the per-turn budget and emit
one compact collection observation. Kind-aware projections retain operational
status, conditions, ownership, and selected scheduling/routing/storage fields.
Collected object names are retained separately from detailed projections.
`objectListComplete` reports whether the Kubernetes object ceiling was reached,
while `detailsTruncated` reports only status-detail compaction; the latter must
not be presented as proof that more objects exist.
The inventory object ceiling is deployment-configurable (500 by default, 1,000
maximum). Explicit list/inventory requests are rendered by normal server code as
an evidence-cited Markdown table from the collected `names` array, so model prose
cannot omit the requested resource list.

`search_resources` is distinct from inventory. It follows continue tokens up to a
separate scan ceiling (2,000 by default, 5,000 maximum), compares a model-selected,
validated dot-separated object field path, and returns only bounded compact matches.
Paths may traverse nested objects and lists, allowing searches such as `spec.type` and
`status.conditions.type`; malformed path expressions are rejected. Route questions
containing a URL compile directly to an exact `spec.host` search, allowing a later round
to GET the discovered namespace/name.
The deterministic search uses the qualified `routes.route.openshift.io` resource. More
generally, discovery resolves an unqualified plural with supplied `apiVersion` and `Kind`
only when both agree with one advertised resource; mismatches fail closed. Preflight performs
this resolution before the read budget advances. Same-plural APIs such as OpenShift and
Knative Routes are not treated as interchangeable fallbacks after ambiguity or RBAC denial.
Projected Route evidence treats `spec.to.name` and `spec.alternateBackends[].name` as
observed Service references, so exact follow-up Service reads are not rejected as model
inventions. Route protocol questions also have a deterministic cited interpretation: `edge`
forwards HTTP after router TLS termination, `reencrypt` establishes new backend TLS, and
`passthrough` leaves TLS termination to the backend. This states configuration, not live
backend reachability or the origin of an HTTP 500.

For Route, HTTP 5xx, and connectivity investigations, normal code follows a bounded traffic
graph from an observed Route to its exact Service, Service-selected Pods, EndpointSlices, and
legacy Endpoints. Endpoint projections retain bounded Pod target references. PodPilot reads
logs from up to three relevant backend containers even when the Pods are Running and Ready,
because application failures need not affect Kubernetes health. This deterministic traversal
uses the same twelve-read ceiling, deduplication, redaction, and RBAC boundary as model-planned
reads; it is a safety net for basic Kubernetes relationships, not unrestricted crawling.

An explicit TCP/connectivity question that names one Pod in each of two namespaces receives a
separate deterministic policy check before model planning. Normal code reads both exact Pods,
both Namespace objects, and a bounded list of NetworkPolicies in each namespace. Compact policy
evidence retains `podSelector`, `policyTypes`, ingress and egress peers, and ports so the answer
can compare destination ingress isolation with source egress isolation using observed Pod and
Namespace labels. This configuration evidence identifies a plausible policy factor; it does not
prove packet drops because PodPilot does not exec a source-originated probe inside the workload.

Pod LIST and named Pod observations also retain a separately bounded registry of
exact Pod and container log candidates. Each candidate receives an opaque
server-derived ID. A model may call `pods/log` only by selecting one of those IDs;
normal code binds it back to the observed namespace, Pod, and container. Literal
placeholders fail the evidence contract before planning completes. Named GET
targets must appear verbatim in the operator question or in collected evidence,
otherwise the planner must discover them with a bounded LIST first. Fabricated or
ambiguous targets consume no cluster-read budget and receive one structured repair
attempt. If the model repeats an invalid log selection, server code may collect
current logs from at most three question-relevant observed candidates; previous
logs are selected only for an explicit restart/crash/terminated question and an
observed positive restart count.

Ad-hoc conversations are private to the creating OpenShift identity. The creator
can start, continue, and permanently delete the conversation and its messages and
evidence; deletion leaves a content-free audit event. There is no per-conversation
question limit. The model receives the ten most recent messages plus a bounded,
durable digest of older messages. UI rendering is capped independently, evidence
retains its existing bounded window, and a per-user one-minute request limit
controls cost and accidental rapid submission without ending a conversation.

Ask turns are persisted as `AdHocRun` jobs before execution. The single-replica
SQLite deployment runs one in-process worker, permits one queued or running turn
per conversation, and atomically stores the assistant reply with the terminal job
state. A restart changes interrupted `running` jobs back to `queued`, so the worker
can recover them from the PVC. The browser receives an immediate redirect, renders
the submitted question optimistically, and follows owner-authorized Server-Sent
Events for durable `starting`, `discovering`, `planning`, `collecting`, `answering`,
and terminal updates. Reloading reconstructs the same state from SQLite, and an
SSE heartbeat keeps the OpenShift Route connection active. These events describe
server-observed workflow actions; PodPilot does not expose model chain-of-thought.
The final schema-validated answer remains a complete response rather than token
streaming.
Pod-log collection distinguishes authorization, missing-resource, and invalid-log
stream failures. When Kubernetes reports that a requested previous terminated
container log is no longer retained, the read broker performs one bounded current
log read instead and records the fallback as a limitation; it does not describe
that condition as an RBAC denial. Citation links explicitly scroll and focus the
matching evidence card, including when the evidence drawer has its own scroll area.
Chat content is rendered server-side through a CommonMark parser with raw HTML
disabled and unsafe link schemes rejected. The UI supports structured headings,
lists, emphasis, inline and fenced code, blockquotes, and tables without trusting
model- or cluster-supplied markup. Ask answer normalization preserves Markdown
paragraph boundaries, removes inline evidence-ID markers that the citation UI
renders separately, and promotes recognized inline labels such as `Root cause:`
and `Remediation:` into headings only when the provider returned otherwise
unstructured prose. Ask PodPilot initializes its bounded chat viewport at the
newest message after navigation while retaining normal manual scrolling afterward.
Private Ask sessions are rendered as a nested list beneath the primary Ask
PodPilot navigation item and expose owner-authorized deletion controls. Collected
evidence no longer consumes a permanent content column: a count in the chat header
opens a modal provenance drawer, and answer citations open that drawer focused on
the matching evidence card. Reply citations are collapsed by default beneath a
compact disclosure and expand into a vertical provenance timeline with the evidence
tool, summary, first material fact, and stable evidence ID. Drawer cards expose typed operator
facts (including exact object coordinates, selected Route/Service/Pod fields,
probe SNI and connection diagnostics, metric bounds, and log container identity),
plus an expandable redacted payload or bounded log excerpt. These views are built
server-side from persisted redacted observations; they do not expose provider
reasoning or unredacted Kubernetes responses.
Assistant confidence is a compact pill beside the reply timestamp; its explanation
appears on hover or keyboard focus. Ask reply, session, and evidence timestamps are
converted from persisted UTC to a fixed `EST (-4)` presentation.

Final-answer validation also rejects a specific unsafe TLS inference: a certificate
verification failure during the TLS stage proves that a peer presented TLS and a
certificate, so it cannot support a conclusion that the backend serves only plain
HTTP. Sidecar logs likewise cannot establish the application container's listener
protocol. When a provider makes that contradictory claim, deterministic code
replaces it with observed facts, the supported conclusion, and the remaining direct
probe or application evidence needed.

The read broker also owns two deterministic investigation continuations. A verified
HTTPS probe that fails only at certificate trust is repeated at most once per target
with the identical URL, method, connection override, Host, and SNI but
`tls_verify=false`; both observations remain evidence and the retry is explicitly
unauthenticated. Pod evidence assigns deterministic investigation priority to
unready, restarting, or non-running containers, allowing bounded current-log reads
without model-authored coordinates. Logs from any container are classified into
typed operational signals (crash/exception, resource pressure, TLS, DNS, network,
authorization, storage, dependency, application error, or warning). Each structured
finding records exact Pod/container provenance, repetition and normalized signature
counts, observed timestamps, bounded samples, paths, and endpoints. Material signals
produce exact Pod and namespace Event follow-ups; crash/resource signals may also
read the same container's previous stream. Automatic continuations share the existing
per-turn budget, are capped and deduplicated, and cannot read Secrets or expand RBAC.
Findings are evidence summaries, not executable instructions, and neither pattern
matches nor log correlation alone establish causality.

The final-answer boundary is separately compacted from durable evidence. Current-turn
observations are ordered first; each observation, Pod-log excerpt, structured finding,
and the total provider observation payload have byte or count ceilings. The database
and evidence drawer retain the complete redacted bounded observations. A schema-valid
answer must also pass semantic substance checks: citations plus headings alone are not
enough, and every current Pod-log observation with a structured finding must be cited. One
bounded correction attempt receives only an error code and instruction.
Persistent incompleteness activates deterministic Route/TLS, inventory, or generic
cited-observation fallback rendering. Normal code then composes a bounded **Backend log
findings** section into either the accepted model answer or deterministic fallback, preserving
exact Pod/container details, samples, extracted paths/endpoints, correlation status, and all
supporting evidence citations.

## Investigation Flow

1. An operator selects an alert or describes a symptom.
2. The API establishes scope, time range, and a bounded tool budget.
3. Deterministic tools collect only the required cluster evidence.
4. The diagnostics engine correlates observations and records provenance.
5. Sensitive values are removed before any external model call.
6. A supported server-owned plan can execute registered read-only follow-up checks.
7. The model reassesses the expanded evidence and proposes hypotheses or remaining checks.
8. Investigation chat may collect additional bounded alert-scoped evidence and
   answers with server-validated citations.
9. The UI presents the plan, activity, conclusions, provenance, and uncertainty.

## Source Of Truth Boundaries

- The cluster API is authoritative for Kubernetes and OpenShift resource state.
- Thanos Querier is the preferred source for platform metrics and alert rule state.
- Alertmanager is authoritative for active, silenced, and inhibited alert instances.
- Deterministic diagnostic code owns evidence schemas and calculations.
- The model supplies interpretation, never ground truth or implicit authorization.
- RBAC manifests define the maximum capabilities of the deployed identity.

## Initial Integrations

- Kubernetes/OpenShift API using the projected in-cluster service-account identity.
- Official Kubernetes Python dynamic client; no `oc` binary in the application image.
- Thanos Querier Prometheus-compatible API.
- Alertmanager v2 API.
- OpenAI Responses and strict-schema Chat Completions APIs through the provider
  router and official Python SDK. Public and internal compatible endpoints are
  stored in the model registry with one probed active profile.
- SQLite FTS5 on the SNO-lab `podpilot-data` PVC for single-replica investigations and memory.

## Open Questions

- Production-grade durable storage and backup path after the SNO-local PoC.
- Multi-cluster identity and tenancy design.
- Production separation between read and approval-gated action identities.
