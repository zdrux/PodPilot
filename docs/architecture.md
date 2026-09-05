# PodPilot Architecture

Last reviewed: 2026-08-30
Update when: ownership boundaries, data flow, integrations, or trust boundaries change.

## Overview

PodPilot converts OpenShift operational signals into evidence-backed troubleshooting
investigations. Deterministic clients gather cluster resources, events, logs,
PromQL results, alert rules, and active alerts. Diagnostic tools normalize and
correlate that evidence before an AI layer explains likely causes and next steps.

The product is investigative by default. Delegated Investigator and Action conversations use the
same agent loop and investigation tools; mutations cross a broker capability boundary. Investigator
requests are read-only, while Action requests are evaluated with the signed-in user's Kubernetes
RBAC and admission policy.

## Components

- **API/orchestrator**: accepts investigation requests, exposes bounded diagnostic candidates, validates agent-selected reads, enforces budgets and policy, and streams results.
- **Web UI**: Jinja2/HTMX views served by the API show alert context, streamed investigation progress, evidence provenance, uncertainty, and suggested operator actions.
- **OpenShift client**: reads the Kubernetes API plus Thanos, the OpenShift LokiStack
  gateway, and Alertmanager, validates TLS, and normalizes failures.
- **Diagnostics engine**: implements deterministic checks and correlation independent of any model provider.
- **Model adapter**: presents one internal contract over configured OpenAI-compatible endpoints, capability probes each profile, and turns normalized evidence into explanations while preserving citations and redaction rules.
- **Evaluation harness**: replays sanitized incidents and scores evidence use, diagnosis quality, safety, and abstention.

## Agent-control boundary

The agent owns discovery direction, selection of the next useful read, evidence sufficiency,
termination, conclusions, and operator-facing prose. Collectors, registered read compilers,
resource catalogs, relationship graphs, findings, and enrichment packs produce normalized evidence
or optional grounded candidates only. Their completion, failure, result shape, or legacy
presentation hint cannot stop, continue, cancel, replace, or redirect an investigation.

The orchestrator retains enforcement authority rather than investigative authority. It validates
schemas and exact targets, denies sensitive resources, applies the selected read-only or read-write
proxy capability, RBAC, redaction, and time/output bounds, and retains preview plus explicit
approval at the mutation boundary. An invalid target may be
returned to the agent for correction, but the server does not substitute a different read. A valid
agent decision to answer is accepted even when other candidates exist. A valid final answer is
stored after redaction and safe-Markdown normalization without style rewrites, deterministic prose
injection, or server-directed gap recovery. Citation conflicts change evidence status and visible
limitations; they do not erase the agent's text. Deterministic answer generation is reserved for a
model-provider or structured-contract failure after evidence has already been collected.

Metric cards and parsed dynamic-column Markdown tables are presentation views. They are additive
and never suppress the complete agent response. The unified agent does not receive generic
`list_resources` or `search_resources` tools and does not receive an unsolicited native inventory
table; it gathers Kubernetes objects with bounded brokered `oc` reads and authors the result shape.
Purpose-built legacy collectors may still use bounded projected object reads internally. Raw bounded
log tails remain available to the final agent instead of being replaced by a separate server-side
log interpretation. Safe-Markdown rendering recognizes attribute-free `<br>`, `<br/>`, and
`<br />` tags as line breaks in ordinary text and table cells. All other raw HTML remains escaped,
and break-like text inside inline or fenced code remains literal. Answer-table cells also receive a
bounded structured-output cleanup: unmatched braces are removed only at item boundaries, and a
leading `unknown` placeholder is discarded only when real cell content follows. Balanced object and
OpenShift template braces are preserved.

## Current Runtime

Delegated and shared-credential Investigator and Action conversations share the same agent tool
contract. The Chat Completions model can select typed `http_probe`, `query_audit_events`, and
`query_metrics` helpers in the same iterative loop as its brokered
shell escape hatch. The helpers reuse the typed readers' fixed query construction, limits,
normalization, redaction, provenance, and cluster attribution. Every helper result is appended as a
tool observation and control returns to the model; neither success nor a collector-level
`complete` field ends the investigation. This preserves exact field filtering, Loki audit
projection, and registered metric backends without making a collector the orchestrator.
The model ends this loop through a structured `finish_investigation` call with `complete`,
`blocked`, or `budget_exhausted`. A claimed completion is returned to the loop when it declares
remaining safe reads or delegates an available read-only check to the operator. PodPilot does not
de-duplicate model-selected shell commands or require model-authored retry metadata: the agent may
re-observe state as needed, and every attempt remains bounded by the action budget, command timeout,
outer run deadline, broker authorization, and audit trail. PodPilot does not prescribe a diagnostic sequence.
Collector transport failures retain a safe category such as `tls_verification_failed`, `timeout`,
or `transport_unavailable` so the model does not confuse failed trust verification with backend
absence.
Before the first delegated-agent decision, normal code performs the same reviewed, enabled,
unexpired, non-restricted lexical memory retrieval used by standalone Ask. It de-duplicates matches
across selected clusters and supplies at most four 1,200-character chunks with applicable-cluster
labels. The chunks are a separate untrusted data message: they cannot define tools, authorize an
operation, replace live evidence, or prove current cluster state.
The generic LIST and SEARCH helpers are absent from every unified-agent schema. Enumeration and
general object-field filtering use bounded `oc get` commands in both conversation modes. The agent
must project or filter large responses in the runner before returning them to model context.
Thanos remains the preferred trend source. Node rankings and namespace-scoped Pod CPU/memory
rankings fall back to a normalized current `metrics.k8s.io/v1beta1` snapshot when Thanos is
unavailable. The fallback is explicitly current-only; average and peak equal current and the
limitation is persisted. If every registered read and agent verification command fails, normal code
renders those exact collection failures and discards speculative model explanations of the outage.
High-confidence router Pod resource-metric requests bypass model classification and compile to CPU
and memory reads scoped to the `openshift-ingress` namespace and grouped by Pod. Router traffic,
request, and bandwidth questions remain separate HAProxy metric semantics.
Explicit retrieval requests may receive exact grounded candidates without losing semantic
classification or agent control. Causal and non-causal wording follows the same rule: presentation
metadata never decides whether investigation is complete. A Pod GET can therefore seed an
investigation without treating `status.phase: Pending` as its explanation. Strimzi Kafka existence
and inventory questions can expose a bounded `kafkas.kafka.strimzi.io` list candidate across
namespaces, but the agent still chooses whether to use it and what it means.
Both interrogative and imperative wording are recognized, including “are there Kafka clusters?”
and “show/list all deployed Kafka clusters.” The same registered read executes independently on
every selected OpenShift cluster. Found objects, complete zero-object results, and failed/API-missing
reads remain cluster-attributed, and coverage counts include failed clusters.
KafkaTopic inventory follow-ups bind a named Kafka CR from prior evidence to its observed
namespace and compile the `strimzi.io/cluster=<name>` selector through the live resource catalog;
topic telemetry, lag, throughput, and health questions remain outside this inventory shortcut.

The API then sends OpenAI-compatible Chat Completions requests with bounded typed read helpers and
one `execute_shell` function. The anomaly-first `pod_health_summary` helper is available with optional
namespace and label-selector scope, but it is not mandatory. Its output, shell observations, and other
tool results are returned as evidence to the agent. PodPilot does not replace a valid agent answer with
a server-authored Pod-health conclusion or impose a typed-scan completion requirement on that answer.
Each call identifies one cluster from the conversation's immutable selection. The API resolves that
cluster's token from the conversation owner's in-memory delegated session and brokers the API origin,
token, execution capability, and effective TLS mode over Pod loopback for that call only. Read-only
capabilities allow Kubernetes GET/HEAD/OPTIONS and SelfSubject reviews while blocking writes and
Secret reads; Action capabilities retain the user's full Kubernetes permissions. The
`oc-runner` creates a mode-0600 temporary kubeconfig, executes Bash with the
Linux `oc` binary, deletes the kubeconfig, and returns
exit code, stdout, and stderr as a Chat Completions `tool` message. The loop continues until the
model returns a final assistant message or the durable Ask run reaches its outer execution
deadline. Typed helpers are validated as `ReadIntent` values, but the model chooses whether and
when to invoke them, how to interpret their observations, and whether to continue through another
helper or shell. The shell path is not constrained to `ReadIntent`, typed remediation, preview, or
approval. The loop retains conversation ownership, provider credentials, redaction before model
reuse/persistence, progress, command metadata audit, and the run deadline.
Before first reinjection, a shell result is capped to a 48 KiB provider payload with separate bounded
stdout and stderr prefixes. The model receives that raw result once. After the next model response,
PodPilot removes the completed assistant tool-call and tool-result protocol pair and replaces it with
a deterministic rolling evidence ledger: a compact index of all completed operations plus bounded
detail for up to the full 50-operation window. If the 80 KiB ledger ceiling requires reduction,
successful read-only shell excerpts are discarded before typed observations, mutations, or failed
operations. Exact command execution remains available in the activity and audit records, while raw
logs and object YAML do not accumulate as hidden provider conversation state. Each retained
operation records its start, completion, and elapsed time. The operator view identifies any
operation whose retained request or output was credential-redacted, truncated, reduced to an
excerpt, stripped of Kubernetes `managedFields`, or replaced by oversized-JSON structural metadata.
The latest conversation messages are sent verbatim after redaction. Once older messages roll out of
that window, their existing bounded transcript digest is also supplied to the agent as continuity
data rather than silently omitted.
Every Chat Completions call estimates the complete messages-plus-tools token count using lexical BPE-
style fragments, JSON punctuation, and a protocol safety margin. This avoids treating each UTF-8 byte
as a token while remaining tokenizer-independent for OpenAI-compatible gateways that front different
models. Older tool/history messages are compacted when needed, and PodPilot refuses local transmission
if the estimate still exceeds the profile's `max_input_tokens` ceiling. The estimate is content-
agnostic: PodPilot does not infer an investigation's intent from question wording to require particular
shell fields or command shapes.
Lazy delegated typed-reader construction, including Kubernetes dynamic-client discovery through the
loopback broker, runs in a worker thread. It must not block the ASGI event loop that serves that same
broker or the health endpoints. Delegated metric and audit adapters resolve the current token from
the memory-only capability vault for each request, use the registered cluster TLS policy, and become
unavailable as soon as that capability is revoked or expires.
Agent tool schemas enumerate the conversation's selected cluster IDs and require one target per
call. Malformed arguments are rejected before cluster execution with bounded correction guidance.
Those model-formatting mistakes remain audited and appear only in collapsed tool-call diagnostics;
actual collector denials, unavailable sources, and non-zero commands remain visible limitations.
An empty label-filtered workload query is treated only as a zero-match selector result. Health or
absence conclusions for operator-managed stacks require the exact discovered custom resource status
and its owned or selected workloads; the agent may not substitute a guessed conventional label.
The standing agent instructions require initial Pod and container log reads to use an exact scope
when known and a bounded `oc logs --tail=200 --timestamps` sample, optionally constrained by time.
The agent may narrow or expand subsequent reads in bounded increments when that sample is
insufficient, rather than placing an arbitrary full log stream into every later model request.
Successful `oc get ... -o yaml` shell results are parsed before model reinjection and have
`metadata.managedFields` removed recursively from objects and list items. The executed command and
cluster response semantics remain unchanged; non-YAML output and YAML-producing non-GET commands
are left untouched.
If a Chat Completions turn returns neither content nor a tool call, or serializes tool arguments as
the final answer, the API issues up to two bounded finalization attempts using the command results
already in context. Successful commands are not automatically repeated. If both attempts remain
empty or tool-shaped, PodPilot renders deterministic collected evidence (or a safe unresolved
message when only shell reads exist) instead of exposing the malformed model output. When the
operator enabled raw-response capture for that turn, rejected non-empty final answers remain
available in the untrusted raw-response panel.
Otherwise, the agent's redacted prose and its chosen completion point are preserved. PodPilot does
not reject a conclusion for offering optional follow-up work, rewrite it based on semantic claims
about prior writes, remove recommendation sections, or replace a valid structured-workflow answer
with a server-authored audit, access-review, or configuration-comparison conclusion. Evidence status,
audited operations, limitations, and native evidence views remain separate metadata and presentation.
No retrieval enrichment is authoritative over the agent and no collector suppresses a model-proposed
read. Collection completeness is evidence about the bounded read, not answer completeness. Native
resource cards remain additive while the agent can explain selectors, rules, effects, and other
material object semantics. Collection classification carries an
optional grounded object-field predicate separately from requested output fields. Exact and
case-insensitive `contains` predicates compile to bounded `search_resources` reads across every
selected cluster. A plain resource list cannot satisfy a question containing a material field
predicate; if classification drops that constraint, the candidate is not treated as satisfying the
request. Search results distinguish complete absence from an empty result at
the scan ceiling, which remains explicitly inconclusive.
Opaque recent-object references retain their source cluster when uniquely attributable. A causal
follow-up about one result therefore investigates that cluster instead of repeating the same
namespace/name coordinate across every cluster selected on the conversation.
Registered top-consumer metric evidence also acts as a typed continuation anchor. An elliptical
follow-up that asks for the same CPU, memory, or namespace log-volume ranking over a different
period reuses the prior metric, scope, coordinates, grouping, and limit while changing only the
bounded time range.
Audit classification is similarly reconciled with unambiguous operator constraints before query
compilation. Explicit last/top counts, delete-versus-mutation scope, success/failure outcome, and
recognized resource kinds override broader model defaults; an omitted model `result_limit` cannot
turn “last 5 audit entries” into the configured default of 20.
Backward window expansion is reserved for an explicit requested count. A vague `recent` audit
request uses the configured initial window once and may return fewer than the default display
limit; a model-invented convenience count cannot widen that query toward the audit ceiling.
The registered Loki audit reader and Strimzi Kafka inventory are grounded capabilities, not terminal
routes. Their success, timeout, denial, or API-missing result is returned to the agent with exact
cluster attribution. Candidate validation prevents misspelled or invented resource types, while the
agent remains free to select another safe read or explain the limitation.
Namespace-scoped Kafka topic-disk-utilization requests are a registered two-stage read. PodPilot first lists
exact `Kafka` CR coordinates in the requested namespace, then issues one bounded
`kafka_topic_disk_utilization` query per observed CR and groups the result by topic. The query
compares replicated topic log bytes with aggregate capacity from that Kafka cluster's broker PVCs.
When the operator names one topic, the typed request keeps the owning `Kafka` CR as its target and
adds an exact `topic` selector, so that topic's byte and partition details do not depend on its rank.
An empty namespace,
partial metric failure, or denied monitoring read remains visible evidence. This resolves the Kafka
name from observed API evidence instead of requiring the model or operator to supply it, without
forcing the agent to stop.
Each shell process group also has an independent runner-side deadline. While it is active, the
runner polls the process silently. Before dispatch, the API deterministically reduces the selected
`oc`/`kubectl` command to a safe operation, resource, name, namespace, and cluster description. The
SSE timeline reports that description at start, during changing elapsed-time updates, and at
completion or failure without exposing command bodies, inline manifests, or model-authored
narration. Timeout returns exit code `124` and a redacted operator-visible
limitation instead of leaving the run indefinitely on `agent_command`.
Dedicated drain threads consume stdout and stderr as the process runs, retain a bounded prefix of
each stream, and discard overflow with an explicit truncation marker. This prevents `communicate()`
from buffering arbitrary command output up to the sidecar's memory limit while preserving true byte
counts and truncation flags in metadata-only runner logs.
Model calls use the same elapsed-time progress mechanism. Each profile configures a per-attempt
provider timeout and transient retry count (default three); the SDK retries timeouts, abrupt
connection failures, rate limits, and transient server responses while the durable Ask deadline
remains the outer bound.

In the current Ask architecture the sidecar has no projected service-account credential. FastAPI passes it only
a random, cluster-specific read-only or action loopback proxy capability; the proxy injects the user-owned in-memory
OAuth token for each Kubernetes request and applies the cluster entry's TLS choice and optional CA
trust. Conversation rows retain only `read_only` or `action`, the owning session ID, and immutable
cluster IDs—never the token. After the applicable preview and approval controls, Action conversations
can therefore issue CREATE, PATCH, APPLY, and DELETE requests when the remote user's RBAC permits
them, while Investigator conversations receive broker HTTP 403 responses for those operations
without receiving the bearer token itself.
The picker reads shared entries plus the current user's private entries. Credentials are submitted
for one environment at a time and passwords are discarded after OAuth exchange. For the system entry,
the API maps its `in-cluster://` marker to the internal Kubernetes API and OAuth services and uses
the projected API/service CA bundles; it does not fall back to the Pod service-account identity.
Owners can permanently delete private registry entries; this revokes matching live delegated
connections while historical conversations retain their immutable cluster references. Shared
entries remain disable-only so their lifecycle stays under configuration-administrator control.

Active workload and remote overlays enable delegated access and deploy a tokenless runner. The
Pod-level `podpilot-investigator` service account is not bound to `cluster-reader`; its custom
`podpilot-role-reader` ClusterRole permits only exact OpenShift Group GETs for application-role
resolution. Each runner command receives a conversation capability, and Kubernetes RBAC and
admission evaluate the signed-in user. Legacy feature-flag-off agent mode therefore requires an
explicit separately reviewed cluster-read identity and is not furnished by the active overlays.
No active deployment reads a remote cluster-token Secret; TLS policy is stored per cluster entry.

The current Pod contains the API, OAuth proxy, and tokenless runner. The OpenShift OAuth proxy is the
only network-facing container and forwards authenticated requests to FastAPI on
`127.0.0.1:8080`. FastAPI accepts the proxy-supplied username, resolves Investigator or Read-Write
from deployment-configured OpenShift groups, resolves configuration administration independently,
and denies unmatched users. The landing route redirects to Ask; Cluster Health is not active.
The API persists schema state in SQLite on the `podpilot-data` PVC. An init container
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
structured-output, and configured embedding checks is ready. The workflow-schema probe is an
informational compatibility smoke test: it verifies schema parsing without grading synthetic
investigation choices, and it does not degrade an otherwise ready profile. Runtime code still
validates every model-authored structure and retains deterministic fallback behavior. Streaming and
tool calling are recorded capabilities but are not required because the current agent
loop exchanges schema-validated read plans rather than provider-native tool calls.
Schema-validated interpretation is displayed separately from deterministic facts.
Provider failure preserves the deterministic investigation and records a bounded,
credential-free error.

The Ask-only cluster registry stores API origins, environment, ownership/visibility,
tags, lifecycle state, and per-cluster TLS policy in SQLite. Shared entries are managed
by configuration administrators; each user may also maintain private entries. The
registry never stores a remote-cluster credential. At conversation connect time the API
exchanges the user's environment credentials with every selected cluster and keeps only
the resulting tokens in the in-memory delegated-session vault.

Every standalone Ask conversation stores an immutable ordered selection of one to ten
cluster IDs. Changing selection starts another conversation and preserves the old session.
The worker fans a question out across the selected enabled clusters within one shared
25-unit weighted investigation ceiling, builds a separate Kubernetes client and discovery catalog for each,
and attributes every observation, read record, citation, limitation, and comparison to its
source cluster. A failed or disabled target becomes a cluster-specific limitation instead
of invalidating successful targets. This routing does not apply to Alertmanager, dashboard
health, alert investigations, or remediation in this release. Typed Ask metrics use each
remote cluster's delegated user token: PodPilot discovers the cluster's
`openshift-monitoring/thanos-querier` Route through its Kubernetes API, then queries that
authenticated Route through the same bounded metrics adapter used by the runtime cluster.
Aggregate application-log rankings similarly discover the conventional
`openshift-logging/logging-loki` Route and use the registered cluster bearer token.

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
PodPilot's bounded read-plan broker: up to ten planning rounds and 50 weighted
investigation units cover resource, ConfigMap, Event, Pod-log, metric, HTTP-probe, and
bounded-watch reads under the same read-only identity,
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
selects only a registered metric capability, typed target, exact coordinates or opaque trusted
prior-object reference, range, grouping, and limit. Registered targets include Kubernetes workload,
node, PVC, Strimzi Kafka, Route/IngressController, MachineConfigPool, HPA, ClusterOperator, API
server, and etcd scopes. Normal code compiles server-owned PromQL and calls `/api/v1/query_range`, accepts only
matrix results, caps series/points/body/time, redacts labels, and persists normalized points
plus minimum, maximum, average, current, trend, unit, and completeness. Requested resolution
is increased automatically when necessary to keep the series within its point ceiling.
Registered application-log-volume metrics are aggregate-only exceptions backed by the LokiStack
application tenant. Normal code owns their `bytes_over_time` LogQL and permits only reviewed
namespace, Pod, and Node label selectors/groupings. The broker supports cluster rankings by
namespace or Node, cluster-wide Pod rankings identified by namespace and Pod, Pod rankings within
one exact namespace, and totals for one exact namespace, Pod, or Node. It accepts only vector
results and persists normalized dimensions, payload bytes, average byte rate, time bounds, and
completeness. Neither the browser nor the model can submit LogQL or receive matching log lines.
Normal code parses common explicit relative periods before deterministic execution, while the
semantic classifier carries `metric_range_seconds` for other wording. Requested values remain
subject to the typed five-minute minimum and deployment maximum; absent metric periods use five
minutes.
Deployment templates join `kube_replicaset_owner` and `kube_pod_owner`, avoiding unreliable
Pod-name-prefix inference. Node templates join workload series with `kube_pod_info`; top CPU
and memory queries support cluster, namespace, Deployment, and node scopes. Top-consumer
queries aggregate application containers into namespace/Pod totals and honor the requested bounded
rank count. Common namespace top-consumer
questions compile deterministically so a planner schema failure cannot prevent the typed query.
These are container/workload observations, not host process telemetry.

Domain capability packs remain separate from Kubernetes API discovery: discovering a Kind does not
prove that its exporter is scraped. Each pack therefore owns its expected metric names, label
matchers, aggregation, units, and a prerequisite-aware empty-result limitation. Kafka broker topic
rates/storage require Strimzi JMX Exporter series, consumer lag requires Kafka Exporter series,
workload/HPA/storage/OpenShift-object state requires the corresponding kube-state-metrics or
openshift-state-metrics collectors, ingress requires router metrics, control-plane signals require
the platform API server/scheduler/etcd scrape jobs, monitoring health uses Prometheus and
Alertmanager self-metrics, and logging health uses LokiStack metrics scraped into Thanos. The model
cannot substitute metric names or raw PromQL when a cluster uses a different telemetry profile.
Unknown CRDs remain fully available to bounded discovery, exact object/status reads, configuration
inspection, and evidence-derived relationship traversal. They do not become metric targets merely
because the API server advertises their Kind; a reviewed capability pack must define series,
labels, units, aggregation, and prerequisites first.
Overall node CPU/memory utilization comes from bounded node-exporter templates joined to
`node_uname_info`. Resource-exhaustion planning should collect both overall utilization and
top workload consumers; any unexplained difference may be host, kernel, cache, or unmonitored
work and must remain a limitation rather than being assigned to a Pod.
Cluster-wide or role-scoped Node ranking requests use those same utilization templates grouped
by Node and wrapped in a bounded `topk`; they are distinct from container-backed top-consumer
rankings. Normal code recognizes an unambiguous `top/rank + CPU/memory + Nodes` request before
generic resource inventory routing and applies the standard five-minute default when no period
is supplied.

Milestone 10 adds standalone Ask PodPilot conversations and the reusable read
broker later shared by incident chat. Up to ten
schema-validated planning rounds may spend at most 50 weighted units on
`discover_resources`, `get_resource`, `list_resources`, `search_resources`,
`watch_resources`, `pod_logs`, `http_probe`, and `query_metrics`; each round receives the bounded
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
Before per-cluster collection, one compact model call interprets the operator's wording
across the selected cluster set and selects one registered evidence capability:
resource inventory, resource details, workload logs, Kubernetes Events, cluster metrics,
cluster audit events, endpoint probe, general investigation, named-object configuration guidance,
or conceptual explanation.
The same tool-free contract carries semantic arguments such as resource concept, exact
namespace/object coordinates, requested fields, time range, outcome, bounded result count, and an
answer goal (`identifiers`, `count`, `existence`, `configuration`, `behavior`, or `investigation`).
Normal code verifies that exact coordinates occur in the operator's question or recent context,
then compiles the selected capability into one registered query per selected cluster
and renders the evidence directly as a multi-cluster table. This lets the model handle
unfamiliar phrasing without maintaining a growing question-pattern list. For inventory mode,
normal code always resolves the model's resource concept against each cluster's live safe catalog and
runs the same bounded LIST. A request for object details may open a subsequent model-directed detail
phase, but it cannot suppress that base inventory collection. Successful inventory evidence is always
rendered by server code even if the optional detail phase or final model response fails. For other modes
the semantic contract pins the planner's goal but
does not select tools. Capability selection cannot authorize a read, invent an exact coordinate,
weaken RBAC, or bypass sensitivity policy. Invalid selections receive one focused repair attempt;
PodPilot does not use wording-specific recognizers to override a valid capability selection or
silently route it to a different evidence family. If capability selection is unavailable after its
repair attempt, the existing bounded deterministic inventory/known-read path remains as a reduced-
capability compatibility fallback; it cannot authorize broader reads and its absence is not treated
as evidence that the requested data does not exist.
For `configuration_guidance`, the model may resolve a resource type, object name, and namespace from
the current question or the four-message recent-context window. For elliptical follow-ups such as
“show that ConfigMap,” the classifier also receives bounded opaque IDs for non-sensitive exact objects
already present in the trusted evidence relationship graph. It selects an ID rather than reconstructing
coordinates; normal code binds that ID to the retained kind, namespace, and name, resolves the live safe
discovery catalog, and reads the named object through the same broker. An exact ConfigMap request is
terminal after that GET, while a parent custom-resource guidance read may remain open long enough to
select an explicitly referenced ConfigMap. The final model may combine observed configuration with
bounded curated knowledge and general Kubernetes/OpenShift knowledge, but must label proposed YAML as
unapplied guidance and cite evidence for every claim about current cluster state. This path is generic
across discoverable resource kinds and does not use keyword or sentence-pattern recognizers.
Related collection follow-ups use a separate opaque scope reference. The model preserves the requested
child resource type, selects the already-observed parent ID, and supplies only the Kubernetes label key
that expresses the relationship. Normal code binds the retained parent namespace and name as the label
value and compiles one bounded namespaced LIST. For example, topics belonging to a selected Strimzi
Kafka compile to `KafkaTopic` objects in the Kafka namespace with the model-selected relationship key
and server-bound Kafka name. Invalid, incomplete, or invented scope selections receive the existing
bounded semantic correction attempt rather than being executed.
The classifier also receives bounded opaque relationship IDs derived from the trusted evidence graph.
Each ID represents one direction of an observed edge and exposes only its anchor, target Kind, scope,
cardinality, and relationship. The model selects the semantic destination; normal code binds the retained
exact name or complete label selector. Forward and reverse selections support relationships such as
Machine to Node, Node back to Machine, ConfigMap back to its referencing custom resource, and
MachineConfigPool to its selected Nodes or MachineConfigs without letting the model author field paths,
selectors, API coordinates, or object names.
An exact custom-resource read also derives bounded relationships from structured ConfigMap reference
objects in its observed spec. Generic extraction also recognizes metadata owner references, typed
ObjectReference-shaped spec/status fields, and a bounded registry of selectors whose target Kind is
defined by a Kubernetes or OpenShift API contract. Each successful read rebuilds the frontier, allowing
another verified hop within the existing planning-round and investigation-unit ceilings. The model
normally receives the referenced target as an opaque exact action and chooses whether it is needed; a
`configuration_guidance` read remains open for that selection.
For an explicit show, display, or read-configuration request, normal code may follow up to three exact
same-namespace ConfigMap references observed in the source object's structured spec without another
model round unless the operator explicitly requested the source CR, object, manifest, spec, or status.
The broker, remaining investigation budget, and normal ConfigMap redaction still apply;
Secret references and inferred names are never traversed by this exception. Explicit
`configures_from` actions outrank generic catalog and list-result candidates during malformed-plan
recovery. An exact ConfigMap GET contributes a bounded, recursively redacted `data` projection to final
fact cards; LIST responses continue to expose metadata only.
For `cluster_audit_events`, normal code compiles the grounded namespace, username, operation,
outcome, period, and limit into a fixed Loki audit query. Loki applies those filters before its
backward result limit and compact line projection; PodPilot revalidates them while projecting
events and never sends model-authored LogQL. Reviewed query profiles cover a direct audit event,
JSON audit text in the OpenShift log record's `message` field, and a parsed event under `structured`;
projected results are deduplicated by audit ID.
The model owns troubleshooting direction, but selects rather than authors each ordinary read.
Normal code derives up to twelve opaque actions from exact operator coordinates, observed
relationship frontiers, unresolved evidence needs, implicated Pod-log targets, and bounded matches
from live API discovery. Every resource type uses the same small `ActionSelection` contract: the
model returns `investigate`, `answer`, or `uncertain`, a short reason, and up to four exact action IDs
when continuing. Exact valid action IDs are authoritative when a constrained model pairs them with
the wrong decision label. A non-empty selection continues; an empty `investigate` is retried and may
recover with the highest-priority action the server already supplied. The server compiles selected IDs back to typed intents it retained privately. The
catalog, deterministic findings, ownership, selectors, endpoints, and mount relationships remain
server-side inputs to action construction rather than a prescribed scenario path or model prompt.
When a model-authored exact GET omits a namespace, the broker reuses the sole namespace attached to
that object by bounded discovery; if the same name was observed in multiple namespaces, it rejects
the ambiguous GET and requires an exact grounded action. This scope repair is deterministic and does
not add planning instructions or object payloads to the model context.
Invalid or empty plans receive one structured repair attempt; the API does not silently
replace a diagnostic direction with a generic catalog traversal.
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
Automatic continuation is limited to mechanical safeguards such as the trust-only retry of the same
HTTPS probe and bounded recovery from a repeated model stop. Object traversal, log selection, Events,
metrics, and configuration reads otherwise require a model-selected direction and return through the
same broker on the next round. If a corrected action selection remains malformed after evidence has
already produced exact unread candidates, PodPilot may execute the highest-priority broker-owned
candidate and visibly record that recovery. A malformed initial plan with no collected evidence still
executes nothing.
List reads follow Kubernetes continue tokens within the per-turn budget and emit
one compact collection observation. Kind-aware projections retain operational
status, conditions, ownership, and selected scheduling/routing/storage fields.
Collected object names are retained separately from detailed projections.
`objectListComplete` reports whether the Kubernetes object ceiling was reached,
while `detailsTruncated` reports only status-detail compaction; the latter must
not be presented as proof that more objects exist.
The inventory object ceiling is deployment-configurable (500 by default, 1,000
maximum). Explicit list/inventory requests are rendered by normal server code from
the collected `names` array, so model prose cannot omit the requested resource list.
Every cited successful `list_resources` or `search_resources` observation also produces a
versioned `grouped_resource_list` presentation block in the message metadata. The block contains
bounded cluster groups, normalized Kind/namespace/name/Ready rows, search predicate values when
retained, scan coverage, and evidence IDs. The web UI renders it as native, auto-escaped,
collapsible tables with CSV export; it never parses provider Markdown or HTML to recover rows.
When a structured presentation fully replaces a server-generated inventory answer, Ask suppresses
only that legacy Markdown inventory table so operators see one canonical result with all retained
fields, while retaining adjacent prose that reports scope or partial collection failures. It does
not discard an answer-authored table that adds material interpretation or fields absent from the
observed-resource card, such as NetworkPolicy selectors and rule effects. Instead, Ask parses
CommonMark table tokens into bounded `answer_table` blocks with dynamic columns, renders them through
the native collapsible/CSV table component, and leaves surrounding prose in its original order.
These blocks are explicitly answer-derived: parsing does not promote interpreted cells to observed
cluster facts. The complete Markdown answer remains stored as a backward-compatible fallback for
clients that do not consume presentation metadata. When the semantic classifier says names are
explicitly sufficient, that deterministic table is the final answer: PodPilot skips the general
final-writer/correction pass and does not manufacture troubleshooting follow-ups for a
completed closed-form inventory request. A successful LIST remains a durable fallback if the
subsequent agent response fails, but it does not preempt interpretation for configuration, behavior,
investigation, requested-field, or uncertain goals. Multi-cluster totals distinguish clusters queried from
clusters with matches. A missing projected Ready condition is displayed as `Unknown`,
never as proof that the object is running or unhealthy. Inventory planning and malformed-plan
recovery preserve the classifier's requested resource Kind: generic scope words such as `cluster`
cannot make `ClusterRole` relevant to a Kafka-cluster request, model-authored LISTs for an
incompatible Kind are rejected, and the deterministic renderer omits any incompatible LIST
evidence that survives collection.
Model-authored cluster-wide LIST and search reads may use `namespace: "*"` as shorthand; normal
code converts that placeholder to the broker's canonical omitted namespace before validation.

`search_resources` is distinct from inventory. It follows continue tokens up to a
separate scan ceiling (2,000 by default, 5,000 maximum), compares a model-selected,
validated dot-separated object field path, and returns only bounded compact matches.
Paths may traverse nested objects and lists, allowing searches such as `spec.type` and
`status.conditions.type`; malformed path expressions are rejected. For a Route URL, the model
can select an exact `spec.host` search and use the resulting namespace/name in later rounds.
The planner guidance prefers the qualified `routes.route.openshift.io` resource. More
generally, discovery resolves an unqualified plural with supplied `apiVersion` and `Kind`
only when both agree with one advertised resource; mismatches fail closed. Preflight performs
this resolution before the read budget advances. Same-plural APIs such as OpenShift and
Knative Routes are not treated as interchangeable fallbacks after ambiguity or RBAC denial.

Resource-collection conversations retain typed continuation state from the latest validated
`list_resources` or `search_resources` observations: Kind, API/resource coordinates, namespace,
label selector, exact field predicate, limit, source clusters, evidence IDs, and collection time.
Elliptical presentation follow-ups such as “show these routes” reuse only that cited snapshot and
create provenance-bearing synthetic activity; they do not depend on reconstructing the query from
truncated chat prose or call the model. A unique normalized mention of one already-selected cluster
(including an environment-suffix-shortened name such as `CMSP Central` for `CMSP Central DEV`)
narrows only that turn. Ambiguous aliases do not narrow. Freshness terms such as `current`, `still`,
`now`, or `refresh` inherit the typed query but execute a new bounded read. Prior snapshots are
never silently represented as current state.
Projected Route evidence treats `spec.to.name` and `spec.alternateBackends[].name` as
observed Service references, so exact follow-up Service reads are not rejected as model
inventions. Route protocol questions also have a deterministic cited interpretation: `edge`
forwards HTTP after router TLS termination, `reencrypt` establishes new backend TLS, and
`passthrough` leaves TLS termination to the backend. This states configuration, not live
backend reachability or the origin of an HTTP 500.

For Route, HTTP 5xx, and connectivity investigations, projected evidence exposes Route targets,
Service selectors, EndpointSlice/Endpoints target references, Pod log candidates, and owner
references. The model decides which relationships matter to its current hypothesis and proposes
each traversal explicitly. Normal code grounds names from those exact references, but never
interprets arbitrary cluster strings as callable targets.

The planner can also query the live discovery catalog during a turn. This is not a curated
resource allowlist: any discovered resource advertising `get`, `list`, or `watch` may be
selected, subject to the explicit sensitive-resource/subresource denylist and the selected
ServiceAccount's RBAC. A bounded watch costs three investigation units, lasts at most 15
seconds, and retains at most 50 compact events. Pod logs, HTTP probes, and metric queries cost
two units; discovery and ordinary resource reads cost one. The default follow-up reserve is zero,
so all 25 units are available to the model-directed loop; deployments may reserve units for the
mechanical TLS trust retry if required.

If the first plan and its structured repair both stop before collecting any evidence, or the first
plan is a valid premature stop and the requested correction is not schema-valid, normal code
may use one non-terminal read compiled from a single exact coordinate in the operator request as a
recovery anchor. A Route URL, for example, can seed one exact `spec.host` search. This does not
activate a generic catalog fallback or a deterministic troubleshooting graph: the resulting
observation is returned to the planner, which selects every later diagnostic hop.

After at least one successful read, a planner-contract failure no longer has to discard the discovered
frontier. Chat Completions retains independently valid action IDs and object reads after its single
schema-repair attempt. If no valid selection survives but exact unread candidates were derived from
trusted observations, PodPilot performs one highest-priority candidate through the normal broker and
returns that evidence to the next model round. Rejected model fields never supply coordinates, and the
recovery is disclosed in limitations and audit logs. For inventory goals, this recovery frontier is
restricted to candidates compatible with the requested resource Kind; it never substitutes a merely
lexically adjacent API type.

For diagnostic, log, and explanation goals, the first evidence-supported request to stop is
subject to one model sufficiency review. The review receives the same observations, findings,
explicit relationships, available typed tools, and remaining budget. It asks the model to collect
one material read now when that read would otherwise appear as an unperformed final recommendation;
otherwise the model may confirm its stop with exact supporting IDs. Recommendation prose is never
executed, and normal broker validation remains unchanged.

The server derives relationships, capability state, findings, and executable intents internally, but
candidate-mode model calls do not receive those implementation structures. Every model-directed
resource investigation receives only the question, up to six normalized fact cards within a 5 KB
aggregate target, up to twelve opaque action ID/label pairs, and up to twelve compact readable API
catalog entries. The universal `ActionSelection` contract permits zero to four exact action IDs plus
up to three small object reads using only discovery, GET, LIST, or bounded field search. This lets the
model pursue a relevant ConfigMap, workload, or configuration CRD without receiving the full tool
union. Normal code still resolves API coordinates and enforces sensitivity, namespace, verb, RBAC,
duplicate, and budget policy before every read.
An exact operator-supplied HTTP/HTTPS URL becomes a grounded GET-probe candidate after Route
evidence exists, or when a structured probe gap remains. A structured Pod-log gap or an explicit
failure question may similarly offer exact normal-priority Running/Ready container candidates;
unhealthy/restarting candidates retain higher priority. If the model twice stops while such an
exact log action remains relevant to a failure question, PodPilot may select one through the normal
broker and disclose the recovery. Pod logs still never accept model-authored coordinates.

Each planning round is supported by two server-derived views of current state. A bounded evidence
relationship graph exposes typed nodes and edges such as Route-to-Service, Service selector-to-Pod,
Service-to-EndpointSlice, endpoint-to-Pod, owner, and volume-source relationships. Its frontier
produces safe action cards for observed-but-unread neighbors. A capability ledger separately
records whether Service specs, endpoints, Pod specs, Pod logs, metrics, and probes are collected,
attempted unsuccessfully, budget-exhausted, awaiting an exact target, or available but not attempted.
These structures remain authoritative server state for validation and follow-through; the model sees
their concise evidence and action projections rather than their schemas or internal vocabulary.

The first accepted goal type is pinned for the collection pass. Later plans may revise hypotheses
and choose different evidence, but cannot silently change the operator's diagnostic goal. Normalized
intent signatures are retained across rounds and the answer-gap pass; a duplicate-only plan receives
bounded `no_progress` feedback so the model can select a novel candidate or explicitly stop. When a
model twice stops despite a medium/high structured gap with a matching grounded candidate, PodPilot
selects the highest-priority candidate deterministically and discloses that recovery in limitations.
Exact model-authored GET/watch requests for previously discovered objects are rewritten to the
resource, served API version, kind, namespace, and name emitted by trusted discovery evidence before
their intent signature is calculated. This prevents alternate model spellings from bypassing
duplicate detection or producing a second evidence row for the same Kubernetes object. Deterministic
object summaries also deduplicate exact identities as a final presentation safeguard.

The action-selection prompt asks the model to select useful supplied reads or author a bounded object
discovery/read when the supplied actions omit a material path. Query-relevant catalog actions remain
available even when a generic relationship candidate exists. LIST/search results become exact GET
candidates on the following round. The final writer is not asked to produce next steps. After the final answer, normal
code independently derives up to three **Run check** controls from unread server-owned candidates.
The browser posts the source message and opaque candidate ID; it cannot
provide coordinates or an intent. The resulting `AdHocRun` stores the validated descriptor, starts with
no conversation messages or summary in model context, executes that exact candidate through the normal
broker, and appends the evidence extension to the same conversation.

For cross-namespace connectivity, the planner can select both Pods, Namespace label sets, and
NetworkPolicies when those reads discriminate a policy hypothesis. Compact policy evidence
retains `podSelector`, `policyTypes`, ingress and egress peers, and ports. Configuration evidence
may identify a plausible factor but cannot prove packet drops because PodPilot does not exec a
source-originated probe inside the workload.

Pod LIST and named Pod observations also retain a separately bounded registry of
exact Pod and container log candidates. Each candidate receives an opaque
server-derived ID. A model may call `pods/log` only by selecting one of those IDs;
normal code binds it back to the observed namespace, Pod, and container. Literal
placeholders fail the evidence contract before planning completes. A model-authored named GET is
resolved through live API discovery and must pass namespace, sensitivity, verb, and RBAC checks.
When the exact name is not known, the planner must use bounded discovery/LIST/search first; only the
server-normalized result becomes an exact GET candidate on the next round. Explicit
`metadata.ownerReferences`, Route backends, EndpointSlice/Endpoints target references, Pod candidates, and
volume-backed object references are grounded targets in the containing object's namespace;
otherwise the planner must discover them with a bounded LIST first. Fabricated or ambiguous
targets consume no cluster-read budget and receive one structured repair attempt. Pod logs
still require the model to select an opaque observed candidate ID; normal code never invents
a replacement diagnostic path.

Ad-hoc conversations are private to the creating OpenShift identity. The creator
can start, continue, and permanently delete the conversation and its messages and
evidence. Deleting a conversation atomically removes queued work and cancels any
in-process running task before it can persist a late response; deletion leaves a
content-free audit event with only the cancelled-run count. There is no per-conversation
question limit. The model receives the ten most recent messages plus a bounded,
durable digest of older messages. UI rendering is capped independently, evidence
retains its existing bounded window, and a per-user one-minute request limit
controls cost and accidental rapid submission without ending a conversation.

Ask turns are persisted as `AdHocRun` jobs before execution. The single-replica
SQLite deployment runs a bounded in-process worker pool (three workers by default),
permits one queued or running turn per conversation, limits each user to two concurrent
runs by default, and atomically stores the assistant reply with the terminal job state.
SQLite uses WAL mode, normal synchronization, and a 30-second busy timeout so short progress
and completion transactions from concurrent runs can coexist. A restart changes interrupted
`running` jobs back to `queued`, so the workers
can recover them from the PVC. The browser receives an immediate redirect, renders
the submitted question optimistically, and follows owner-authorized Server-Sent
Events for durable `discovering`, `planning`, `hypothesis`, `next_check`,
`collecting`, `agent_thinking`, `agent_command`, `finding`, `answering`,
and terminal updates. Reloading reconstructs the same state from SQLite, and an
SSE heartbeat keeps the OpenShift Route connection active. These events describe
short operator-visible hypotheses and server-observed workflow actions; PodPilot does not
expose hidden model chain-of-thought. Queued state remains visible in the live header, while
one-time queued and starting events are omitted from the phase journal. Agent command retains five
recent updates and other visible phases retain three. The rolling journal exists only while a run is active.
Each run also persists a separate bounded, redacted operation ledger. An operation is upserted when
its tool call starts and again when that call completes or fails; SSE publishes ledger snapshots
independently of the final response so the activity sidebar can expose completed call details while
the agent is still choosing later actions. The final assistant message retains the same completed
ledger as the durable conversation-history representation.
The final schema-validated answer remains a complete response rather than token
streaming.
For an individual Ask question, the operator may opt in to retaining the raw final-answer
provider bodies. PodPilot stores only bounded, redacted answer attempts (including its one
correction attempt), never prompts, chain-of-thought, credentials, or unredacted cluster
payloads. The raw output is visibly labeled untrusted and does not bypass answer validation,
citation enforcement, deterministic fallback, or action policy. Capture defaults off and is
recorded on the durable run so asynchronous processing preserves the sender's choice.
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
unstructured prose. If a chat-completions model leaves the structured citation
array empty but includes an exact supplied observation ID in its answer text,
normal code recovers only that allowlisted ID as a citation and removes the
provider-facing marker from displayed prose. Ask PodPilot initializes its bounded chat viewport at the
newest message after navigation while retaining normal manual scrolling afterward.
Private Ask sessions are rendered as a nested list beneath the primary Ask
PodPilot navigation item and expose owner-authorized deletion controls. Collected evidence and
agent activity occupy a collapsible persistent investigation sidebar. Each running or completed
operation can open a focused detail sheet; credential filtering and other
retained-output reductions are disclosed on the affected timeline row. The header count and answer
citations continue to open the modal provenance drawer focused on the matching evidence card. Reply
citations are collapsed by default beneath a
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

The read broker can expose evidence-derived candidates without selecting them. A verified
HTTPS probe that fails only at certificate trust may expose the identical target with
`tls_verify=false`; Pod evidence may expose exact current-log candidates for unready, restarting,
or non-running containers. The agent alone decides whether to select either read. Logs from any
container can be classified into
typed operational signals (crash/exception, resource pressure, TLS, DNS, network,
authorization, storage, dependency, application error, or warning). Each structured
finding records exact Pod/container provenance, repetition and normalized signature
counts, observed timestamps, bounded samples, paths, and endpoints. Material signals
produce optional exact Pod, Event, and previous-stream candidates. Candidates are capped and
deduplicated, cannot read Secrets or expand RBAC, and consume budget only after agent selection.
Findings are evidence summaries, not executable instructions, and neither pattern
matches nor log correlation alone establish causality.

The final-answer boundary is separately compacted from durable evidence. Current-turn observations
are converted to at most eight resource-agnostic fact cards within a 7.5 KB aggregate target. Each card contains an
allowlisted evidence ID, cluster attribution, summary, concise material facts, and a bounded object
projection or 500-character log sample. The final model receives only the question, cluster ID/name
pairs, those fact cards, up to three collection issues, and an optional 500-character prior answer or
short retry code.
Its system prompt covers evidence-only claims, exact citations, multi-cluster attribution, uncertainty,
no claimed mutation, and optional simple Markdown. For inventory/existence questions it also asks for
counts and identifiable matches rather than a bare yes/no conclusion. The concise schema contains
`answer_mode`, `answer`, and `citations`; recommendation generation and formatting are not part of this
call. `general_guidance` can be uncited, while any observed-state claim remains evidence-gated. Single-line bold labels,
Unicode bullets, and recognized section headings
flattened later in a line are normalized into headings and lists before rendering. Graph,
capability-ledger, findings, and raw observation payloads stay server-side. A small bounded
curated-knowledge projection is included only for explanation and configuration guidance. The database and
evidence drawer retain the complete redacted bounded observations. A schema-valid
answer must also pass semantic substance checks: citations plus headings alone are not
enough, and every current Pod-log observation with a structured finding must be cited. A bounded
correction attempt receives only an error code and instruction. The same check rejects schema
fields or fenced `investigation_gaps` serialized inside the answer
string. Provider attempts to append a recommendation heading or `recommended_actions` serialization
are removed before Markdown rendering because suggested controls are composed independently.
Final validation preserves agent-authored gaps and prose while recording citation/evidence conflicts
as limitations and lowering evidence status when required. Provider-facing citation markers are
stripped after allowlisted citations are recovered. Once an HTTPS probe completes TLS and
returns an HTTP status, grounded workload logs and Pod configuration rank ahead of additional topology
reads because they can distinguish application, authentication, and upstream failures.
Provider or structured-contract failure may activate a deterministic cited-observation fallback.
Independently, cited list evidence can render an additive native table of OpenShift cluster, kind,
namespace, object name, and Ready condition. This preserves the complete model interpretation while
making verified object identities visible. A readable catalog with no matching resource type remains
distinct from an installed/readable API returning zero objects. A truncated LIST or incomplete field
search cannot support a conclusive absence claim. Normalized log findings remain evidence and optional
candidates; normal code does not append them to or replace a valid agent answer.
Route/TLS fallback also composes relevant current-turn Service, endpoint, Pod, and probe observations.
A completed TLS probe with an HTTP response proves the tested path has a TLS-capable termination point,
but does not by itself identify that component, exclude later plain-HTTP forwarding, or explain the
returned application status.

## Investigation Flow

1. An operator selects an alert or describes a symptom.
2. The API establishes scope, time range, and a bounded tool budget.
3. The agent selects bounded read-only tools; normal code validates targets and policy.
4. Collectors record normalized observations and provenance without selecting the next step.
5. Sensitive values are removed before any external model call; bounded raw log evidence remains
   available to the same agent for interpretation.
6. The agent reassesses the expanded evidence, revises its direction, and decides when to answer.
7. The UI presents the complete answer, additive evidence views, activity, provenance, and uncertainty.

Natural-language Pod log requests with both an explicit namespace and a Pod-name hint receive a
generic deterministic discovery anchor. PodPilot performs a bounded `metadata.name contains` Pod
search in that namespace; only exact Pod/container candidates returned by cluster evidence can then
authorize `pod_logs`. Bounded Pod searches and lists use the same candidate extraction path, so the
model never supplies or invents log coordinates.

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
