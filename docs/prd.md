# PodPilot Product Requirements Document

Status: Draft v0.9; Milestone 10 standalone read-only investigation implemented
Last reviewed: 2026-08-23
Update when: scope, personas, workflows, acceptance criteria, or product safety boundaries change.

## 1. Product Definition

PodPilot is an OpenShift-first AI operations companion for junior administrators
and SRE teams. It turns alerts and operator-reported symptoms into bounded,
evidence-backed investigations, recommends a course of action, and can execute a
small set of explicitly approved remediations while verifying the outcome.

PodPilot is not a replacement for Prometheus, Alertmanager, Grafana, Kiali, or the
OpenShift console. Those systems remain sources of truth. PodPilot is the
investigation and action layer that correlates their signals into an operational
workflow.

### Product promise

> From firing alert to an evidence-backed diagnosis and approved next action in
> minutes, without requiring the operator to know every OpenShift subsystem.

### Positioning correction

Do not market the first releases as a “production-level SRE.” That implies broad
correctness, autonomy, and reliability that an early AI system cannot prove.
Position it as an **OpenShift investigation and Day-2 operations copilot**, then
earn broader SRE claims through evaluations and operating history.

## 2. Target Users

### Primary persona: junior OpenShift administrator

- Knows basic `oc`, Kubernetes objects, and the OpenShift console.
- Can recognize that a workload or operator is unhealthy but needs help finding the cause.
- Wants explanations, evidence, safe commands, and guidance on what to inspect next.

### Secondary persona: senior SRE or platform engineer

- Wants faster triage, consistent runbooks, an auditable investigation record,
  and a way to encode cluster-specific operational knowledge.
- Reviews and approves remediation plans.

### Not an initial persona

- Application end users without cluster-operational responsibility.
- Organizations needing multi-cluster fleet management or production-grade tenancy.

## 3. Product Principles

1. **Investigation-first, chat-assisted.** The primary object is an investigation,
   not a conversation transcript.
2. **Evidence before explanation.** Every diagnosis cites current observations,
   timestamps, queries, and resource identities.
3. **Facts, hypotheses, and actions are distinct.** The UI must never blur them.
4. **Approval is specific and fresh.** Approval applies to one rendered action
   against one observed resource version, not to an open-ended agent session.
5. **Verify every action.** “API request succeeded” is not the same as “problem fixed.”
6. **Memory is curated knowledge, not automatic truth.** Every memory has source,
   scope, owner, freshness, and confidence.
7. **Deterministic tools remain useful without the model.** Collection, checks,
   diffs, and verification are normal code.

## 4. Holes In The Original Concept

### 4.1 The feature surface is too broad

Crashing Pods, networking, Routes, ClusterOperators, storage, and two generations
of OpenShift Service Mesh represent several products' worth of diagnostic logic.
Trying to cover them all initially will produce shallow, unreliable advice.

Recommendation: establish a capability ladder and require an evaluation pack for
each domain before calling it supported.

### 4.2 Chat is a poor primary operating surface

A blank chat requires the junior user to know what to ask and makes evidence,
approval, and audit state hard to follow.

Recommendation: make the home screen a prioritized work queue. Each alert opens a
structured investigation with an embedded chat scoped to that investigation.

### 4.3 “One-click fix” is underspecified

An unconstrained model-generated command or YAML patch is equivalent to remote
cluster-admin shell access. A button alone is not a meaningful approval boundary.

Recommendation: model output selects from typed action schemas. The server renders
the exact target and change, checks preconditions, performs server-side dry-run
where possible, asks for approval, executes, verifies, and offers rollback.

### 4.4 RAG can institutionalize bad tribal knowledge

Old incident notes and confident but incorrect chat answers can become more
dangerous when retrieved automatically.

Recommendation: separate curated runbooks, explicit cluster facts, and historical
incident summaries. Require provenance, scope, expiry/review dates, and owner.
Never promote raw chat or model output into durable memory automatically.

### 4.5 “OpenAI-compatible” does not imply capability compatibility

Providers vary in tool calling, JSON schema support, streaming, context length,
embeddings, TLS, and error behavior even when they expose similar endpoints.

Recommendation: save model profiles only after a capability probe. Record separate
chat and embedding models, supported features, timeout, TLS CA, and maximum context.

### 4.6 Service Mesh needs version-aware adapters

OpenShift Service Mesh 2 uses `ServiceMeshControlPlane`; Service Mesh 3 uses the
`Istio` and `IstioCNI` resources, while traffic APIs such as `VirtualService`
remain relevant. Red Hat publishes an explicit migration mapping between these
generations. PodPilot must detect the installed generation and run versioned checks,
not assume one resource model. See the [Red Hat Service Mesh 2 to 3 migration guide](https://docs.redhat.com/en/documentation/red_hat_openshift_service_mesh/3.1/html-single/migrating_from_service_mesh_2_to_service_mesh_3/index).

Recommendation: defer Service Mesh diagnosis until after core workloads, Routes,
and ClusterOperators are reliable.

### 4.7 Logs and cluster objects are an adversarial input channel

Workload logs, annotations, alert text, and ConfigMaps can contain secrets or
instructions intended to manipulate the model.

Recommendation: enforce collection limits, structured extraction, redaction, and
explicit “untrusted evidence” framing before model calls. Never expose raw Secret
values to the model by default, even though the PoC identity can read them.

## 5. MVP Scope

### 5.1 Settings and model connection

An administrator can configure multiple OpenAI-compatible model profiles and
activate one successfully tested profile:

- provider label and API base URL, defaulting to OpenAI at `https://api.openai.com/v1`
- API token stored under a per-profile key in one server-side OpenShift Secret
- Responses or Chat Completions API mode, selected explicitly and checked by a
  connection probe
- reasoning/chat model name, initially `gpt-5.6-terra`
- optional embedding model, initially `text-embedding-3-small`
- system TLS trust, an optional custom CA bundle, or an explicitly warned insecure
  PoC mode
- explicitly selected plain HTTP only for direct Kubernetes Service DNS endpoints;
  external plaintext endpoints remain prohibited
- request timeout and maximum investigation token budget

The UI must never read the saved token back. A connection test must report:

- endpoint reachability and TLS result
- authentication result
- model availability
- streaming support
- tool-call support
- structured-output/JSON-schema support
- embedding support, when configured

The provider adapters use the official OpenAI Python SDK. Responses calls use
`store=false`; Chat Completions calls require strict JSON-schema output.
Investigation and diagnostic code depend on PodPilot's own
provider-neutral interface, not SDK response objects. A later internal endpoint
An internal endpoint can supply its own base URL, token, model names, CA, and
supported features without changing the agent workflow; profiles that lack required capabilities must fail
closed or run in a clearly labeled reduced-capability mode.

The local Windows user environment contains a validated `OPENAI_API_KEY` with
access to `gpt-5.6-sol`, `gpt-5.6-terra`, `gpt-5.6-luna`, and
`text-embedding-3-small`. The value must be transferred directly into an
OpenShift Secret during deployment and must never be written to this repository.

### 5.2 Cluster health work queue

The landing page shows operational summaries, not time-series dashboards:

- OpenShift version and upgrade/progress condition
- unavailable, degraded, or progressing ClusterOperators
- count of active firing, silenced, and inhibited alerts
- unhealthy workload count grouped by namespace and reason
- investigations awaiting approval or verification
- recently resolved and failed investigations

The screen links to Prometheus, Alertmanager, the OpenShift console, and later
Kiali for deep source-system views instead of rebuilding those products.

### 5.3 Alert ingestion

- Read current alerts from the OpenShift Alertmanager v2 API.
- Preserve active, silenced, inhibited, severity, namespace, alert source, and timestamps.
- Treat `Watchdog` as expected and visually separate it from actionable alerts.
- Refresh on demand and on a conservative polling interval; do not build a second alert store.
- Deduplicate using the Alertmanager fingerprint plus active interval.

### 5.4 Alert investigation

Clicking **Analyze** creates an investigation rather than a one-off response.

The first diagnostic capability pack gathers:

- alert definition, labels, annotations, status, and recent rule state
- relevant PromQL query results from Thanos
- matching Kubernetes/OpenShift resources and conditions
- namespace events within a bounded time window
- current and previous logs from a bounded number of relevant containers
- owner references and recent Deployment/StatefulSet/DaemonSet rollout state
- related ClusterOperator conditions when applicable

The result contains:

- concise incident summary
- timeline
- confirmed observations with citations
- ranked hypotheses with confidence and disconfirming evidence
- missing evidence and collection failures
- recommended next checks
- zero or more typed remediation proposals

### 5.5 Chat within an investigation

- Chat inherits the investigation's evidence and scope.
- Users can ask follow-up questions or request additional supported checks.
- Every new factual answer must cite evidence or clearly identify itself as general guidance.
- The user can explicitly widen namespace, resource, or time scope.
- Chat cannot directly execute arbitrary shell text or YAML.

### 5.6 Approved remediation

The first MVP supports only two typed actions:

1. Delete one controller-owned failed Pod so its controller recreates it.
2. Trigger a rollout restart for one Deployment, StatefulSet, or DaemonSet.

Each proposal must show:

- exact cluster, namespace, kind, and name
- why the action may help and why it may not
- blast radius and expected interruption
- current resource UID and resourceVersion precondition
- generated patch or API operation
- server-side dry-run result where supported
- verification query and timeout
- rollback or recovery note

Execution requires an authenticated member of `podpilot-approvers` to press
**Approve and run** after the preview is generated. Approval expires if the
resource version changes or after a short timeout. The system records the
OpenShift username and groups, proposal, before/after state, API result,
verification outcome, and all tool activity.

Arbitrary patches, shell commands, node operations, Secret changes, RBAC changes,
and Service Mesh mutation are out of MVP scope even though the lab identity has
cluster-admin.

PodPilot may recommend a broader remediation when current cluster evidence and
logs support it, but recommendations outside the registered action catalog are
display-only. The UI must identify which observations support the recommendation,
what remains uncertain, and provide operator-run verification steps. A suggestion
does not become executable merely because the model produced it.

### 5.7 Investigation lifecycle

```text
new -> collecting -> analyzing -> recommendation_ready
    -> awaiting_approval -> executing -> verifying
    -> resolved | unresolved | failed | rolled_back | cancelled
```

Every transition is durable and visible. Retrying creates a new attempt under the
same investigation rather than rewriting history.

### 5.8 Remediation preview lifecycle

Fresh previews are not durable authorization. An investigation creator or an
Approver can cancel a preview without gaining execution permission. PodPilot
automatically expires overdue previews, cancels them after a complete
Alertmanager snapshot proves the source alert is no longer active, and cancels a
preview when a read-only recheck finds the exact target missing or stale. An
incomplete or unavailable alert snapshot cannot authorize execution and cannot
be used to infer that an alert resolved. Every closure records actor, time,
reason, detail, and an audit event.

### 5.9 Bounded diagnostic plan lifecycle

Supported alert packs can persist a server-owned sequence of registered read-only
checks. An Investigator starts the queued plan with one explicit control; the
browser sends only the investigation ID. It cannot submit tool names, Kubernetes
targets, commands, or query text. Each check is atomically claimed once, bounded
by configured check, Pod, event, and response limits, and records its actor,
tool, outcome, observations, provenance, and collection limitations.

Milestone 7 first supports `TargetDown` when the normalized alert identifies a
namespace and Service. PodPilot resolves the Service selector, EndpointSlices,
bounded matching Pod health, and bounded recent Pod events. Results become
confirmed observations and are supplied to the configured model for a fresh
schema-validated interpretation. Provider failure leaves the deterministic
results usable. Active network probing, arbitrary PromQL, generic Kubernetes
reads, shell, generated tools, and diagnostic mutation remain out of scope.

Milestone 9 adds a third registered `TargetDown` check. Normal code constructs
exact-label instant queries for current `ALERTS` rule state and `up` scrape health,
then calls the authenticated in-cluster Thanos Querier with TLS validation, an
eight-second timeout, a 64 KiB response ceiling, and a 20-series retention limit.
Neither the browser nor model supplies PromQL. Query results are normalized and
redacted before becoming evidence. A direct DNS/TCP/TLS/HTTP probe remains out of
scope: allowing alert labels to select a network destination would create an
SSRF-shaped capability until an administrator-owned destination registry and
egress boundary exist.

### 5.10 Investigation-scoped chat

An Investigator can ask follow-up questions inside one durable investigation.
PodPilot supplies only that investigation's redacted alert, deterministic analysis,
persisted evidence, bounded conversation history, alert-scoped read policy, and
available registered intent names to the configured model. Up to three planning
rounds may request at most six reads through the same deny-by-default broker as
standalone Ask; successful observations are persisted into the investigation
before the answer pass. Factual incident answers must cite observation IDs
that the server can resolve in the investigation; an evidence-based response with
no valid citation is withheld. General guidance and insufficient-evidence answers
are labeled explicitly.

The only executable UI proposal is `run_queued_checks`, and it is exposed only while
the investigation has queued registered checks. A proposal is display data, not an
execution request: the Investigator must press the existing safe-check control,
which re-enters the role, CSRF, claim-once, scope, and audit gates. Read-plan
output is advisory data validated and executed by the API; chat cannot directly
submit Kubernetes calls, query text, shell, YAML, credentials, or cluster
mutations. Messages are attributed, redacted before persistence/model use, capped
at 1,000 characters each and 20 messages per investigation, and audited without
copying message content into the audit record.

### 5.11 Standalone Ask PodPilot

An Investigator can start a durable, attributed conversation without a firing
alert. For each turn, up to three schema-validated planning rounds select at most six total reads
from named resource GET, bounded resource LIST, and bounded current or previous
Pod logs. A policy-filtered, five-minute discovery catalog lets planning address
common Kubernetes/OpenShift objects and installed CRDs by plural resource name.
The server resolves apiVersion, Kind, namespaced scope, and advertised read verb;
it rejects ambiguous cross-group names unless qualified. Each round
receives prior observations, allowing Pod discovery to lead to exact container-log
collection without requiring an operator follow-up. ConfigMaps
and logs are first-class evidence; Secrets, access-review resources, arbitrary
subresources, commands, active network probes, and mutations are rejected.
The model infers inventory, health, diagnosis, log, comparison, and explanation
goals from natural language and returns an explicit collect, evidence-answer, or
clarification decision. The API rejects unsupported operational answers, retries
the planner once with bounded feedback, and may compile a matching safe LIST from
live discovery after a second refusal. No wording-specific object allowlist is
required, and neither inference nor fallback can exceed broker policy or RBAC.

When a Pod inventory is needed before logs, PodPilot must derive exact log-target
candidates from the returned objects and let the planner select opaque IDs rather
than synthesize resource names. Invalid selections must be repaired without using
the cluster-read budget. After repeated invalid selection, PodPilot may fan out to
at most three relevant observed candidates and must disclose that deterministic
fallback. RBAC denial, invalid planning, missing resources, unavailable previous
streams, and successful log collection must remain distinct outcomes.

List collection follows server continue tokens within the object ceiling and uses
kind-aware compact projections; object- or payload-ceiling truncation is explicit.
The object ceiling is operator-configurable, defaults to 250, and remains bounded
at 500 for the PoC. For explicit inventory requests, the API renders the collected
names as an evidence-cited Markdown table instead of relying on the model to copy
the list into its answer.
Collected objects are recursively bounded and redacted, persisted with source and
timestamp, and supplied to a second schema-validated answer pass. Cluster-specific
answers require server-resolvable evidence citations. A missing capability pack
does not block generic investigation, but the answer must expose collection gaps
and remain non-remediating until a typed action and its approval gates exist.

Conversations are private to their creating OpenShift user and have no hard
question-count limit. Operators can start a new conversation at any time and can
permanently delete an owned conversation, including its messages and evidence.
The model context uses a sliding recent-message window plus a bounded durable
digest of older messages. Per-user request throttling, per-turn read/model budgets,
bounded evidence retention, and independent UI message limits replace a session
turn cap. Enter submits the question; Shift+Enter inserts a newline.

Submitting a turn must clear the composer immediately, place the attributed user
message in the timeline, and show a pulsating/spinner assistant placeholder. The
API must persist the turn as a recoverable job and stream truthful workflow phases
such as resource discovery, safe-read planning, exact resource/log collection,
and evidence-backed answer preparation. Reloads and reconnects must preserve the
current phase. Progress must not claim an action before it starts and must not
expose model chain-of-thought. Only one turn may run in a conversation at a time.

## 6. Cluster Memory

### 6.1 Recommendation for the first release

Use SQLite with FTS5 inside the PodPilot API container on the `podpilot-data` PVC.
Do not deploy a separate vector database yet.

The SNO cluster initially had no StorageClass. PodPilot now supplies a non-default
`podpilot-local` class, one static 5 Gi Retain-policy local PV pinned to the SNO
node, and the `podpilot-data` claim for this disposable single-node lab.
Investigations, chat
history, audit events, and curated memory survive Pod replacement, but remain
vulnerable to node loss/rebuild. The UI must display a **Single-node PoC storage**
banner. Model credentials remain in an OpenShift Secret rather than SQLite.
Production requires supported CSI-backed block storage plus backup and restore.

Why:

- one cluster and one API replica need little retrieval scale
- FTS5 provides mature full-text indexing and query syntax in-process
- the same database can hold settings metadata, investigations, actions, audit
  events, curated documents, and retrieval metadata
- it eliminates another Deployment, service, credential, backup path, and memory consumer

SQLite documents FTS5 as its built-in full-text virtual-table module. If WAL mode
is used, all database processes must remain on the same host and it must not be
placed on a network filesystem. A single Pod with a block-backed `ReadWriteOncePod`
PVC matches those constraints. See [SQLite FTS5](https://www.sqlite.org/fts5.html),
[SQLite WAL constraints](https://www.sqlite.org/wal.html), and
[Kubernetes single-Pod volume access](https://kubernetes.io/docs/tasks/administer-cluster/change-pv-access-mode-readwriteoncepod/).

Start with lexical retrieval plus strong metadata filters. If semantic recall is
needed, compute embeddings through the configured provider and perform exact cosine
search in-process for the small corpus. This avoids committing to an early vector
extension or service.

### 6.2 When to move to PostgreSQL plus pgvector

Move when PodPilot requires multiple API replicas, concurrent writers,
multi-cluster tenancy, materially larger corpora, or database-operated backups and
high availability. pgvector keeps relational metadata and vectors in PostgreSQL
and supports exact and approximate search. See the [official pgvector project](https://github.com/pgvector/pgvector).

Qdrant is capable and supports single-node operation, but it is a separate vector
service with its own block-storage, resource, backup, and lifecycle requirements.
That is unnecessary for the MVP's small corpus. Its own documentation recommends
block-level POSIX storage and notes that sizing depends on vector dimensions,
payloads, indexes, and replication. See [Qdrant installation requirements](https://qdrant.tech/documentation/installation/).

### 6.3 Memory types

| Type | Example | Lifecycle |
| --- | --- | --- |
| Curated runbook | “Recover image pull failures using internal registry checks” | human-created, versioned, reviewed |
| Cluster fact | “Namespace X uses egress proxy Y” | scoped, owner, expiry required |
| Resource annotation | explicit `podpilot.io/context` metadata | live-read, never silently persisted |
| Incident summary | verified cause and successful action | human-approved before reusable |
| Product knowledge | versioned OpenShift diagnostic guidance | shipped with capability pack |

Every retrievable item requires `source`, `source_type`, `cluster_id`, optional
namespace/resource scope, owner, creation time, review/expiry time, sensitivity,
version, and verification state.

### 6.4 Memory administration

The GUI supports:

- paste or upload Markdown/text runbooks
- add structured cluster facts
- review, edit, disable, expire, and delete knowledge
- approve a verified incident summary for future retrieval
- preview which knowledge items influenced an investigation

Raw logs, full chat transcripts, model answers, Secrets, and failed hypotheses do
not become durable reusable memory automatically.

## 7. Proposed Architecture

### MVP implementation stack

- Red Hat UBI 9 Python 3.12 builder/runtime image, pinned by digest for releases.
- Python 3.12 with FastAPI, Pydantic, Uvicorn, SQLAlchemy, and Alembic.
- Jinja2 plus HTMX for a server-rendered GUI, with Server-Sent Events for investigation progress.
- Official `kubernetes` Python client and its `kubernetes.dynamic.DynamicClient`.
- Do not install the `oc` binary in the application image.
- Do not use the older `openshift` PyPI package as the core client dependency;
  its latest published release is 0.13.2 from 2023 and classified alpha.
- Use in-cluster service-account configuration in the Pod and kubeconfig only for local tests.
- Use `httpx` for bounded Thanos and Alertmanager HTTP requests.
- Use the official `openai` Python SDK behind provider-neutral Responses and
  strict-schema Chat Completions adapters.

The dynamic client performs API discovery, allowing PodPilot to work with core
Kubernetes resources, OpenShift resources such as Routes and ClusterOperators,
and later-installed CRDs without generated clients for every API group.

### MVP deployment in `ai-ops`

- **podpilot-api**: orchestration, OpenShift clients, deterministic diagnostics,
  retrieval, approval policy, action execution, and audit API.
- **podpilot-web**: Jinja2 templates and HTMX/static assets served by the API in the same image.
- **SQLite on `podpilot-data` PVC**: single-replica investigations, audit events,
  and memory on lab-local storage.
- **OpenShift Secret**: per-profile model tokens only; endpoint metadata and
  public custom CA certificates remain in SQLite.
- **Service/Route**: authenticated web and API access.
- **OAuth-aware Route proxy**: authenticates users with the cluster's
  `podpilot-htpasswd` provider and supplies a trusted OpenShift identity to the app.

The SNO cluster's built-in OpenShift authentication operator and OAuth route are
present and healthy. The PoC configures four HTPasswd test identities and maps
hierarchical OpenShift groups to viewer, investigator, approver, and break-glass
application permissions. Human groups receive no direct mutation RBAC; the
executor service account performs approved changes and the application correlates
them with the authenticated approver in its audit record.

Keep collection and action tools as explicit internal functions with typed inputs.
Do not expose a generic `oc`, shell, or unrestricted Kubernetes proxy tool to the model.

### Model interaction boundary

1. Deterministic code builds a minimal, redacted evidence package.
2. Retrieval adds scoped, current, attributable knowledge.
3. The model returns a schema-validated analysis and optional typed action intents.
4. The server independently validates every cited observation and action target.
5. Only the action executor can mutate the cluster after approval.

## 8. Capability Roadmap

### Capability Pack 1: alerts and unhealthy workloads

- CrashLoopBackOff, ImagePullBackOff, pending/unschedulable Pods
- failed probes, OOMKilled, missing ConfigMaps/Secrets references without reading values
- rollout and replica mismatch
- Pod logs, previous logs, events, resource pressure, and owner chain
- approved Pod recreation and workload restart

### Capability Pack 2: Services and Routes

- Service selectors and endpoint availability
- targetPort/containerPort mismatches
- Route service/port/TLS configuration
- DNS resolution and bounded connectivity probes
- NetworkPolicy explanation

Mutation remains disabled until each action has a typed schema, dry-run/precondition
strategy, verification, rollback, and evaluation coverage.

### Capability Pack 3: ClusterOperators and platform services

- condition history and related namespace resources
- storage, ingress, authentication, monitoring, and image-registry operator checks
- upgrade-blocking conditions

### Capability Pack 4: Service Mesh

- Live lab check on 2026-08-22 found no Service Mesh, Istio, VirtualService, or
  Kiali CRDs/operators. Install a supported mesh and create fault fixtures before
  treating this capability pack as implementable or testable.
- detect Service Mesh 2 versus 3
- `ServiceMeshControlPlane` versus `Istio`/`IstioCNI` health
- Kiali, control plane, gateway, sidecar/ambient enrollment, mTLS, and certificate checks
- `VirtualService`, `DestinationRule`, `Gateway`, and service/port consistency
- version-specific diagnostic packs and explicit unsupported-version response

## 9. Functional Requirements

### Required for MVP

- FR-1: A PoC user can save and capability-test one OpenAI-compatible model profile without exposing its token to the browser after submission.
- FR-2: A PoC user can view current Alertmanager alerts and their state.
- FR-3: A user can create exactly one durable investigation per Analyze request.
- FR-4: The system gathers bounded evidence and exposes partial collection failures.
- FR-5: Analysis distinguishes observations, hypotheses, uncertainty, and actions.
- FR-6: Every cluster-specific factual claim cites evidence.
- FR-7: A user can chat within one investigation and request supported follow-up tools.
- FR-8: The system can propose only registered typed actions.
- FR-9: An authenticated `podpilot-approvers` member can preview and approve one action, and the audit event records that OpenShift identity.
- FR-10: The executor enforces resource identity/version preconditions and records an audit event.
- FR-11: The system verifies the result and reports resolved, unresolved, or failed.
- FR-12: An administrator can curate and inspect cluster memory.

## 10. Non-Functional Requirements

- First dashboard content visible within 5 seconds when cluster APIs are healthy.
- First evidence appears within 15 seconds of Analyze.
- Default investigation finishes within 90 seconds or reports which dependency is delayed.
- Every external call has a timeout, bounded retry policy, and cancellation path.
- A single investigation has configurable limits for tool calls, log bytes, PromQL range, model tokens, and elapsed time.
- Model and cluster credentials never appear in browser payloads, logs, traces, or audit bodies.
- The system remains navigable when the model endpoint is unavailable and still shows deterministic evidence.
- PoC mutations are attributable to the authenticated OpenShift user plus an
  immutable proposal record, while the Kubernetes API caller remains the executor service account.
- The UI visibly warns that application state is node-local and that break-glass
  roles are for lab evaluation only.

## 11. Success Metrics

Do not use chat-message count or token volume as success metrics.

- Median time from Analyze to first supported hypothesis.
- Percentage of factual claims with valid evidence citations.
- Top-1 and top-3 root-cause accuracy on versioned incident evals.
- Percentage of investigations where a junior admin reaches the verified resolution.
- Approved-action success, no-effect, rollback, and failure rates.
- False-remediation proposal rate; target zero in the release-blocking suite.
- Operator-rated usefulness and explanation clarity.
- Secrets or sensitive values sent to model/telemetry; target zero.

## 12. MVP Acceptance Scenarios

The first three incidents are practice fixtures and release-blocking evaluation
cases, not a hard-coded capability ceiling. The agent may investigate any cluster
symptom using its bounded generic collectors; the UI must label domains without a
validated capability pack as exploratory and keep remediation display-only.

1. A deliberately broken workload fires `KubePodCrashLooping`; PodPilot uses current
   and previous logs, termination reason, events, and owner chain to identify the cause.
2. An invalid container image fires `KubeContainerWaiting`; PodPilot distinguishes
   a nonexistent image from registry authentication evidence without exposing pull-secret contents.
3. An impossible CPU or memory request fires `KubePodNotScheduled`; PodPilot cites
   scheduler events, resource requests, node allocatable capacity, and taints/tolerations.
4. A controller-owned failed Pod produces a typed recreate proposal, becomes stale
   when resourceVersion changes, and cannot execute without renewed approval.
5. A rollout restart records before/after state and reports whether replicas became ready.
6. An Alertmanager outage produces a degraded dashboard state, not an empty healthy state.
7. A model outage still returns deterministic evidence and manual next checks.
8. Prompt-injection text in a Pod log is quoted as evidence and never changes tool policy.
9. A stale cluster-memory item is excluded or visibly flagged.

## 13. Explicit MVP Non-Goals

- Multiple clusters, tenants, or fleet views.
- Autonomous, unattended remediation.
- Arbitrary shell, `oc`, YAML, or model-generated patches.
- Node reboot/drain, MachineConfig, RBAC, Secret, certificate, or storage mutation.
- Full log aggregation or time-series visualization.
- Service Mesh support in the first capability pack.
- Learned memory created automatically from every conversation.
- High availability or production-grade durable state; SQLite on SNO-local storage is intentionally single-replica and node-bound.

## 14. Decisions Needed Before Implementation

1. Should MVP execute both registered actions, or begin with controller-owned Pod recreation and keep rollout restart display-only?
2. How much log data may one investigation collect before truncation?
3. When the model recommends an unregistered fix, should the UI show a copyable
   operator command, or explanatory steps only?
