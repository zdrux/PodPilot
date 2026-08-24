# PodPilot Architecture

Last reviewed: 2026-08-23
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
highest matching role from the four named OpenShift groups, renders the dashboard,
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

Milestone 4 adds a singleton provider profile and a provider-neutral interpretation
contract. Metadata and capability results live in SQLite; the token lives only in
the resourceName-restricted `ai-ops/podpilot-model-credentials` Secret. An
Approver can save the profile and run an explicit capability probe. Only a profile
that passes endpoint, TLS, authentication, model, streaming, tool-call, structured
output, and configured embedding checks is used for investigations. The first
adapter uses the official OpenAI SDK and Responses API with `store=false`.
Schema-validated interpretation is displayed separately from deterministic facts.
Provider failure preserves the deterministic investigation and records a bounded,
credential-free error.

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
generic tool interface to the provider. Model citations are intersected with the
persisted observation-ID set; uncited evidence-based claims are replaced with an
insufficient-evidence response. The server similarly accepts only the literal
`run_queued_checks` proposal while queued `DiagnosticCheck` records exist. The UI
links validated citations to evidence cards and routes execution through the
pre-existing check endpoint after a distinct operator click.

Milestone 9 adds a bounded Thanos query adapter and a third server-owned
`TargetDown` check. The diagnostics registry derives exact namespace, Service,
job, and instance matchers from the persisted normalized alert. The adapter sends
only fixed `ALERTS` and `up` instant-query shapes to the authenticated in-cluster
Thanos endpoint, validates its service certificate, caps time, body size, and
series count, and normalizes values and label provenance. It does not expose a
generic PromQL endpoint to the API, browser, or model. Active target probing is
deliberately absent because the alert is not an authorized network-destination
registry.

## Investigation Flow

1. An operator selects an alert or describes a symptom.
2. The API establishes scope, time range, and a bounded tool budget.
3. Deterministic tools collect only the required cluster evidence.
4. The diagnostics engine correlates observations and records provenance.
5. Sensitive values are removed before any external model call.
6. A supported server-owned plan can execute registered read-only follow-up checks.
7. The model reassesses the expanded evidence and proposes hypotheses or remaining checks.
8. Investigation chat answers follow-up questions with server-validated evidence citations.
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
- OpenAI Responses API through the first provider adapter and official Python SDK, using `gpt-5.6-terra` initially; internal OpenAI-compatible endpoints can be configured later.
- SQLite FTS5 on the SNO-lab `podpilot-data` PVC for single-replica investigations and memory.

## Open Questions

- Production-grade durable storage and backup path after the SNO-local PoC.
- Multi-cluster identity and tenancy design.
- Production separation between read and approval-gated action identities.
