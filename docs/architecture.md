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

Milestone 2 adds a bounded Alertmanager adapter that uses the projected service
account token and OpenShift service CA to call the in-cluster v2 API. Dashboard
requests obtain a fresh snapshot; Alertmanager remains the source of truth and
PodPilot does not create a second alert store. Watchdog is separated from the
actionable queue, while collection failure produces an explicit degraded state.

An Investigator can create one durable investigation from an active fingerprint.
The API re-reads Alertmanager before creation, runs a deterministic alert-type
triage pack, stores the bounded alert snapshot and evidence-linked result, and
records an audit event. Analyze is protected by both application role and a
double-submit CSRF token. Milestone 2 contains no model call, cluster mutation,
chat, PromQL, event, resource-status, or log collector.

## Investigation Flow

1. An operator selects an alert or describes a symptom.
2. The API establishes scope, time range, and a bounded tool budget.
3. Deterministic tools collect only the required cluster evidence.
4. The diagnostics engine correlates observations and records provenance.
5. Sensitive values are removed before any external model call.
6. The model proposes ranked hypotheses and safe verification steps.
7. The UI presents conclusions alongside supporting evidence and uncertainty.

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
