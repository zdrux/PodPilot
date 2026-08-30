# PodPilot Product Brief

Last reviewed: 2026-08-22
Update when: target user, product scope, core workflow, or non-goals change.

## Current access model

Ask is the product landing experience. Every cluster request uses a temporary OpenShift token
created from the signed-in user's own credentials; PodPilot stores cluster metadata but no remote
bearer tokens. Investigator conversations are always read-only. Read-Write users choose read-only
or Action mode before the first message, and that mode plus the selected clusters remains locked.
Both modes use the same autonomous investigation loop, typed collectors, and shell-backed `oc`
capability. The broker gives Investigator mode a read-only Kubernetes capability and gives Action
mode the user's full Kubernetes capability; product usefulness must not otherwise differ by mode.
Users may maintain private cluster metadata alongside administrator-managed shared entries.
Cluster sign-ins belong to the PodPilot browser session rather than a conversation: users may add
more clusters later, remove one sign-in, or remove all sign-ins without deleting durable chats.
The Workspace sidebar lists every enabled cluster visible to the user and marks its current
browser-session login state. Selecting a connected cluster opens a fresh composer preselected for
that cluster; selecting a disconnected cluster first opens the existing username/password login
flow and then returns to that preselection. The cluster-tree add control opens private ad hoc
cluster registration. Shared registry administration is separately labeled **Cluster Management**
under the administrative section.
Cluster Health is not part of the active navigation or remote access model.
The **Show my access** starter runs deterministic cluster-wide Kubernetes
SelfSubjectAccessReview checks for common workload resources and renders exactly one permission
matrix per selected cluster. It does not infer authorization by listing objects or ask the model
to select, label, or summarize those results.

## Problem

OpenShift operators must correlate alerts, metrics, events, logs, workload state,
and platform operator health under time pressure. PodPilot gathers that evidence,
explains likely causes, and offers safe verification steps without pretending the
model is the source of truth.

## Initial User

An OpenShift administrator or SRE investigating a firing alert or a degraded
cluster/workload in a lab or non-production environment.

## First Useful Workflow

1. Show active alerts, including silenced and inhibited state.
2. Select an alert to begin an investigation.
3. Collect a bounded evidence bundle: alert labels/annotations, rule state,
   relevant PromQL, resource status, events, operator conditions, and targeted logs.
4. Present ranked hypotheses, cited evidence, uncertainty, and operator-run next steps.
5. Capture operator feedback for evaluations without retaining secrets.

## Product Principles

- Evidence before explanation.
- Investigation is read-only by default; the broker rejects every Kubernetes write in Investigator
  mode. Action-mode mutations remain behind PodPilot's preview and explicit-approval boundary and
  are additionally bounded by the signed-in user's RBAC and admission policy.
- Least privilege and explicit scope.
- Safe failure and honest uncertainty.
- OpenShift-first UX with portable Kubernetes foundations.
- Deterministic diagnostics remain useful when the model is unavailable.
- Resource LIST/search evidence is inventory only. Collection analysis uses exact GET evidence for
  every object only when the complete collection fits the configured small fan-out bound; larger
  collections must be narrowed and are reported as partial rather than sampled as if complete.

## Non-Goals For The First Milestone

- Autonomous remediation in Investigator mode or any write that bypasses the conversation broker.
- `cluster-admin` access.
- Direct cluster credentials or an unbrokered command interface over the cluster.
- Production HA claims based on a single-node Hyper-V lab.
- Hosting a large model on the SNO control-plane node.
