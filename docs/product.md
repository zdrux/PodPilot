# PodPilot Product Brief

Last reviewed: 2026-08-22
Update when: target user, product scope, core workflow, or non-goals change.

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
- Investigation is read-only by default; mutations require a typed preview and fresh approval.
- Least privilege and explicit scope.
- Safe failure and honest uncertainty.
- OpenShift-first UX with portable Kubernetes foundations.
- Deterministic diagnostics remain useful when the model is unavailable.

## Non-Goals For The First Milestone

- Autonomous remediation, arbitrary shell execution, or unrestricted model-generated patches.
- `cluster-admin` access.
- A general-purpose chat interface over every cluster object.
- Production HA claims based on a single-node Hyper-V lab.
- Hosting a large model on the SNO control-plane node.
