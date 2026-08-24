# PodPilot Release And QA

Last reviewed: 2026-08-23
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
- Confirm image digests, resource limits, probes, NetworkPolicy, and rollback instructions.

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

## Rollback

Reapply the previous immutable application image digest and matching manifest
revision, then wait for `deployment/podpilot` to become available. The SNO binary
build currently publishes `:latest` for iteration, so record the successful
ImageStream digest before a release and patch the overlay to that digest for a
repeatable rollback. Alembic migrations must be backward-compatible until a
separate, tested database rollback procedure exists.
