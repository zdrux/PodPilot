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

Milestone 2 automates the Watchdog-only healthy view, explicit Alertmanager
degradation, group-role denial, CSRF denial, durable investigation/audit creation,
bounded alert normalization, and synthetic CrashLooping, image-waiting, and
unscheduled triage expectations. Metrics, resource state, events, and log evidence
remain required before those three capability fixtures can graduate from triage
to root-cause evaluation.

## Rollback

Reapply the previous immutable application image digest and matching manifest
revision, then wait for `deployment/podpilot` to become available. The SNO binary
build currently publishes `:latest` for iteration, so record the successful
ImageStream digest before a release and patch the overlay to that digest for a
repeatable rollback. Alembic migrations must be backward-compatible until a
separate, tested database rollback procedure exists.
