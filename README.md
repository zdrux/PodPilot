# PodPilot

PodPilot is an OpenShift-first AI troubleshooting and Day-2 operations companion.
It correlates alerts, metrics, resource state, events, and targeted logs into an
evidence-backed investigation with ranked hypotheses and approved remediations.

Milestone 6 is implemented for the disposable SNO lab. PodPilot correlates workload
alerts with bounded live evidence and model interpretation, then offers a small
set of typed, previewed, approval-gated remediations with stale-target checks,
verification, lifecycle reconciliation, explicit cancellation, and audit
attribution. See the current project status for the precise handoff and remaining
work.

## Start Here

- [Current project status](docs/project-status.md)
- [Product brief](docs/product.md)
- [Product requirements draft](docs/prd.md)
- [Architecture](docs/architecture.md)
- [Security model](docs/security.md)
- [Hyper-V SNO lab](docs/cluster-lab.md)
- [Operations](docs/operations.md)
- [ocp-inventory reuse boundary](docs/ocp-inventory-reuse.md)

## Repository Shape

```text
apps/api/                    AI orchestration and HTTP API
apps/web/                    Operator investigation UI
packages/openshift-client/   Kubernetes, Thanos, and Alertmanager adapters
packages/diagnostics/        Deterministic diagnostics and evidence models
deploy/openshift/            Runtime identity and permissions
evals/                       Sanitized incident evaluations
docs/                        Living project knowledge
```

## Safety

Never commit cluster pull secrets, kubeconfigs, kubeadmin credentials, private
keys, installer ISOs, service-account tokens, or model API keys. PodPilot's
production base identity is read-only; the disposable PoC lab uses a separate,
explicit cluster-admin overlay. Every product mutation still requires a preview
and fresh user approval.

## Develop Locally

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.lock
python -m pip install -e . --no-deps
python -m pytest --cov --cov-report=term-missing
```

## Deploy The Current Milestone

Connect to the disposable SNO lab with a short-lived PoC cluster-admin identity:

```powershell
. .\scripts\connect-sno.ps1
oc whoami
```

Build the image inside OpenShift, create the generated OAuth cookie Secret, and
apply the lab overlay. Full commands and router CA guidance are in
[Operations](docs/operations.md).

```powershell
oc apply --dry-run=server -k deploy/openshift
oc apply -k deploy/openshift
oc apply -k deploy/openshift/build/sno-binary
oc start-build podpilot --from-dir=. --follow -n ai-ops
oc apply -k deploy/openshift/overlays/sno-milestone-one
oc apply -k deploy/openshift/overlays/poc-cluster-admin
oc -n ai-ops rollout status deployment/podpilot --timeout=180s
oc auth can-i --list --as=system:serviceaccount:ai-ops:ai-observer
```
