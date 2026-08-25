# PodPilot Codebase Map

Last reviewed: 2026-08-23
Update when: top-level structure, core tooling, or verification commands change.

## Workspaces

| Path | Responsibility | Status |
| --- | --- | --- |
| `apps/api/` | AI orchestration and HTTP API | Milestone 10 alert and standalone evidence-cited investigation flow |
| `apps/web/` | operator investigation UI | alert queue, evidence-cited chat, executable safe-check plan, approval, and cancellation |
| `packages/openshift-client/` | Kubernetes, Thanos, and Alertmanager adapters | bounded monitoring/evidence checks, typed actions, and read-only validation clients |
| `packages/diagnostics/` | deterministic tools, evidence, and runbooks | evidence, diagnostic plan, interpretation, and remediation contracts |
| `deploy/openshift/` | OpenShift runtime identity, RBAC, workload, build, and lab storage | Reader runtime plus separate lab break-glass identity |
| `evals/` | incident fixtures and expected outcomes | synthetic workload alerts plus live remediation and TargetDown fixtures |
| `scripts/` | local development and cluster bootstrap helpers | SNO connection helper present |

Each workspace has a local `AGENTS.md` describing its intended boundary.

## Tooling

- Git repository initialized.
- Python 3.12 on Red Hat UBI 9 is selected for the API and diagnostic runtime.
- FastAPI, Pydantic, Uvicorn, SQLAlchemy, and Alembic form the initial API stack.
- Jinja2, HTMX, and Server-Sent Events provide the single-image interactive GUI.
- The official Kubernetes Python dynamic client replaces a runtime dependency on `oc`.
- The provider router uses the official OpenAI Python SDK for Responses and
  strict-schema Chat Completions endpoints. SQLite stores endpoint metadata while
  per-profile tokens remain in the fixed OpenShift credential Secret.
- SQLite FTS5 on the `podpilot-data` SNO-local PVC provides single-replica PoC state.
- Hash-locked dependencies are generated with `pip-compile`; pytest and coverage are configured in `pyproject.toml`.
- OpenShift manifests use Kustomize's built-in resource aggregation.

## Important Files

- `AGENTS.md`: repository router and invariants.
- `.gitignore`: credential, local cluster state, build output, and editor exclusions.
- `Dockerfile`: pinned UBI Python image and non-root application runtime.
- `requirements.lock`: hash-locked production dependency graph.
- `apps/api/src/podpilot_api/main.py`: FastAPI routes and security headers.
- `apps/api/migrations/`: Alembic schema history.
- `apps/api/src/podpilot_api/model_provider.py`: structured interpretation and
  investigation-chat provider contracts.
- `apps/web/`: local templates, styles, and JavaScript with no CDN dependency.
- `packages/openshift-client/src/podpilot_openshift/roles.py`: cached OpenShift group-role resolution.
- `packages/openshift-client/src/podpilot_openshift/alerts.py`: TLS-validated, bounded Alertmanager transport.
- `packages/openshift-client/src/podpilot_openshift/workloads.py`: bounded Pod,
  event, owner-chain, log, and scheduling evidence collection.
- `packages/openshift-client/src/podpilot_openshift/remediation.py`: typed action
  preview, read-only target validation, execution, and verification.
- `packages/openshift-client/src/podpilot_openshift/checks.py`: registered,
  bounded monitoring signal, Service topology, and target event checks.
- `packages/openshift-client/src/podpilot_openshift/metrics.py`: authenticated,
  TLS-validated, response-bounded Thanos instant-query adapter.
- `packages/diagnostics/src/podpilot_diagnostics/alerts.py`: model-free alert evidence and triage results.
- `packages/diagnostics/src/podpilot_diagnostics/workloads.py`: portable workload evidence contracts.
- `packages/diagnostics/src/podpilot_diagnostics/checks.py`: portable diagnostic
  plan, result, and executor contracts.
- `evals/fixtures/`: synthetic CrashLooping, image-waiting, and scheduling cases.
- `deploy/openshift/rbac.yaml`: read-only observer permissions.
- `deploy/openshift/workload/`: Deployment, OAuth-protected Service/Route, and NetworkPolicy.
- `deploy/openshift/build/sno-binary/`: lab ImageStream and binary BuildConfig.
- `deploy/openshift/overlays/sno-milestone-one/`: complete SNO application overlay.
- `deploy/openshift/overlays/poc-cluster-admin/`: additive cluster-admin exception for the disposable SNO lab.
- `deploy/openshift/auth/poc-htpasswd/`: hierarchical PoC application groups and minimal OAuth-proxy access RBAC.
- `deploy/openshift/storage/sno-local/`: non-default static local storage for the disposable SNO lab.
- `docs/ocp-inventory-reuse.md`: reviewed boundary for selectively extracting adjacent project patterns.
- `scripts/connect-sno.ps1`: generates a short-lived observer kubeconfig outside the repository.
- `scripts/copy-poc-user-password.ps1`: copies one temporary lab password to the Windows clipboard without printing it.
- `docs/product.md`: initial product scope.
- `docs/cluster-lab.md`: known lab topology and verification commands.
- `docs/security.md`: trust and secret-handling boundaries.

## Verification Commands

- `git status --short`
- `git check-ignore -v <candidate-sensitive-file>`
- `oc apply --dry-run=server -k deploy/openshift`
- `oc auth can-i --list --as=system:serviceaccount:ai-ops:ai-observer`
- `.\.venv\Scripts\python.exe -m pytest --cov --cov-report=term-missing`
- `.\.venv\Scripts\python.exe -m alembic -c apps/api/alembic.ini upgrade head`

## Questions To Resolve

- Which capability follows the first executable plan: investigation chat,
  active reachability probes, Routes, ClusterOperators, or curated memory?
- Which supported CSI storage and backup design replaces SNO-local storage for production?
- Which production image registry and immutable release promotion flow replaces the SNO binary build?
