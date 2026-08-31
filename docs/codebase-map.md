# PodPilot Codebase Map

Last reviewed: 2026-08-24
Update when: top-level structure, core tooling, or verification commands change.

## Workspaces

| Path | Responsibility | Status |
| --- | --- | --- |
| `apps/api/` | AI orchestration and HTTP API | Milestone 10 alert and standalone evidence-cited investigation flow |
| `apps/web/` | operator investigation UI | alert queue, evidence-cited chat, executable safe-check plan, approval, and cancellation |
| `packages/openshift-client/` | Kubernetes, Thanos, LokiStack, and Alertmanager adapters | bounded monitoring/evidence checks, typed actions, and read-only validation clients |
| `packages/diagnostics/` | deterministic tools, evidence, and runbooks | evidence, diagnostic plan, interpretation, and remediation contracts |
| `deploy/openshift/` | OpenShift runtime identity, RBAC, workload, portable remote overlay, build, and lab storage | Remote reader deployment plus separate lab-only paths |
| `evals/` | incident fixtures and expected outcomes | synthetic workload alerts plus live remediation and TargetDown fixtures |
| `scripts/` | local development and cluster bootstrap helpers | SNO connection helper present |

Each workspace has a local `AGENTS.md` describing its intended boundary.

## Tooling

- Git repository initialized.
- Python 3.12 on Red Hat UBI 9 is selected for the API and diagnostic runtime.
- FastAPI, Pydantic, Uvicorn, SQLAlchemy, and Alembic form the initial API stack.
- Jinja2, HTMX, and Server-Sent Events provide the single-image interactive GUI.
- The guarded runtime uses the official Kubernetes Python dynamic client instead of `oc`. The
  explicit unrestricted overlays add a separate digest-pinned `oc` runner sidecar.
- The provider router uses the official OpenAI Python SDK for Responses and
  strict-schema Chat Completions endpoints. SQLite stores endpoint metadata while
  per-profile tokens remain in the fixed OpenShift credential Secret.
- SQLite FTS5 on `podpilot-data` provides single-replica PoC state. The remote
  PVC uses the cluster's default StorageClass; local static storage is isolated
  to the lab overlay.
- Hash-locked dependencies are generated with `pip-compile`; pytest and coverage are configured in `pyproject.toml`.
- OpenShift manifests use Kustomize's built-in resource aggregation.

## Important Files

- `AGENTS.md`: repository router and invariants.
- `.gitignore`: credential, local cluster state, build output, and editor exclusions.
- `Dockerfile`: pinned UBI Python image and non-root application runtime.
- `Dockerfile.oc-runner`: pinned agentic sidecar containing Linux `oc` and the loopback runner.
- `deploy/openshift/components/agentic-runner/`: shared optional sidecar patch used by SNO and
  remote agentic overlays.
- `deploy/openshift/overlays/remote-poc-agentic/`: additive unrestricted remote PoC overlay with a
  separately promoted runner ImageStream.
- `requirements.lock`: hash-locked production dependency graph.
- `apps/api/src/podpilot_api/main.py`: FastAPI routes and security headers.
- `apps/api/migrations/`: Alembic schema history.
- `apps/api/src/podpilot_api/model_provider.py`: structured interpretation and
  investigation-chat provider contracts.
- `apps/web/`: local templates, styles, and JavaScript with no CDN dependency.
- `packages/openshift-client/src/podpilot_openshift/roles.py`: cached,
  deployment-configured OpenShift group-to-application-role resolution.
- `packages/openshift-client/src/podpilot_openshift/alerts.py`: TLS-validated, bounded Alertmanager transport.
- `packages/openshift-client/src/podpilot_openshift/workloads.py`: bounded Pod,
  event, owner-chain, log, and scheduling evidence collection.
- `packages/openshift-client/src/podpilot_openshift/remediation.py`: typed action
  preview, read-only target validation, execution, and verification.
- `packages/openshift-client/src/podpilot_openshift/agent_runner.py`: loopback client for the
  lab-only unrestricted shell sidecar, including per-command registered-cluster credential
  brokering that never exposes tokens to model messages.
- `packages/openshift-client/src/podpilot_openshift/checks.py`: registered,
  bounded monitoring signal, Service topology, and target event checks.
- `packages/openshift-client/src/podpilot_openshift/metrics.py`: authenticated,
  TLS-validated, response-bounded Thanos instant/range-query adapter.
- `packages/openshift-client/src/podpilot_openshift/metric_trends.py`: registered
  metric templates, bounded range execution, normalized points, statistics, and trends.
- `packages/openshift-client/src/podpilot_openshift/log_metrics.py`: authenticated,
  aggregate-only LokiStack namespace-volume query and bounded evidence normalization.
- `packages/openshift-client/src/podpilot_openshift/discovery.py`: cached,
  policy-filtered live API catalog and safe resource-name resolution.
- `packages/openshift-client/src/podpilot_openshift/explorer.py`: bounded dynamic
  GET/LIST/projected-search, Pod-log, and typed HTTP-probe dispatch with pagination, projection,
  and redaction.
- `packages/openshift-client/src/podpilot_openshift/http_probe.py`: bounded,
  unauthenticated HTTP/HTTPS observations with default-verified or explicitly insecure TLS, SNI, connection
  overrides, no redirects, and response ceilings.
- `packages/diagnostics/src/podpilot_diagnostics/alerts.py`: model-free alert evidence and triage results.
- `packages/diagnostics/src/podpilot_diagnostics/adhoc.py`: portable read-plan,
  deterministic inventory, and ad-hoc evidence contracts.
- `packages/diagnostics/src/podpilot_diagnostics/workloads.py`: portable workload evidence contracts.
- `packages/diagnostics/src/podpilot_diagnostics/checks.py`: portable diagnostic
  plan, result, and executor contracts.
- `evals/fixtures/`: synthetic CrashLooping, image-waiting, and scheduling cases.
- `deploy/openshift/base/rbac.yaml`: narrow OpenShift Group lookup, supporting platform
  views, and explicit namespaced Alertmanager API permissions; no `cluster-reader` binding.
- `deploy/openshift/overlays/remote-poc/`: portable remote-cluster Kustomize entry
  point with an internal-registry ImageStreamTag deployment.
- `docs/remote-poc-deployment.md`: ordered build, authorization, install,
  validation, and rollback procedure.
- `deploy/openshift/workload/`: Deployment, OAuth-protected Service/Route, and NetworkPolicy.
- `deploy/openshift/build/sno-binary/`: lab ImageStream and binary BuildConfig.
- `deploy/openshift/overlays/sno-milestone-one/`: complete SNO application overlay.
- `deploy/openshift/overlays/remote-poc-agentic/`: optional additive remote unrestricted overlay.
- `deploy/openshift/overlays/poc-cluster-admin/`: additive cluster-admin exception for the disposable SNO lab.
- `deploy/openshift/auth/poc-htpasswd/`: elevated PoC application groups and authenticated-user OAuth-proxy access RBAC.
- `deploy/openshift/storage/sno-local/`: non-default static local storage for the disposable SNO lab.
- `docs/ocp-inventory-reuse.md`: reviewed boundary for selectively extracting adjacent project patterns.
- `scripts/connect-sno.ps1`: generates a short-lived observer kubeconfig outside the repository.
- `scripts/deploy-agentic-sno.ps1`: RBAC-checks, builds, deploys, and configures the SNO
  OpenRouter/oc agent simulation without printing credentials.
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

- Which read domains need deeper deterministic interpretation beyond generic
  discovery-backed evidence collection, and which typed remediation pack follows?
- Which supported CSI storage and backup design replaces SNO-local storage for production?
- Which production image registry and immutable release promotion flow replaces the SNO binary build?
