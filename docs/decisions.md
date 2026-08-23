# PodPilot Decisions

Last reviewed: 2026-08-23
Update when: a durable architecture or product-engineering decision is made or superseded.

## 2026-08-22 - PoC cluster-admin with product-level approval gates

Context: An AI troubleshooting service needs broad visibility, while AI-proposed actions can be incorrect or influenced by untrusted cluster content.

Decision: The disposable SNO lab grants the PodPilot service account cluster-admin so development can cover Day-2 operations and approved fixes. The reusable base RBAC remains read-only, and the product requires a preview plus explicit user approval before every mutation.

Consequences: The PoC can exercise the full lifecycle, but it is not a production security model. Production requires separate read/action identities, an action allowlist, audit history, and no cluster-admin binding.

## 2026-08-22 - Deterministic evidence before model interpretation

Context: Troubleshooting conclusions must be reproducible and attributable.

Decision: Cluster collection, normalization, correlation, and evidence provenance live in deterministic packages. The model interprets bounded, redacted evidence.

Consequences: Model-free unit and integration tests are required for diagnostics. User-visible claims should link back to observations.

## 2026-08-22 - Remote inference for the SNO lab

Context: The single-node cluster has finite resources and runs the entire OpenShift control plane and monitoring stack.

Decision: Start with a remote model API rather than running an LLM on the SNO node.

Consequences: Evidence must be redacted before egress, outbound network policy must be explicit, and provider credentials must remain in a Secret or external secret store.

## 2026-08-22 - OpenShift-first, portable diagnostic core

Context: The initial environment and product need are OpenShift-specific, but many diagnostic concepts apply to Kubernetes generally.

Decision: Optimize the first adapters and UX for OpenShift while isolating distribution-specific APIs behind the client boundary.

Consequences: OpenShift resources can be first-class, but core evidence contracts should not require them when a Kubernetes equivalent exists.

## 2026-08-22 - Python on Red Hat UBI without oc

Context: PodPilot needs dynamic access to core Kubernetes, OpenShift, and future CRD APIs without bundling the `oc` CLI into every image.

Decision: Build the API on UBI 9 Python 3.12 and use the maintained official `kubernetes` Python package plus `kubernetes.dynamic.DynamicClient`. Do not use `oc` as an application runtime dependency or rely on the older `openshift` PyPI package as the primary client.

Consequences: Cluster operations are typed Python functions over API discovery. Release images pin the UBI digest and Python dependencies, and client compatibility is tested against the lab's Kubernetes 1.35/OpenShift 4.22 API.

## 2026-08-22 - Configurable OpenAI-compatible model boundary

Context: The local Windows environment has a validated OpenAI API key and access to the candidate reasoning and embedding models.

Decision: Define a provider-neutral model adapter and a persisted model profile containing base URL, secret reference, chat model, optional embedding model, timeout, TLS CA reference, and discovered capabilities. The first adapter uses the official OpenAI Python SDK and Responses API with `store=false`; start evaluations with `gpt-5.6-terra` and `text-embedding-3-small` where semantic retrieval adds value.

Consequences: The key is copied directly into an OpenShift Secret during deployment, never into Git. OpenAI-compatible internal endpoints can be selected later without changing investigation code, but each profile must pass capability probes because URL compatibility does not guarantee tool calling, structured output, streaming, or embeddings.

## 2026-08-22 - Persistent single-node PoC storage

Context: The SNO lab initially had no StorageClass, while SQLite state should survive application Pod replacement.

Decision: Install a non-default `podpilot-local` StorageClass with one static, Retain-policy local PV pinned to the SNO node and mount the `podpilot-data` PVC for SQLite FTS5. Require explicit `PODPILOT_POC_MODE=true` for this lab-only storage and executor configuration.

Consequences: Pod replacement preserves investigations and memory, but node loss/rebuild can still lose them; local filesystem capacity is not enforced by the declared PV size and the layout is SNO-lab-only. The UI must show persistent storage and lab-policy warnings.

## 2026-08-22 - Selective ocp-inventory extraction

Context: The adjacent `ocp-inventory` project contains a functional FastAPI/Jinja dashboard and useful OpenShift patterns, but it solves fleet inventory rather than incident investigation and carries security and maintainability shortcuts that do not fit PodPilot.

Decision: Reuse reviewed visual patterns, small UI infrastructure, resource-formatting helpers, and the dynamic-discovery concept. Rewrite the domain model, adapters, diagnostic engine, settings, migrations, and remediation path. Do not inherit plaintext tokens, disabled TLS verification, hard-coded secrets, anonymous-admin fallback, CDN runtime dependencies, or monolithic JavaScript.

Consequences: PodPilot gets a faster UI start without coupling its core architecture or trust boundaries to the adjacent application. See `docs/ocp-inventory-reuse.md`.

## 2026-08-22 - Single-image server-rendered GUI

Context: The PoC needs a useful interactive dashboard while remaining lightweight and Python-first.

Decision: Serve Jinja2 templates, HTMX interactions, static assets, and Server-Sent Events from FastAPI in one image rather than introducing a separate Node/SPA build and frontend Deployment.

Consequences: The first UI ships with less build and runtime overhead. A separate frontend remains possible if later interaction complexity justifies it.

## 2026-08-22 - OpenShift OAuth attribution with HTPasswd lab users

Context: Approval records need a human identity before executable remediation is enabled, and the SNO cluster has a healthy built-in OAuth server but no external identity provider.

Decision: Configure a PoC HTPasswd provider and hierarchical `podpilot-viewers`, `podpilot-investigators`, `podpilot-approvers`, and `podpilot-breakglass` groups. Protect the PodPilot Route with an OAuth-aware proxy and map those groups to application permissions. Keep FastAPI on Pod loopback, expose only the proxy Service port, and do not grant human groups direct mutation RBAC or cluster-admin.

Consequences: Test approvals can be attributed to named OpenShift users. Cluster API mutations still appear as the executor service account and must be correlated with PodPilot's action audit record. Password bootstrap material remains outside Git and is deleted after distribution.

## 2026-08-22 - Disposable integrated-registry build path

Context: The SNO lab has no external release registry and its integrated image
registry was disabled.

Decision: Enable the integrated registry with `emptyDir` storage for this lab and
use an OpenShift binary Docker BuildConfig for fast Milestone 1 iteration.

Consequences: Image data can disappear when the registry Pod is replaced, and
`:latest` is not a releasable artifact reference. Production promotion must use a
durable registry, vulnerability scanning, and immutable image digests.

## 2026-08-23 - Live alerts without a second alert store

Context: The work queue needs current Alertmanager state, but duplicating alert
lifecycle locally would create consistency and retention problems.

Decision: Fetch bounded snapshots from the in-cluster Alertmanager v2 API using
the projected identity and service CA. Persist an alert snapshot only when a user
explicitly creates an investigation. Separate Watchdog from actionable alerts and
show collection errors as degraded state.

Consequences: The dashboard reflects current source-system state and remains
honest during outages. Historical alert browsing depends on investigation records
until a separately justified retention design exists.

## 2026-08-23 - Deterministic triage before model integration

Context: The first alert analysis workflow must be useful and testable before
provider credentials, prompt policy, and full evidence collectors are introduced.

Decision: Milestone 2 creates durable investigations with evidence IDs,
hypotheses, next checks, and explicit limitations using normal code only. Known
workload alert types select bounded collection guidance but remain low-confidence
until resource, event, metric, and log evidence is collected.

Consequences: Watchdog can be classified confidently, while workload alerts
abstain from claiming root cause. Synthetic fixtures gate regression behavior and
include adversarial annotation text that must remain inert.
