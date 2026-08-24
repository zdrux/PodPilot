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

## 2026-08-23 - Alert-scoped workload evidence before model analysis

Context: Crash-loop, image-waiting, and scheduling alerts cannot support a root-cause
claim from Alertmanager labels alone, while broad log or resource harvesting would
create unnecessary exposure and latency.

Decision: Milestone 3 selects one namespace and Pod from trusted alert-label fields,
collects bounded status and events, follows at most three controller links, and
adds only incident-specific evidence: targeted current/previous container logs for
crash loops, or bounded node capacity and taints for unscheduled Pods. Image-pull
diagnostics never read pull-secret values. All free text is redacted before it is
persisted or rendered.

Consequences: The three initial fixtures can graduate to evidence-backed diagnosis,
but alerts missing Pod identity remain low-confidence triage. Cluster collection
failures are explicit limitations, and model integration still consumes only the
normalized evidence contract rather than Kubernetes client objects.

## 2026-08-23 - Capability-gated model interpretation with deterministic fallback

Context: URL compatibility alone cannot establish that a provider supports the
Responses features PodPilot needs, and provider downtime must not erase useful
cluster evidence.

Decision: Milestone 4 stores one model profile in SQLite and one token in the
fixed `ai-ops/podpilot-model-credentials` Secret. Approver-or-higher users can
save metadata and explicitly probe TLS, authentication, model availability,
streaming, function tools, structured output, and optional embeddings. Only a
fully ready profile participates in investigations. The OpenAI adapter uses
`store=false`, no automatic retries, bounded time and output tokens, and returns a
PodPilot-owned Pydantic contract.

Consequences: Model text remains visually and operationally separate from facts
and cannot authorize tools. Outages produce an explicit model limitation while
the deterministic result remains usable. The base observer policy remains
read-only; the workload adds a narrow Role that can update but neither create nor
list exactly one credential Secret. Custom CA upload remains a later internal-
provider hardening increment.

## 2026-08-23 - Typed single-use remediation instead of generated commands

Context: The PoC service account has cluster-admin, but broad RBAC cannot make a
model-generated command safe. Approval must bind one actor to one exact observed
resource and one known operation.

Decision: Milestone 5 registers only controller-owned crash-looping Pod deletion
and Deployment/StatefulSet/DaemonSet rollout restart. Normal code derives targets
from normalized evidence, performs server dry-run, persists UID/resourceVersion
and a ten-minute expiry, and exposes no target or patch input in the approval API.
Approver-or-higher confirmation atomically claims the proposal once. The executor
re-reads identity, applies fixed Kubernetes calls, and verifies a genuinely new
Ready replacement or a completed observed rollout. Completing one proposal
cancels sibling previews.

Consequences: Arbitrary shell/YAML, standalone Pod deletion, node/system/Secret/
RBAC mutation, and model authorization remain impossible through the product.
Unresolved, stale, expired, and failed outcomes are durable rather than silently
retried. Production still needs a separate narrowly scoped action identity.

## 2026-08-23 - Remediation previews are revocable and continuously reconciled

Context: A ten-minute preview could remain visible after its alert resolved or
its exact target disappeared, encouraging an operator to approve stale intent.
Bounded Alertmanager responses can also be truncated, so absence is not always
proof of resolution.

Decision: Milestone 6 lets the investigation creator or an Approver explicitly
cancel without granting execution rights. It expires previews durably, cancels
them when a complete Alertmanager snapshot proves the source fingerprint is no
longer active, and uses read-only exact-target validation to close stale or
missing targets. Approval independently proves the alert is active. Truncated or
unavailable alert data fails closed and never implies resolution.

Consequences: Awaiting-approval counts converge without database intervention,
every closure is attributable, and fewer stale actions reach execution. Dashboard
and investigation reads may perform safe lifecycle writes, and target validation
adds bounded Kubernetes reads but no dry-run or mutation.

## 2026-08-23 - Server-owned diagnostic plans before model-selected tools

Context: Investigation pages exposed prose suggestions that neither PodPilot nor
the operator could execute from the workflow, while giving a model generic
Kubernetes or shell tools would undermine the policy boundary.

Decision: Milestone 7 persists a typed, server-selected read-only plan for
`TargetDown`. An Investigator starts the plan, normal code atomically claims and
executes registered Service-topology and Pod-event checks, and the model
reinterprets their normalized results. The browser and model provide no tool
names or targets. Existing compatible investigations are lazily backfilled.

Consequences: PodPilot now performs concrete follow-up investigation instead of
only printing advice, with deterministic usefulness during model outages. The
first pack does not yet offer free-form chat, model-selected tools, PromQL/rule
state, or active network probes; those require separate fixtures and policy gates.

## 2026-08-23 - Validate chat citations and tool intent on the server

Context: Follow-up chat is useful only if operators can distinguish grounded
incident facts from general advice, and if conversational requests cannot bypass
the registered diagnostic-plan boundary.

Decision: Milestone 8 persists attributed, investigation-scoped chat with a
structured provider response. The API intersects model citations with observation
IDs already stored on that investigation and withholds evidence-based answers that
have no valid citation. The model may propose only `run_queued_checks`, and only
while queued server-owned checks exist. The proposal is rendered as data; a
separate operator click calls the existing role-, CSRF-, scope-, claim-, and
audit-gated endpoint. Inputs, history, and output are redacted and bounded.

Consequences: Chat can explain evidence and invite further collection without
receiving credentials or executable tools. General guidance remains possible but
is labeled as such. The first version has no streaming, arbitrary tool selection,
cross-investigation memory, chat-driven mutation, or automatic execution.

## 2026-08-23 - Use passive Thanos evidence before active reachability probes

Context: `TargetDown` needs monitoring-path evidence after Kubernetes topology
looks healthy. A direct probe seems useful, but alert labels and rule annotations
are untrusted evidence and cannot safely authorize a destination for a
cluster-admin workload.

Decision: Milestone 9 adds only fixed, server-built Thanos instant queries for
matching `ALERTS` rule state and `up` scrape health. Exact label values are escaped;
the provider URL, query shapes, token source, CA, timeout, body limit, and series
limit are application policy. Existing two-check investigations receive only the
missing monitoring check when opened. No DNS, TCP, TLS, or HTTP request is sent to
the alert instance or selected Service.

Consequences: PodPilot can distinguish a currently down scrape target, recovered
target, and missing target series without an SSRF primitive. Active probing is
deferred until destinations are administrator-registered and enforced with a
dedicated no-token identity, egress policy, rate limits, protocol allowlist, and
fixtures for redirect, DNS-rebinding, link-local, control-plane, and Secret-service
denial.
