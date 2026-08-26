# PodPilot Decisions

Last reviewed: 2026-08-26
Update when: a durable architecture or product-engineering decision is made or superseded.

## 2026-08-26 - Every current Pod-log read receives bounded semantic model analysis

Context: Deterministic keyword and regex classification can preserve known high-value log
signals and drive safe registered follow-ups, but it cannot scale to every application,
framework, or failure vocabulary. Sending the entire conversation again solely to interpret
logs would waste context and make attribution harder.

Decision: After bounded collection, every turn with successful Pod-log reads makes one separate
structured provider request containing all current redacted excerpts under a shared size cap,
the operator question, coordinates, and evidence IDs—without conversation history. The model
returns potential issues, severity, impact, confidence, citations, and a short supporting quote.
Normal code allowlists citations and requires each quote to occur in its cited excerpt before
rendering a **Model-assisted log analysis** section. The final-answer request receives the
validated analysis instead of duplicate raw tails, while deterministic log classification remains available for known safe
automatic follow-ups. Analysis failure is a visible limitation and does not fail the turn.

Consequences: Novel log failures can be surfaced without expanding an ever-growing regex list,
including application-specific errors. Model findings remain hypotheses rather than ground
truth, cannot authorize reads or mutation, and are bounded by the same redaction and evidence
provenance boundary as other provider calls. One additional provider request is incurred only
on turns that actually collect Pod logs.

## 2026-08-26 - Final answers require substance and bounded provider context

Context: A schema-valid `evidence_based` response could contain citations but only
a Markdown heading. Broader automatic log investigation also increased final-answer
context because persisted observations can contain large bounded log excerpts and
structured findings repeat their most material samples.

Decision: The API compacts provider-facing final-answer evidence independently of
persisted evidence. Current-turn observations are prioritized; log tails, strings,
lists, individual observations, findings, and the total encoded observation set have
explicit ceilings. Evidence-backed replies must contain a non-heading body. An answer
with headings but no readable body receives one correction
request containing only a bounded reason/message, never the rejected response body.
If correction remains incomplete, recognized Route/TLS or inventory answers use the
existing deterministic renderer; other questions receive a cited deterministic
observation summary. Concise answers are accepted, and inventory-only support is displayed
as an evidence limitation rather than causing otherwise readable prose to be discarded.
Regardless of model success or fallback, normal code appends a
bounded operator-facing log-finding section with exact Pod/container, category, severity,
occurrence count, paths/endpoints, sample, correlated checks, and evidence citations.
Semantically equivalent limitations are collapsed before display.

Consequences: Operators do not receive empty heading-only answers, small providers
receive a materially smaller final context, and complete persisted evidence remains
available through provenance. The fallback discloses that causal interpretation is
still unverified rather than inventing one. Readable answers are not vetoed by arbitrary
length, inventory-shape, or exhaustive-log-citation heuristics. Structured log signals cannot disappear when a
Route/TLS fallback replaces weak model prose, but remain explicitly labeled as correlation
rather than proven root cause.

## 2026-08-26 - Deterministic TLS retry and general bounded log-signal investigation

Context: Model planning permitted insecure troubleshooting probes and iterative
reads, but it could stop after a private-CA trust failure or overlook material
errors in application, init, or sidecar logs. A certificate-only Istio/Envoy rule
was too incident-specific to provide durable operational coverage.

Decision: Normal code repeats a trust-only verified HTTPS failure once with the
same bounded probe and `tls_verify=false`. Pod observations mark unready,
restarting, and non-running containers as prioritized exact log candidates; the
broker can inspect up to three within the existing budget. Bounded logs from any
container are classified into crash, resource, TLS, DNS, network, authorization,
storage, dependency, application-error, and warning signals. Findings retain
exact coordinates, occurrence/signature counts, timestamps, bounded samples,
paths, and endpoints. Material findings trigger exact Pod and Pod-Event reads;
crash/resource findings can also request previous logs. These continuations retain
all original evidence, carry no credentials, and never read Secrets. Model prompts
receive findings as untrusted summaries and must not infer causality without correlation.

Consequences: Private-CA endpoints can be tested through HTTP without hiding the
certificate warning, and broadly useful workload log signals receive immediate
configuration and Event context. Automatic reads remain deterministic, auditable,
deduplicated, capped, and inside `cluster-reader`; the feature does not add arbitrary
shell, exec, Secret, or network access.

## 2026-08-25 - Typed metric trends use server-owned PromQL

Context: Operators need pod, namespace, and volume trends over a requested period, but
model-authored PromQL would expand the evidence boundary and make cost, injection, and
cardinality controls difficult to enforce.

Decision: Add `query_metrics` to the bounded read broker. The model selects a registered
metric, typed scope, exact coordinates, period, and resolution; normal code compiles the
PromQL and calls authenticated Thanos `/api/v1/query_range`. The initial catalog covers CPU
usage/requests/limits/throttling, memory working set/requests/limits, network receive/transmit,
container restarts, PVC utilization, Pod readiness, Deployment aggregation, and namespace,
Deployment, or node top CPU/memory container consumers. Deployment scope joins
Deployment-to-ReplicaSet-to-Pod ownership at query time. Namespace ranking uses an exact
namespace selector; node scope joins Pod metrics to `kube_pod_info`. Both retain monitored
namespace/Pod/container series and do not claim visibility into arbitrary host processes.
Common namespace top-consumer wording compiles directly to the typed query so a model schema
failure cannot prevent this basic bounded investigation.
Separate node-exporter templates report overall node CPU and memory utilization so PodPilot
can disclose when ranked workload containers do not explain total node pressure.
Default policy permits 30 days and
300 points per series, with a 90-day and 1,000-point configuration maximum. The existing
series, response-byte, timeout, TLS, redaction, ServiceAccount, and read-budget controls apply.

Consequences: Ask PodPilot can answer bounded trend questions without exposing tokens or a
generic PromQL endpoint. Query availability still depends on OpenShift monitoring retention
and metric presence, and configured requests/limits must not be described as measured usage.
Host process attribution requires a separate process exporter, eBPF agent, or privileged
node diagnostic capability and is not implied by `cluster-reader`.

## 2026-08-25 - Projected resource search and explicit troubleshooting TLS mode

Context: Ordinary LIST evidence is intentionally capped, but operators often identify
an object by a projected field rather than its Kubernetes name. Route hostnames are a
common example. Private, self-signed, and component-managed certificates also make a
verified network probe unsuitable for some reachability and passthrough-SNI tests.

Decision: Add `search_resources`, which follows Kubernetes pagination while comparing
a validated dot-separated object field path and returns at most the requested matches. The scan has
a separate 2,000-object default and 5,000-object hard configuration maximum. Compile an
operator-supplied Route URL deterministically into an exact `spec.host` search. Add an
explicit `tls_verify=false` option to unauthenticated HTTPS probes. Verification remains
the default, SNI remains the URL hostname, and every bypass is recorded in evidence and
operator-visible limitations. The exception does not apply to Kubernetes, model-provider,
or other credential-bearing transport.

Consequences: Route-host and backend-Service lookup no longer depends on which 250 objects
fit ordinary inventory evidence. Insecure probes can demonstrate reachability and SNI
behavior with internally issued certificates, but cannot establish server identity.
The planner may select fields below metadata, spec, or status as needed; normal code rejects
malformed paths and retains the existing resource deny policy and scan/result ceilings.
When multiple API groups expose the same plural, supplied `apiVersion`/`Kind` coordinates
disambiguate and must agree with discovery. OpenShift ingress/browser Route questions use
`routes.route.openshift.io`; Knative Routes are selected only for explicit Knative/Serving
questions. Discovery ambiguity or coordinate mismatch is rejected before consuming a read.
Projected OpenShift Route destinations (`spec.to.name` and alternate backends) are accepted
as observed Service names by the grounding guard. Route TLS questions receive a deterministic
cited interpretation of edge, reencrypt, passthrough, or unsecured behavior so a later planner
failure cannot discard directly relevant Route evidence. The interpretation states
configuration, not live reachability or the origin of an HTTP 500.

## 2026-08-25 - Broader agentic reads and SNI-aware HTTP probes

Context: Three planning rounds and six Kubernetes-only reads were too brittle for
cross-resource OpenShift investigations. Later malformed plans also discarded usable
evidence. Operators need direct reachability observations for Routes and Services,
including passthrough Route SNI behavior.

Decision: Allow up to five rounds and twelve reads, derive the plan decision from
typed content, and continue to the answer phase after any planner-contract failure.
Add an unrestricted-destination `http_probe` intent to the same bounded broker. It
supports unauthenticated HEAD/GET, verified TLS, no redirects, bounded/redacted output,
and a connection override that preserves the URL hostname as HTTP Host and TLS SNI.
Arbitrary shell and model-authored headers, credentials, bodies, and mutations remain
unavailable. This decision's prohibition on model-selected TLS bypass is superseded by
the explicit, evidence-visible troubleshooting mode above.

Consequences: PodPilot can actively cross-check object configuration against network
behavior and test passthrough Routes against a chosen router address. This introduces
an accepted SSRF-shaped read capability wherever workload egress permits; production
deployments that do not accept that reachability must add an egress or destination
policy. Probe failures remain evidence rather than generic provider failures.

## 2026-08-23 - Broad reader identity and brokered ad-hoc investigation

Context: Alert-specific packs cannot cover the long tail of ordinary cluster
questions. Logs and ConfigMaps are necessary operational evidence, while the model
must not receive Kubernetes credentials or an unrestricted client.

Decision: Run the application as `ai-ops/podpilot-investigator`, bind it to the
OpenShift `cluster-reader` ClusterRole, and retain `ai-observer` as the disposable
lab break-glass identity. Ask PodPilot uses schema-validated, bounded
`get_resource`, `list_resources`, and `pod_logs` intents. Normal code denies
Secrets, access-review resources, subresources, commands, and mutations and
validates evidence citations before displaying cluster-specific claims.

Consequences: Novel APIs can be investigated without waiting for a capability
pack, while packs remain the gate for deterministic remediation. The application
cannot execute existing remediation proposals until a separate action executor
identity is implemented. `cluster-reader` aggregation and model-data redaction
must be audited at release time.

## 2026-08-23 - Private, unlimited managed conversations

Context: A fixed question count interrupts legitimate incidents, while globally
visible conversations disclose operational context across users. Unlimited raw
model context and unbounded rendering would create separate cost and performance
problems.

Decision: Pin every standalone conversation to its creating OpenShift username
and enforce that ownership for history, reads, continuation, and deletion. Remove
the hard turn count. Preserve continuity with ten recent messages and a bounded
durable digest of older content, while keeping per-turn read/token limits,
per-user request throttling, bounded evidence, and bounded UI rendering. Deletion
removes conversation content but leaves a content-free attribution audit event.

Consequences: Conversations are private rather than team-shared. A future sharing
feature must be explicit and separately authorized. Starting a new conversation
is recommended when the operational target changes, but it is never forced by a
question counter.

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

Status: The group-gated GUI admission portion was superseded on 2026-08-24 by
authenticated-user Viewer access. The named Investigator, Approver, and
Breakglass groups remain lab elevation fixtures; the Viewer group was removed.

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

## 2026-08-24 - SQLite model registry with per-profile Secret keys

Context: The lab must switch between public OpenAI and internal compatible
gateways without changing manifests or restarting the Pod. Provider catalogs use
both Responses and Chat Completions conventions, and internal endpoints may use a
private CA.

Decision: Replace the singleton with a SQLite registry of endpoint metadata and
one active, successfully probed profile. Keep bearer tokens out of SQLite. Each
profile owns an opaque data key in the fixed, resourceName-restricted OpenShift
Secret; the API patches that key and rereads it for every inference. Support
Responses and strict-schema Chat Completions adapters plus system trust, custom
CA, and an explicitly unsafe PoC-only TLS mode.

Consequences: Endpoint and token changes do not require a rollout. Deleting an
inactive profile also removes its Secret key; an active profile cannot be deleted.
Chat Completions compatibility now means more than accepting the URL: the probe
must prove authentication, selected-model access, and strict structured output.
TLS bypass remains visible as accepted, never as verified.

## 2026-08-25 - Plain HTTP is limited to direct Kubernetes model Services

Context: Internal model inference is sometimes available only over an HTTP
Kubernetes Service. Forcing its external Route adds router timeouts and an
unnecessary cluster-internal hairpin, while allowing arbitrary plaintext URLs
would expose bearer credentials outside the intended trust boundary.

Decision: Add an explicit `plaintext` model transport that accepts only
`service.namespace.svc` or `service.namespace.svc.cluster.local` URLs. Keep HTTPS
as the default and reject external HTTP hosts, IP literals, embedded credentials,
and mismatched scheme/transport combinations.

Consequences: PodPilot can reach an in-cluster model Service without an OpenShift
Route, but prompts and credentials are unencrypted on that network path. Operators
must use NetworkPolicy and should migrate production endpoints to trusted TLS.

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

## 2026-08-24 - Portable remote PoC uses default dynamic storage and split RBAC

Context: The local static PV, node-specific security context, HTPasswd users,
integrated-registry build, and cluster-admin helper are unsuitable for a cluster
with real workloads.

Decision: Add one remote Kustomize entry point that composes the portable base,
group-based GUI access, and single-replica workload. Existing LDAP-synchronized
OpenShift Groups are mapped through deployment-configured JSON arrays; PodPilot
does not create or update Group membership. The GUI RoleBinding admits the union
of those groups to the exact Service. Build the root Dockerfile
externally and deploy an immutable digest. Omit `storageClassName` so the target's
default CSI class provisions the PVC. Keep human exact-Service GUI permission as
namespace-local RBAC, attach `cluster-reader` and monitoring access only to the
runtime ServiceAccount, and define the named Alertmanager API Role explicitly in
`openshift-monitoring`.

Consequences: The remote path has no node, local-path, lab-hostname, HTPasswd, or
cluster-admin dependency. Cluster administrators still must audit the aggregated
`cluster-reader` role and default StorageClass on every target. SQLite remains a
single-replica PoC persistence choice, not an HA production database.

Status: The immutable remote image selection was superseded for this PoC by the
versioned internal ImageStreamTag decision below. Digest pinning remains the
production recommendation.

## 2026-08-24 - Authenticated users default to Viewer

Context: Repeating the same LDAP group names in both the OAuth proxy admission
RoleBinding and application-role configuration creates avoidable drift. The PoC
is intended for a cluster whose authenticated users may view shared operational
evidence, while investigation and remediation workflows still require explicit
elevation.

Decision: Bind the namespace-local exact-Service GUI Role to OpenShift's built-in
`system:authenticated` group and assign Viewer to every proxy-authenticated user.
Keep one deployment-configured mapping only for Investigator, Approver, and
Breakglass groups. PodPilot continues to read group membership without creating
or synchronizing groups, and highest-role precedence remains deterministic.

Consequences: Any authenticated cluster identity can open PodPilot and view its
cluster-wide findings, including collected logs and ConfigMap evidence. This is
an explicit PoC disclosure boundary. Human identities still receive no direct
cluster-reading or mutation RBAC, and all non-Viewer operations remain protected
by application authorization, CSRF, typed-action, approval, and audit controls.

## 2026-08-24 - Remote PoC deploys a versioned internal ImageStreamTag

Context: The target OpenShift cluster already provides its integrated registry,
and PoC operators prefer a readable ImageStreamTag over editing a digest into the
remote Kustomization. The external registry Route used by a workstation is not the
appropriate pull hostname for in-cluster Pods.

Decision: Create the `ai-ops/podpilot` ImageStream in the remote overlay. Push
versioned tags through the registry's external Route, but render the Deployment
image as `image-registry.openshift-image-registry.svc:5000/ai-ops/podpilot:<tag>`.
Select the version through Kustomize `newTag`; do not duplicate the full Deployment
as a second installation path.

Consequences: Promotion and rollback use human-readable versioned tags and require
no external-registry pull Secret. Tags are mutable, so operators must publish a
new tag for each build. Reusing a tag requires an explicit Deployment restart and
provides weaker provenance than a digest-pinned production release.

## 2026-08-24 - Read investigations resolve resources from safe API discovery

Context: Maintaining apiVersion/Kind mappings for every common OpenShift object
and installed operator CRD does not scale, while allowing a model to invent raw
API coordinates or invoke a generic Kubernetes client weakens the trust boundary.

Decision: Cache the cluster's served API resources for five minutes, remove
Secrets, identity/token/access-review resources, and all subresources, and expose
only bounded catalog metadata to planning. Plans select plural resource names.
Normal code resolves the current stable served version, group collision,
namespaced scope, and advertised `get`/`list` verb before using the dynamic client.
Explicit inventory questions compile directly from the same catalog. List results
follow continue tokens but persist compact kind-aware projections under object and
payload ceilings.

Consequences: Core Kubernetes, OpenShift, and installed CRD reads no longer need a
handwritten domain pack merely to collect evidence. RBAC remains the final access
ceiling, provider output remains non-executable data, and remediation still
requires separately reviewed typed actions, preconditions, approval, and
verification. Newly served APIs may take up to five minutes to enter the catalog.

## 2026-08-25 - Natural-language planning is model-first with bounded repair

Context: Exact phrase matching cannot cover normal operator language, but blindly
accepting a model's empty plan can withhold evidence even when live discovery
contains an obvious safe target.

Decision: Require the model to classify the goal and explicitly choose collection,
evidence-backed answer, or clarification. Reject unsupported operational answers
and retry planning once with structured feedback. If a policy-filtered live
catalog match proves that a safe inventory or health read is available, compile
that read after a second refusal. Keep exact built-in planners only for a few
high-confidence compatibility and alert-scoped paths.

Consequences: Operators can use natural language without a growing static object
list. The model selects intent but never receives execution authority; discovery,
broker validation, limits, redaction, ServiceAccount RBAC, persistence, and
citation enforcement remain server-owned.

## 2026-08-25 - Ask turns use durable single-worker jobs and server-owned progress

Context: Holding one browser request open through discovery, multiple cluster
reads, and model inference provides little feedback, is vulnerable to Route and
client timeouts, and loses visible state on navigation. Streaming model tokens
would not explain which trusted server actions actually occurred.

Decision: Persist every Ask turn before execution and process queued turns with
one in-process worker in the single-replica SQLite deployment. Publish durable,
owner-authorized SSE events only for server-observed phases and exact bounded-read
activity. Requeue interrupted work at startup, allow one active turn per
conversation, and commit the final assistant message and terminal job state in
one transaction. Keep the final model call schema-validated and non-token-streamed.

Consequences: Operators get immediate, reconnectable progress and Route requests
no longer wait for the full model workflow. The design intentionally supports one
application replica; horizontal workers require a database-backed claim/lease
design beyond SQLite. A crash may repeat a read-only inference job, but cannot
perform cluster mutations, and terminal reply persistence remains atomic.

## 2026-08-25 - Pod logs bind to exact evidence-derived candidates

Context: Iterative planning could successfully list Pods and then lose autonomy
because a model synthesized invalid Pod names for `pod_logs`. The broker correctly
rejected them, but each proposal consumed a read slot and the final response
looked like logs were unavailable rather than a planner-target failure.

Decision: Retain a separately bounded namespace/Pod/container projection in Pod
list evidence and assign opaque candidate IDs. Require planners to select those
IDs whenever available, validate before accounting a cluster read, retry invalid
selection once, and then allow a server-owned fallback across at most three
question-relevant candidates. Previous logs require both explicit operator intent
and an observed restart hint.

Consequences: Common discover-then-log investigations recover from weak model
target selection without wider RBAC or arbitrary log access. Candidate creation,
binding, fan-out, budget accounting, redaction, and error classification remain
deterministic. The compact candidate projection has its own payload ceiling, so a
very large Pod inventory can still require narrower scope.

## 2026-08-25 - Curated memory begins with deterministic lexical retrieval

Context: PodPilot needs basic operator tribal knowledge, while available model
profiles may expose Chat Completions without an embedding endpoint. Allowing the
model to decide whether or how to search would make recall inconsistent and would
let untrusted context influence retrieval policy before provenance is established.

Decision: Store immutable, metadata-rich knowledge versions and heading-aware
chunks in SQLite, using FTS5/BM25 for deterministic lexical retrieval. Normal code
owns eligibility, cluster/namespace/sensitivity filters, query tokenization, and
result limits. Approvers curate memory and Investigators can preview retrieval.
Keep this first slice out of model prompts until a distinct knowledge-citation
contract and retrieval evaluations exist.

Consequences: Useful exact operational terminology is searchable without an
embedding service or new database. Revisions remain auditable and stale or
out-of-scope entries fail closed. Semantic reranking and answer-time augmentation
remain optional later layers; neither may expand collection or remediation policy.

## 2026-08-25 - Traffic-path traversal is deterministic and bounded

Context: Route investigations depended on the model producing a valid multi-round
Route-to-Service-to-Pod plan. A malformed later ReadPlan stopped collection before Pods
existed, so generalized log analysis could not run and the final answer fell back to shallow
Route configuration. Healthy backend Pods were also excluded from automatic logs even though
an application can return HTTP 500 while remaining Ready.

Decision: For Route, HTTP 5xx, and connectivity questions, derive an automatic read graph from
observed Kubernetes relationships: Route to exact Service, Service selector to bounded Pods,
and Service to EndpointSlices and Endpoints with compact Pod targets. Inspect current logs from
at most three relevant backend containers regardless of health, then apply the existing general
signal correlations. Keep every continuation inside the shared read budget and allow it to
complete even when a subsequent model planning call is malformed.

Consequences: Basic traffic-path evidence no longer depends on model schema reliability, while
the model still prioritizes optional investigation branches. The traversal remains read-only,
evidence-derived, deduplicated, redacted, RBAC-limited, and capped; it does not become a generic
cluster crawler or claim that log correlation proves causality.

## 2026-08-26 - Ask conversations pin a bounded multi-cluster selection

Context: Operators need one Ask surface for remote OpenShift clusters and comparisons, while
historical answers must remain attributable and cluster changes must not silently reuse prior
context. Remote bearer tokens cannot enter SQLite or browser responses.

Decision: Register the runtime cluster plus Approver-managed remote API origins and exact tags.
Store remote tokens as opaque keys in a dedicated resourceName-restricted Secret. Pin an ordered
one-to-ten-cluster selection when a conversation is created; changing selection creates another
conversation. Fan out within one shared twelve-read ceiling and attribute evidence, activity,
limitations, and citations to the source cluster. Keep alerts, investigations, dashboard health,
remote metrics, and remediation on the runtime cluster. TLS verification defaults on, but an
Approver may explicitly disable certificate and hostname verification for one registered remote
API; persist, display, and audit that credential-interception exception.

Consequences: Comparisons are possible without mixing identities or deleting history, and partial
cluster failures do not erase successful evidence. The insecure TLS option is a deliberate
credential-bearing risk and is unsuitable for production. Multi-cluster remediation and remote
monitoring require separate designs.

## 2026-08-26 - Curated memory eligibility precedes Ask augmentation

Context: The lexical-memory foundation is ready to inform Ask, but environment-specific guidance
must never leak to unrelated clusters or be mistaken for observed state.

Decision: A knowledge version may target explicit clusters, require an all-matching key/value tag
set, or leave both empty for global scope. Explicit and tag eligibility use OR semantics. Normal
code filters current, enabled, reviewed, unexpired, namespace-compatible, nonrestricted chunks
before planning or answering. Prompts label each chunk as untrusted guidance and name its
applicable cluster. Memory cannot define tools, authorize reads, or support current-state citations.

Consequences: Azure, bare-metal, and other environment knowledge can coexist with portable
guidance in one index. Restricted entries remain previewable only by Approvers and never enter Ask
workers. This supersedes the 2026-08-25 preview-only restriction while retaining deterministic
retrieval and provenance boundaries.

## 2026-08-26 - Adaptive read-only traversal uses weighted units and transient plan summaries

Context: A twelve-read investigation could exhaust its budget after finding an initial clue, and
the fixed catalog slice made unfamiliar operator APIs difficult to traverse. Operators also had
little feedback while a longer investigation was active.

Decision: Allow up to ten planning rounds within 25 weighted investigation units and reserve five
units for server-derived correlations. Discovery/get/list/search cost one unit, logs/metrics/HTTP
probes cost two, and a watch costs three. Let the planner query live Kubernetes discovery and use
any resource advertising `get`, `list`, or `watch`; retain the small sensitive-resource and
subresource denylist, exact-coordinate validation, redaction, bounded payloads, and ServiceAccount
RBAC. Bound watches to 15 seconds and 50 compact events. Permit structured `working_hypothesis`
and `next_step_summary` fields and stream those alongside server-observed findings in a six-item
journal that exists only while the spinner is active. These fields are concise operator status,
not hidden chain-of-thought. Let incomplete final answers recommend precise next checks and retry
once when the provider declines to interpret evidence PodPilot already collected.

Consequences: Investigations can follow Authorino and other installed-operator clues without a
maintained CR allowlist, while Secrets, identity/token/access-review APIs, subresources, mutation,
and unavailable RBAC remain outside the broker. Longer runs provide useful progress without
cluttering completed chat history. This supersedes the five-round/twelve-read ceiling in the
2026-08-25 broader-agentic-reads decision and the shared twelve-read ceiling in the 2026-08-26
multi-cluster decision.

## 2026-08-26 - A bounded worker pool enables concurrent users on SQLite

Context: Durable Ask jobs were processed by one coroutine, so different users could submit work
but their investigations ran serially. The current PoC must remain a single application replica
with SQLite while allowing a small operator team to investigate at the same time.

Decision: Run three configurable in-process Ask workers and allow at most two running jobs per
user by default. Each worker claims the oldest eligible queued run with the existing conditional
status update; one active turn per conversation remains mandatory. Configure SQLite connections
for WAL mode, `synchronous=NORMAL`, and a 30-second busy timeout, and keep transactions short.
Retain one API Pod and the block-backed PVC. Excess or per-user-saturated work stays queued and
starts automatically. Increase the API container resource envelope for concurrent inference and
evidence processing.

Consequences: Several users can run independent read-only investigations concurrently without a
new service, while one user cannot consume every default worker. Model-provider and Kubernetes API
load can now overlap and must be capacity-tested. This is not horizontal scaling: multiple API
replicas, robust crash leases, or sustained write concurrency still require PostgreSQL and an
atomic cross-process claim design. This supersedes the one-worker limit in the 2026-08-25 durable
Ask-job decision while preserving its persistence, ownership, and recovery rules.

## 2026-08-26 - Troubleshooting traversal is model-directed inside a fixed broker boundary

Context: Server-authored Route, traffic, log, Event, and configuration continuations made common
incidents reliable, but they also steered diagnosis toward a preconceived graph and could consume
the budget before the model pursued a competing hypothesis. Final recommendations were display
strings rather than evidence actions, and a useful cited unresolved answer was rejected whenever
any evidence existed.

Decision: Keep the ten-round, 25-unit safety envelope and every existing broker enforcement rule,
but make troubleshooting and object traversal model-directed. Only terminal unambiguous inventory
and metric requests retain deterministic compilation. Findings, selectors, endpoint targets,
owner references, and mount relationships are supplied as optional candidates; the model must
return a typed intent for every diagnostic hop. Normal code grounds explicit owner, Route,
endpoint, Pod-candidate, and volume-backed references, while arbitrary text remains non-callable.
The only automatic continuation is an identical trust-only HTTPS retry. After two initial no-read
plans, normal code may also recover with one safe read compiled from a single exact coordinate in
the operator request, such as searching Route `spec.host` for a supplied URL; subsequent traversal
returns to the model. This is an availability recovery anchor, not a generic catalog fallback or a
server-authored diagnostic graph. Set the default reserved follow-up units to zero. Treat answer
grounding separately from certainty: a cited interpretation is evidence-based and may carry an
unresolved conclusion, while uncited refusals and structurally empty answers still receive one
correction attempt.

Consequences: The model can change direction as evidence arrives and use the full default budget
without gaining credentials, arbitrary tools, Secret access, mutation, or authority over the
broker. Malformed plans still stop or retry visibly instead of silently invoking a diagnostic
graph; repeated no-read plans can no longer turn an exact operator-supplied target into an empty
investigation. Provider quality remains visible because the recovery is logged and limited to one
grounded read. This supersedes the server-derived
correlation reserve and deterministic diagnostic continuations in the adaptive-traversal,
traffic-path, cross-namespace-policy, and log-correlation decisions; their evidence normalization
and safety constraints remain in force.
