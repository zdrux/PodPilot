# PodPilot Security Model

Last reviewed: 2026-08-27
Update when: identities, permissions, model data flow, storage, telemetry, or remediation scope changes.

## Trust Boundaries

- Cluster objects, events, logs, annotations, and alert text are untrusted data and may contain prompt injection.
- Model output is untrusted advice and never authorization.
- Chat Markdown is parsed with raw HTML disabled. Template output is marked safe
  only after parser escaping and link-scheme validation; model and operator text
  cannot inject script or trusted HTML through chat formatting.
- The API is the policy enforcement point for tool scope, budgets, redaction, and future user authorization.
- OpenShift RBAC is the hard ceiling on cluster capability.
- Monitoring access remains read-only and split by platform API: the Thanos API
  uses `cluster-monitoring-view`, while Alertmanager uses the namespaced
  `openshift-monitoring/podpilot-alertmanager-api-view` Role.
- OpenShift Logging remains read-only through `cluster-logging-application-view`,
  `cluster-logging-infrastructure-view`, and `cluster-logging-audit-view`. The application
  tenant supplies aggregate namespace-volume evidence. The audit tenant supports bounded
user-activity queries through a server-owned LogQL template; the model may extract only the
optional username, period, result limit, operation scope, and outcome filter. Omitting the
username requests matching activity across all users; a supplied username is matched exactly and
case-insensitively after regex escaping. PodPilot persists only projected audit fields—not raw
lines, request objects, or response objects. Infrastructure and audit access add investigation
visibility but no mutation authority.

The audit LogQL pipeline parses and filters those typed fields in Loki, then applies a server-owned
`line_format` projection containing only the bounded audit ID, timestamp, username, verb, object
reference, and response code. Raw request and response objects are therefore excluded before the
Loki response crosses the network; `query_range` uses newest-first direction and the requested
result limit over the filtered compact lines.

An omitted audit period is not interpreted as a one-hour evidence boundary. The broker expands a
bounded initial window until the requested result count is satisfied or the configured maximum
range is reached. Follow-up inheritance uses only the prior server-validated audit projection and
accepts a strict duration-only override; it does not derive a new username from chat prose.

## Credentials That Must Never Be Committed

- Red Hat/OpenShift pull secrets
- kubeconfig files and kubeadmin passwords
- service-account bearer tokens
- SSH private keys
- installer ISOs or generated installer working directories
- TLS private keys and raw Kubernetes Secret exports
- model provider API keys
- remote-cluster bearer tokens

Use projected service-account tokens in-cluster and short-lived credentials for
local development. Rotate any credential exposed in source control or chat.

## Initial Authorization Policy

### Explicit unrestricted agent exception

`deploy/openshift/overlays/sno-milestone-one/` and the optional
`deploy/openshift/overlays/remote-poc-agentic/` deliberately enable
`PODPILOT_AGENT_MODE=unrestricted` and add a localhost-only `oc-runner` sidecar. In this mode a
Chat Completions model may execute arbitrary Bash and `oc` commands without PodPilot's read
schemas, mutation preview, or approval workflow. This is an explicit test fixture, not a production
security boundary. The base and standard `remote-poc` overlays remain guarded. The remote agentic
overlay adds no RBAC of its own and therefore exercises every permission already granted to
`podpilot-investigator` on that target cluster.

High-confidence and schema-valid semantic questions may additionally run through the existing
registered deterministic known-read, metric, audit, and catalog-grounded resource compilers before
the shell loop. Those reads retain their normal fixed query construction,
normalization, redaction, evidence persistence, and bounded presentation. They provide trusted
product enrichment—such as Loki application-log byte rankings—but do not remove or constrain the
agent's arbitrary shell tool.
Registered-source failures are authoritative only as failures: the model may not infer that an
add-on, API, or resource is absent from an unavailable adapter. If neither a registered reader nor
a successful shell verification produces evidence, normal code replaces the model prose with the
exact redacted collection failures.
Conversely, a successful terminal registered enrichment is authoritative for its declared scope.
The unrestricted loop does not execute a competing shell tool call in that turn, avoiding both
duplicate output and unnecessary command execution after the bounded source answered the request.

For the runtime cluster, the runner uses the Pod's `podpilot-investigator` service account, not `ai-observer`, and the SNO
deployment helper fails before building if that identity can patch Deployments. Remote operators
must perform the equivalent authorization review before applying the optional agentic overlay. Cluster RBAC and
admission therefore remain the authoritative execution boundary. For a selected registered remote
cluster, the API reads only that cluster's token and brokers it over Pod loopback for one command.
The runner writes a mode-0600 per-command kubeconfig under `/tmp` and deletes it after execution;
the broker never places the token or kubeconfig in the model tool schema, command, result, or logs.
This is not container-level credential isolation: the unrestricted sidecar shares the Pod service
account, whose RBAC can read the two resourceName-restricted credential Secrets, and can inspect its
projected token. Output redaction is defense in depth, not a guarantee against a model deliberately
transforming secret bytes. Command text, target cluster, and exit status are
audited. A bounded redacted stderr summary is retained only for failed commands; full shell output
is secret-pattern redacted before it is returned to the provider and is not persisted as evidence.
Normalized deterministic enrichment is persisted as
evidence under the existing policy. Cluster output remains untrusted data and may contain
prompt injection. The runner binds only to Pod loopback, runs non-root with a read-only root
filesystem and dropped capabilities. Runner logs contain target identity, TLS mode, exit code,
duration, timeout state, and byte counts, never tokens, command text, stdout, or stderr. The runner
also reports whether either stream was truncated. It continuously drains both streams but retains
only the configured bounded prefix (256 KiB each by default), preventing verbose output from being
buffered without limit. Periodic idle and in-flight heartbeat log messages are suppressed; health
probes, command lifecycle events, and deadlines remain authoritative. Every shell process group is terminated at the
configured command deadline; the API has a slightly longer loopback HTTP deadline and the durable
Ask job retains its outer deadline.

Even with read-only RBAC, arbitrary shell execution can consume Pod resources, inspect files
readable by the runner container, and make allowed network requests. Do not enable this overlay on
a production cluster or compose it with `poc-cluster-admin`.

- The reusable base in `deploy/openshift/` remains a read-only observer policy.
- The disposable SNO development lab deliberately adds `cluster-admin` through
  `deploy/openshift/overlays/poc-cluster-admin/` so implementation and remediation
  experiments are not blocked by evolving RBAC.
- Outside the explicitly enabled unrestricted SNO fixture above, the PoC exception does not relax
  product-level approval requirements: every
  proposed mutation must show its target, patch or command, risks, and rollback,
  then require a fresh explicit approval.
- Production packaging must not install the PoC overlay. It should use separate
  read and action identities with a small action allowlist.

Milestone 10 separates the normal runtime from the break-glass exception. The
`ai-ops/podpilot-investigator` ServiceAccount runs the application and is bound to
OpenShift `cluster-reader`; `ai-ops/ai-observer` retains the disposable lab
cluster-admin overlay only for development access. Ask PodPilot permits bounded
resource, ConfigMap, and Pod-log reads through an application broker, while denying
Secrets, access-review resources, exec/attach/port-forward/proxy paths, and every
mutation. Because `cluster-reader` is aggregated, release checks audit its effective
permissions as well as the broker policy.

Cluster audit queries use the same Ask authorization boundary: Investigator, Approver, and
Breakglass roles may request them; Viewer may not. Human application roles do not receive direct
Loki credentials or RBAC. The runtime ServiceAccount performs the read through its existing
`cluster-logging-audit-view` binding.

Model diagnostics follow the existing conversation and model-management authorization boundaries.
An Ask turn stores only normalized call metadata and token counts; it does not store provider request
bodies, response content, authorization headers, or credentials. The conversation owner sees this
metadata in a collapsed control. Model capability probes are Approver-only, use fixed synthetic
inputs, and may store a redacted 4,000-character response preview so schema failures can be diagnosed.
Only the latest probe trace is retained on each profile and saving new profile settings clears it.

Pod-log autonomy does not give the model a free-form log client. Pod LIST evidence
creates bounded opaque candidate IDs for exact observed namespace/Pod/container
tuples. The broker resolves those IDs, rejects invented names before a Kubernetes
request, and caps deterministic fallback fan-out at three candidates within the
existing per-turn budget. Candidate rejection does not widen ServiceAccount RBAC;
a subsequent Kubernetes `pods/log` 403 remains an explicit RBAC limitation.

Standalone conversations are authorization-scoped to their immutable
`created_by` OpenShift username. Other users receive a not-found response and do
not see the conversation in history, including users with a higher PodPilot role.
Only the owner can continue or delete it. Deletion removes messages and retained
evidence but preserves an audit record containing the conversation ID and actor,
not message content. A per-user rate limit applies across all of that user's
conversations.

Standalone Ask conversations also pin an immutable cluster-ID selection. The browser
cannot change routing on a continuation request. Normal code loads only those registered
entries, refuses disabled or missing targets, reads each opaque bearer token immediately
before use, and attributes retained evidence to the source cluster. Remote tokens are
stored only in `ai-ops/podpilot-cluster-credentials`; SQLite and API responses contain
only opaque keys. RBAC restricts the runtime to `get`, `patch`, and `update` that exact
Secret and does not allow Secret creation or enumeration. Cluster create, update, token
rotation, connection test, and disable operations require Approver-or-higher, CSRF, and
content-free audit metadata. Disabling removes the Secret key but preserves historical
conversation and evidence attribution.

Remote Kubernetes API TLS verification defaults on in portable and guarded deployments. An Approver may explicitly disable
certificate and hostname verification for one registered cluster. This is a
credential-bearing exception: a network attacker can impersonate the API server, steal
the bearer token, and alter evidence. The management page warns before use, the registry
stores the exception, connection tests audit it, and every affected Ask run adds an
operator-visible limitation. The `remote-poc-agentic` overlay is an explicit broader lab exception:
it sets `PODPILOT_REMOTE_CLUSTER_TLS_VERIFY=false`, forcing registered remote readers and runner
commands in that deployment to skip certificate and hostname verification. The management page
displays the environment override. This does not change model-provider or ordinary application TLS
policy and should not be used in production.

Each Ask turn is an owner-scoped persisted job. Status and Server-Sent Event
endpoints return not found to every identity except the conversation creator,
regardless of that user's higher PodPilot role. Progress records contain bounded
server-authored phase labels and target summaries, never provider reasoning,
tokens, prompts, raw logs, or response bodies. A conversation with an active job
cannot accept another turn or be deleted. The browser reconnects with its existing
same-origin OAuth session; the API rechecks ownership before opening the stream.

## Model Data Policy

- Minimize collected fields before redaction.
- Remove tokens, authorization headers, credentials, private keys, cookies,
  connection strings, Secret values, and other configured patterns.
- Preserve provenance through stable object references and timestamps, not raw credentials.
- Do not retain raw evidence by default until retention and deletion rules are defined.
- Raw final-answer provider output is retained only when the conversation owner enables
  it for that question. Capture is limited to four redacted 16 KiB answer bodies, including
  provider/schema and PodPilot correction attempts; prompts and intermediate reasoning are
  never included. The output remains owner-scoped, is deleted with the conversation, is
  rendered as escaped text, and has no authority as evidence or an action.
- Evals must use synthetic or explicitly sanitized incident data.
- Model endpoint metadata, TLS mode, and optional public CA certificates are stored
  in SQLite. API tokens are not: each profile references an opaque key in the one
  resourceName-restricted credential Secret.
- Remote cluster origins, tags, and TLS mode are stored in SQLite. Their bearer tokens
  are not: each cluster references an opaque key in the separate fixed
  `ai-ops/podpilot-cluster-credentials` Secret.
- The OAuth-protected GUI sends a new token once to FastAPI. The runtime uses its
  projected ServiceAccount identity to patch only that Secret key, never returns
  the value, and rereads it before inference. Kubernetes Secret `data` is base64
  encoding, not application-level encryption; cluster encryption-at-rest and
  Secret-access controls remain administrator responsibilities.
- `insecure` TLS mode is an explicit PoC compatibility escape hatch. It disables
  server certificate and hostname verification, so a bearer token and model data
  can be intercepted. Prefer system trust or a custom CA and do not enable this
  mode for production endpoints.
- `plaintext` transport is a separate explicit exception for model workloads
  reached directly through Kubernetes Service DNS. It accepts only
  `service.namespace.svc` and `service.namespace.svc.cluster.local` HTTP hosts;
  external HTTP names, IP addresses, embedded credentials, and mismatched
  transport selections are rejected. Traffic and bearer tokens are still
  unencrypted inside the cluster, so production deployments should prefer HTTPS,
  NetworkPolicy, and a trusted service certificate.

## Curated Memory Policy

Cluster memory accepts only Approver-curated Markdown or text and redacts common
secret patterns before persistence. Every immutable version records its source,
owner, cluster and optional namespace/resource scope, verification state,
sensitivity, review time, optional expiry, and checksum. Audit events retain IDs
and metadata but not document content.

Only current, enabled, reviewed, unexpired versions are retrievable. Normal code
applies global, explicit-cluster, required-tag, and namespace filters before ranking;
restricted entries require
the Approver role. Search text is converted to a bounded quoted FTS expression,
so operators and cluster-derived text cannot supply SQLite FTS instructions.
Retrieved memory remains untrusted guidance rather than live evidence. Ask planning
and answering receive eligible internal chunks annotated with their applicable cluster;
memory cannot define a tool, authorize a read, support a live-state citation, or enter
investigation/remediation workflows in this release.

## OpenShift Authentication And Application Roles

PodPilot places an OAuth-aware proxy in front of its Route, accepts identity only
from that proxy, and maps authenticated identities and selected OpenShift groups
to application permissions. A
remote cluster uses its existing identity provider; the disposable SNO lab uses
its local `podpilot-htpasswd` provider.

| Configured role | PodPilot permission |
| --- | --- |
| Any authenticated OpenShift user | Viewer: view health, alerts, investigations, collected evidence, and audit history |
| Investigator groups | Start analyses and use investigation-scoped chat |
| Approver groups | Approve registered low/moderate-risk actions |
| Breakglass groups | Enter future high-risk approval workflows; no direct cluster-admin grant |

The GUI RoleBinding admits the built-in `system:authenticated` group to the exact
PodPilot Service. The application defaults authenticated users to Viewer, accepts
multiple existing LDAP-synchronized OpenShift Groups for each elevated role, and
assigns the highest match. Human users
do not receive `cluster-reader` or mutation RBAC; the application records the
authenticated actor separately from its runtime ServiceAccount.

The Route and Service expose only the OAuth proxy. FastAPI listens on Pod loopback,
so clients cannot directly forge `X-Forwarded-User`. The proxy does not forward
access tokens or bearer tokens upstream, uses secure same-site cookies, and
performs a SubjectAccessReview for `get` on the `ai-ops/podpilot` Service before
granting access. The API reads only configured elevated-role Group objects; no
Group lookup is required to assign Viewer.

OpenShift usernames may contain colons, including virtual users and service-account
identities. PodPilot accepts that identity syntax. A valid proxy-authenticated
identity without an elevated mapping receives Viewer; a missing or invalid proxy
identity remains an authentication failure (401).

Milestone 3 introduced one state-changing application operation: creating a local
investigation record. It requires Investigator-or-higher application role and a
same-site double-submit CSRF token. The server re-reads the active Alertmanager
fingerprint instead of accepting alert content from the browser. Alert labels,
annotations, events, status messages, image references, and bounded Pod logs are
secret-pattern redacted before investigation persistence and treated as untrusted
evidence; no model receives them. Secret resources and pull-secret contents are
never read by the workload collector.

Milestone 4 permits Approver-or-higher users to update one fixed model-credential
Secret through a dedicated settings endpoint. RBAC limits `get`, `patch`, and
`update` to `ai-ops/podpilot-model-credentials`; it cannot create or enumerate
Secrets. The browser may submit a replacement token over the protected Route, but
the server never returns it, stores it in SQLite, includes it in audit details, or
sends it to model prompts. Model profile save and probe operations require the
same-site CSRF token and create audit events. Provider errors are normalized to
type and HTTP status without response bodies that may echo sensitive material.
Operational logs record provider-probe and Ask workflow phase/outcome metadata.
For schema failures they may include only bounded Pydantic field locations and
error types; tokens, prompts/questions, response bodies, and evidence are never
logged.

Normalized alert and workload evidence is framed as untrusted JSON for every
model call. Responses must pass PodPilot's Pydantic schema and remain advisory;
they cannot register or execute actions. `store=false`, bounded timeouts, disabled
SDK retries, and output-token limits apply to both probes and investigations.
Capability readiness also requires the provider to return schema-valid discovery
`ReadPlan`, candidate-selection `CandidateReadPlan`, and `AdHocAnswer` objects, rather than relying on a simpler structured
output probe as a proxy for the live Ask workflow. A Chat Completions validation
failure receives at most one explicit correction attempt containing only bounded
field/type diagnostics and static cross-field `ReadIntent` rules, not the rejected response body.
If that correction remains invalid after an initial valid no-read stop, only an independently
compiled exact coordinate from the operator request may seed the existing recovery anchor; no
field from the malformed intent is executed or used as a target.
The API supplies a fixed descriptive default when only `ReadPlan.scope_summary`
is absent; this field never controls a cluster read. Before execution, well-known
Kubernetes and OpenShift Kind/apiVersion pairs may be canonicalized, while all resources,
including installed CRDs, are resolved against live API discovery and the verb advertised
there. The broker has no per-resource operational allowlist. It retains a small explicit
denylist for Secrets, token/identity/access-review resources, and all subresources; selected
coordinates also remain subject to ServiceAccount RBAC and strict read-only verb validation.
Only limitations produced by the trusted read broker are promoted as collection
limitations; model-authored planning caveats are not represented as observed
collection failures.

Evidence relationship graphs and capability ledgers are deterministic, bounded projections of
already-redacted observations and server-known broker state. They remain server-side; the planner
receives only compact evidence, opaque action labels, and a bounded policy-filtered readable API
catalog. Graph frontier hints, structured
investigation gaps, model-authored prose, and cluster content remain non-executable.
The capability classifier may additionally receive up to 24 opaque references for non-Secret exact
objects already present in that redacted relationship graph. A model-selected reference ID is bound
server-side to the retained kind, namespace, and name and still passes live discovery, deny, RBAC,
and read-only broker validation; model-authored replacement coordinates are not trusted.
For related collection queries, the model may select a separate parent scope ID and a syntactically
valid Kubernetes label key. Server code supplies the label value exclusively from the selected trusted
parent name, carries its namespace into the LIST, rejects parent names that cannot be label values, and
retains the existing result ceiling and broker checks. The model cannot author or replace that value.
Suggested-check buttons are
compiled only from unread server-owned candidates and are scoped to the source assistant message and
conversation owner. Their CSRF-protected endpoint reloads the persisted descriptor, verifies the
conversation cluster and read-only capability, rejects mutation language, and lets the unchanged
broker rederive and authorize the exact action. The browser cannot submit a target, namespace, tool
payload, Secret read, or mutation. A linked evidence-extension run excludes prior chat history and
summary from model context while retaining bounded, redacted supporting evidence.
For ordinary traversal, server code holds each
typed intent and exposes only an opaque candidate ID plus a redacted description. Unknown, modified,
or stale IDs are rejected; candidate prose is never parsed for coordinates. The model may return a
schema-valid candidate selection or author up to three object-only discovery, GET, LIST, or field-search
reads. Model-authored Pod-log, Secret, identity/token/access-review, subresource, probe, metric, watch,
command, and mutation requests are outside this compact schema. Every authored object read is
independently checked for normalization, duplicate suppression, budget, resource sensitivity,
read-only verb, live discovery, scope, and ServiceAccount RBAC before execution. Goal pinning
and no-progress repair do not widen that authority.
The final-answer schema contains only narrative and citations. It cannot authorize or describe a
clickable action. Normal code independently selects remaining unread server-owned candidates for
display, and strips provider recommendation-schema tails from narrative Markdown. Names, namespaces,
URLs, JSON fields, mutations, and other final-answer prose are never retained as an intent; only the
planner's schema-valid object-read fields can enter broker validation.
The sole URL-probe exception is an absolute HTTP/HTTPS URL copied exactly from the operator request;
normal code validates it and retains the typed intent server-side. Healthy Pod-log candidates are
exact namespace/Pod/container tuples derived from collected Pod evidence and are exposed only when a
structured log gap makes them relevant. Both still pass budget, deny, read-only, redaction, and audit policy.

Bounded Pod logs are untrusted evidence. Deterministic log-signal classification
matches fixed operational patterns only; it never executes, evaluates, or follows
instructions found in log text. Samples, paths, endpoints, and timestamps are
bounded and pass through the existing redaction boundary. Findings are supplied to the
planner as optional evidence-derived candidates; they do not automatically cause Pod, Event,
log, or configuration reads. Any continuation must be returned as a typed plan and independently
pass grounding, budget, sensitivity, verb, and RBAC checks. Pattern matches are signals and do
not establish causality without corroborating evidence.

Model-planned `watch` is time- and event-bounded and uses only Kubernetes watch semantics;
it does not create a long-lived background monitor. Discovery, get, list, search, logs,
metrics, probes, and watch consume weighted units within one 25-unit turn. Broader discovery
does not grant broader authorization: an HTTP 403 is retained as a scoped collection
limitation, not treated as permission to try a different API with similar names.

Final-answer context uses a compact copy of already-redacted evidence; compaction never
modifies the durable observation or expands model exposure. The correction path reuses
the same compact context and adds only a fixed validation code and bounded instruction;
it never includes the rejected model response or additional evidence. Deterministic fallback content is built solely
from persisted summaries and stable evidence IDs and cannot initiate new reads or actions.
An empty Chat Completions content field receives one schema-only correction. If the final provider
call still fails after successful reads, PodPilot returns a cited deterministic answer from those
persisted observations instead of discarding them; the provider status and failure remain visible.
Answer-time capability wording is checked against the server ledger. Calling an actionable,
unattempted check "unavailable" causes one bounded correction; collection failures and RBAC denials
remain visible and are never rewritten as successful evidence.

## PoC Storage Exception

The SNO overlay uses a static node-local PV at `/var/mnt/podpilot`. It is acceptable
only on this disposable single-node development cluster. It has no storage-level
encryption, capacity enforcement, HA, snapshot, or backup guarantee. Model tokens
remain in an OpenShift Secret and must never be written to SQLite. Production must
use a supported CSI-backed block volume, backups, retention controls, and tested
restore procedures.

## Remediation Boundary

The PoC may execute approved changes through its cluster-admin identity. The
orchestrator must still require explicit human approval, re-read resource versions
before applying, prefer server-side dry-run, record before/after state, enforce
timeouts, and present rollback. Production must use a separate action service and
identity with a small allowlist rather than cluster-admin.

Milestone 5 enables the first workload-mutation endpoint only for two registered
types: `delete_controller_owned_pod` and `restart_workload_rollout`. Proposals are
derived from normalized live evidence and are never accepted from model or browser
payloads. Each stores exact UID/resourceVersion preconditions and expires after ten
minutes. Creation performs a server dry-run. Execution requires Approver-or-higher,
same-site CSRF, an atomic single-use claim, and a second explicit UI confirmation.

Immediately before mutation the executor re-reads the target and fails stale if
UID, resourceVersion, or Pod controller changed. Pod deletion uses Kubernetes
delete preconditions and applies only to crash-looping controller-owned Pods.
Its preview carries `dryRun: ["All"]` in `DeleteOptions` as well as the API
query parameter, covering OpenShift DELETE dry-run compatibility without relying
on a client-side simulation.
Rollout restart uses a fixed `podpilot.io/restartedAt` template annotation and
supports only Deployment, StatefulSet, and DaemonSet. Every attempt records the
actor, preview, approval, operation result, before/after identities, and bounded
verification. Shell, arbitrary YAML/patches, Secrets, RBAC, nodes, system-namespace
targets, and model-created tools remain non-executable.

Milestone 6 treats a preview as revocable state rather than durable authority.
An investigation creator may cancel but cannot execute it. Dashboard
reconciliation infers resolution only from a complete bounded Alertmanager
snapshot; truncated or unavailable snapshots neither cancel nor authorize.
Approval independently rechecks that source fingerprint and fails closed when it
cannot be proven active. A separate read-only target validation classifies exact
identity as current, stale, missing, or unavailable. Only stale or missing closes
the preview automatically; transient Kubernetes failures leave it unapproved and
visible for retry.

Milestone 7 does not give the model Kubernetes credentials or a generic tool
channel. Normal code selects check types and exact namespace/Service scope from a
normalized alert. The browser submits only an investigation ID, and an
Investigator role plus same-site CSRF is required. The API atomically claims at
most `PODPILOT_DIAGNOSTIC_MAX_CHECKS` queued records and invokes a fixed read-only
executor. Service selectors influence only bounded API LIST filters; cluster
text is redacted and returned as evidence, never evaluated as instructions.
Check failures are durable and do not fall through to shell, retries, broader
scope, Secrets, active probes, or mutation.
The reusable observer role adds only read access to `discovery.k8s.io`
`EndpointSlices`; Service, Pod, and Event reads were already part of its evidence
ceiling. No new mutation or Secret permission is introduced.

Milestone 8 keeps chat on the same evidence and authorization side of the trust
boundary. Operator text and conversation history are untrusted, redacted, and
bounded before a provider call. Incident chat can invoke the same schema-validated
read-plan broker as standalone Ask, but the provider receives neither Kubernetes
credentials nor a generic execution channel. Normal code canonicalizes, bounds,
deny-checks, executes, redacts, persists, and audits every proposed read. Secrets,
access reviews, arbitrary subresources, commands, and mutations remain unavailable.
The typed HTTP probe is an explicit exception to the former active-probe boundary:
it sends only unauthenticated HEAD or bounded GET requests, follows no redirects,
validates TLS, and records the logical Host/SNI name separately from an optional
TCP connection override. Structured output distinguishes evidence-based,
general-guidance, and insufficient-evidence answers. The API—not the model—validates
citation IDs against persisted observations and withholds uncited factual claims.
A missing structured citation may be recovered only from an exact observation ID
present in both the provider answer text and the allowlisted evidence supplied for
that request. Partial or invented IDs remain uncited, and the internal marker is
removed before display.
A deterministic contradiction guard additionally prevents a TLS-stage certificate
failure or sidecar-only log evidence from being presented as proof that an
application backend serves plain HTTP. The evidence drawer renders only the same
persisted redacted observation payloads and normalized facts already inside this
boundary. Jinja autoescaping remains enabled, raw cluster HTML is never trusted,
and bounded log excerpts retain the collector's existing size and redaction limits.
When current-turn Pod logs exist, the API makes a separate structured provider request that
contains only the redacted operator question, bounded log coordinates/excerpts, and evidence
IDs; it supplies no conversation history or credentials. Log text remains untrusted input.
Normal code allowlists returned citations and rejects a model-quoted supporting excerpt unless
it occurs in the cited supplied log text after whitespace normalization. The analysis is shown
as a potential issue rather than authoritative evidence or root cause.
Trust-only TLS failures may trigger one identical probe with verification disabled;
the retry remains unauthenticated, carries no credentials, preserves Host/SNI, is
bounded by the normal read budget, and records the identity-verification limitation.
Proxy certificate-error findings may inform a model-selected exact Pod, owner, Event, or
configuration read when its target is grounded in server-observed coordinates or explicit
object references. Log text alone never supplies a callable target, Secret reads remain denied,
and the resulting finding is evidence rather than an instruction or root-cause claim.
A `run_queued_checks`
proposal cannot call the executor; it renders a separate button backed by the
existing Investigator, same-site CSRF, server-owned plan, atomic claim, and audit
controls. Chat audit events contain IDs, modes, citations, bounded read targets,
limitations, intent name, and counts, not message bodies or evidence payloads.

Dynamic API discovery does not expand this execution boundary. The provider sees
only a policy-filtered catalog of resource names, Kinds, scope, and apiVersions;
it does not receive discovery credentials or callable clients. Secret, OAuth
token, identity, user/group, access-review, and every subresource entry are
removed before planning. The broker independently resolves the selected plural
resource, confirms the requested `get`, `list`, or `watch` verb is advertised, rejects
ambiguous names unless group-qualified, and still relies on the investigator
ServiceAccount's RBAC for the final authorization decision. Recursive redaction
and compact payload ceilings apply to discovered built-ins and CRDs alike.
ConfigMap LIST evidence contains metadata only. After an exact broker-authorized ConfigMap GET, the
final-answer model may receive at most a small bounded projection of `data`; recursive sensitive-key and
value redaction runs before that projection. When the operator explicitly asks to show configuration,
PodPilot may automatically GET a bounded number of exact same-namespace ConfigMaps whose names were
observed in the structured spec of an exact source object. This relationship traversal cannot infer names,
does not apply to Secrets, and remains subject to broker policy, RBAC, read budgets, and redaction. Secret
objects remain denied regardless of references or RBAC.
An API `403` becomes an explicit operator-facing limitation naming the
`podpilot-investigator` ServiceAccount, requested read verb, resource, scope, and
the need for an administrator-granted permission. The answer validator prepends
that RBAC boundary only when the answer remains uncited and insufficient. Unrelated denied reads remain
visible as limitations without replacing a supported answer. When no evidence could be collected, the
validator preserves the blocking boundary rather than replacing it with a generic request for a narrower
question.
Model intent classification does not authorize access. Planner decisions and
supporting evidence IDs are schema-validated; unsupported operational answers
are repaired once. If both initial plans stop before collecting evidence, a
recovery may compile one read only from a single exact coordinate already present
in the operator request; it cannot choose a generic catalog target or continue a
server-authored traversal. The broker still validates scope and verb, applies
limits and redaction, and submits the request using the investigator ServiceAccount,
so Kubernetes RBAC remains the maximum read boundary.

Relationship traversal does not grant the model a general Kubernetes query interface. Normal code
derives bounded graph edges only from observed owner references, typed object-reference structures, and
registered selector contracts with known target Kinds. The provider sees opaque relationship IDs and
descriptive coordinates but never the retained read hints. A selected forward or reverse edge is rebound
to the server-retained exact name or complete selector, resolved through the safe live catalog, deduplicated,
and charged against the normal hop/read budget. Unknown free-form strings, inferred names, Secret targets,
cross-namespace owner guesses, and model-authored field paths or selectors cannot create executable edges.

Milestone 9 treats Prometheus label values as untrusted selectors, not query text.
The server owns both supported PromQL expressions and
JSON-escapes exact-match values. Thanos access uses the projected service-account
token, the OpenShift service CA, a fixed service URL, bounded timeout, 64 KiB body
limit, and series cap. Responses are shape-validated and redacted. The model and
browser cannot submit PromQL. The later ad-hoc HTTP probe deliberately allows any
absolute HTTP/HTTPS destination selected by the model, including values derived
from untrusted cluster evidence. This is an SSRF-shaped capability accepted for
the operator-oriented environment: the workload currently has no egress-deny
NetworkPolicy, so reachable internal and external endpoints are in scope. Risk is
bounded by a typed method set, no credentials or custom headers, no redirect following,
verified TLS by default, short timeouts, response-size ceilings, redaction, per-turn read budgets,
ownership, attribution, and audit records. It does not execute text, shell syntax,
or commands found in evidence. Deployments requiring a narrower boundary must add
egress or destination policy before enabling this capability outside the PoC.

Ad-hoc metric trends preserve the same boundary: the model selects only an enumerated
metric and typed scope/time parameters. Kubernetes coordinates are syntax-validated, and
server code owns every PromQL metric name, label, function, and aggregation. The browser and
model never receive the projected token or a generic PromQL field. Range responses must be
matrices and remain bounded by time, points, series, bytes, timeout, and redaction policy.
Deployment and node membership are derived from server-owned kube-state-metrics joins, not
model-provided selectors. Namespace, Deployment, and node consumer rankings expose only
already-authorized monitoring labels and must be described as container/Pod attribution.
Kafka, ingress, MachineConfigPool, HPA/workload, storage, ClusterOperator, API server, scheduler,
etcd, Prometheus/Alertmanager, and LokiStack
capability packs use the same registered-template boundary. The provider may select only enumerated
signals, typed groupings, and an exact target or opaque ID from server-supplied recent object
references. Normal code rebinds opaque IDs to retained coordinates and rejects invented target
names, namespaces, cross-Kind references, unsupported signal/scope combinations, and attempts to
route explicit telemetry questions through inventory. Exporter absence produces a limitation; it
never relaxes the boundary to model-authored PromQL.
Unknown CRDs stay on the generic discovery/object/relationship broker unless a reviewed metric
profile is registered. Neither CRD discovery nor a model guess can promote an arbitrary series name,
label matcher, unit, or aggregation into executable telemetry.
No node shell, `/proc` access,
host PID inspection, privileged DaemonSet, or process-level credential is introduced.
Namespace log-volume rankings preserve the typed metric boundary. The model selects only the
registered metric, period, and limit; server code owns LogQL and authenticates to the LokiStack
gateway. Responses are capped and reduced to namespace/byte aggregates, with no log lines returned
or persisted. Cluster-wide Loki authorization can technically permit raw queries, so production
deployments should isolate this credential behind PodPilot and restrict direct gateway access.
Operator-authored periods are parsed only into bounded integer seconds and never become LogQL text.
Projected Route destination names are treated only as observed Kubernetes object references
eligible for the existing exact read broker. They do not authorize mutation, arbitrary name
construction, credential access, or traffic to a new destination.
For private, self-signed, or component-managed certificates, a model may explicitly
select `tls_verify=false` on one HTTPS troubleshooting probe. SNI remains enabled, the
bypass is persisted and displayed as a limitation, and the observation establishes only
reachability/protocol behavior—not authenticated server identity. This exception never
applies to Kubernetes API, model-provider, credential-bearing, or default application TLS.

Bounded resource search does not grant a query language or raw API access. Normal code
allows only validated dot-separated object field paths, scans at most the configured ceiling, returns a small
match set, applies the existing sensitive-kind deny policy, and redacts the evidence.

Concurrent Ask execution remains bounded inside one application Pod. The default pool has three
workers and allows at most two running jobs per user, preventing one operator from occupying the
entire pool when another user's work is queued. Conversation ownership, status/SSE authorization,
per-user submission rate limits, ContextVar-scoped raw-response capture, read budgets, provider
timeouts, and ServiceAccount RBAC apply independently to every run. Raising concurrency increases
model cost and Kubernetes/provider request pressure and must not be treated as expanded authority.
