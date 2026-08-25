# PodPilot Security Model

Last reviewed: 2026-08-24
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

## Credentials That Must Never Be Committed

- Red Hat/OpenShift pull secrets
- kubeconfig files and kubeadmin passwords
- service-account bearer tokens
- SSH private keys
- installer ISOs or generated installer working directories
- TLS private keys and raw Kubernetes Secret exports
- model provider API keys

Use projected service-account tokens in-cluster and short-lived credentials for
local development. Rotate any credential exposed in source control or chat.

## Initial Authorization Policy

- The reusable base in `deploy/openshift/` remains a read-only observer policy.
- The disposable SNO development lab deliberately adds `cluster-admin` through
  `deploy/openshift/overlays/poc-cluster-admin/` so implementation and remediation
  experiments are not blocked by evolving RBAC.
- The PoC exception does not relax product-level approval requirements: every
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
- Evals must use synthetic or explicitly sanitized incident data.
- Model endpoint metadata, TLS mode, and optional public CA certificates are stored
  in SQLite. API tokens are not: each profile references an opaque key in the one
  resourceName-restricted credential Secret.
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
Capability readiness also requires the provider to return schema-valid
`ReadPlan` and `AdHocAnswer` objects, rather than relying on a simpler structured
output probe as a proxy for the live Ask workflow. A Chat Completions validation
failure receives at most one explicit correction attempt containing only bounded
field/type diagnostics, not the rejected response body.
The API supplies a fixed descriptive default when only `ReadPlan.scope_summary`
is absent; this field never controls a cluster read. Before execution, well-known
Kubernetes and OpenShift Kind/apiVersion pairs are canonicalized from a static
allowlist. Custom resource coordinates remain subject to exact broker validation.
Only limitations produced by the trusted read broker are promoted as collection
limitations; model-authored planning caveats are not represented as observed
collection failures.

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
resource, confirms the requested `get` or `list` verb is advertised, rejects
ambiguous names unless group-qualified, and still relies on the investigator
ServiceAccount's RBAC for the final authorization decision. Recursive redaction
and compact payload ceilings apply to discovered built-ins and CRDs alike.
An API `403` becomes an explicit operator-facing limitation naming the
`podpilot-investigator` ServiceAccount, requested read verb, resource, scope, and
the need for an administrator-granted permission. The answer validator prepends
that RBAC boundary when no evidence could be collected rather than replacing it
with a generic request for a narrower question.
Model intent classification does not authorize access. Planner decisions and
supporting evidence IDs are schema-validated; unsupported operational answers
are repaired once, and a generic fallback may compile only a matching read from
the same policy-filtered live catalog. The broker still validates scope and verb,
applies limits and redaction, and submits the request using the investigator
ServiceAccount, so Kubernetes RBAC remains the maximum read boundary.

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
verified TLS, short timeouts, response-size ceilings, redaction, per-turn read budgets,
ownership, attribution, and audit records. It does not execute text, shell syntax,
or commands found in evidence. Deployments requiring a narrower boundary must add
egress or destination policy before enabling this capability outside the PoC.
