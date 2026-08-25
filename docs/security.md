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

Standalone conversations are authorization-scoped to their immutable
`created_by` OpenShift username. Other users receive a not-found response and do
not see the conversation in history, including users with a higher PodPilot role.
Only the owner can continue or delete it. Deletion removes messages and retained
evidence but preserves an audit record containing the conversation ID and actor,
not message content. A per-user rate limit applies across all of that user's
conversations.

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
bounded before a provider call. Structured output distinguishes evidence-based,
general-guidance, and insufficient-evidence answers. The API—not the model—validates
citation IDs against persisted observations and withholds uncited factual claims.
The provider receives only an allowlisted intent name, never tool schemas,
Kubernetes clients, credentials, or arbitrary arguments. A `run_queued_checks`
proposal cannot call the executor; it renders a separate button backed by the
existing Investigator, same-site CSRF, server-owned plan, atomic claim, and audit
controls. Chat audit events contain IDs, modes, citations, intent name, and counts,
not message bodies.

Milestone 9 treats Prometheus label values as untrusted selectors, not query text
or network destinations. The server owns both supported PromQL expressions and
JSON-escapes exact-match values. Thanos access uses the projected service-account
token, the OpenShift service CA, a fixed service URL, bounded timeout, 64 KiB body
limit, and series cap. Responses are shape-validated and redacted. The model and
browser cannot submit PromQL. PodPilot does not resolve or connect to the alert's
`instance` value or the selected Service; doing so would let rule authors steer a
privileged workload toward arbitrary in-cluster endpoints. An active probe requires
an administrator-owned allowlist, destination pre-registration, dedicated no-token
identity, explicit egress policy, rate limits, and separate evaluation gates.
