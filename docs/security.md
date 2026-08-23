# PodPilot Security Model

Last reviewed: 2026-08-23
Update when: identities, permissions, model data flow, storage, telemetry, or remediation scope changes.

## Trust Boundaries

- Cluster objects, events, logs, annotations, and alert text are untrusted data and may contain prompt injection.
- Model output is untrusted advice and never authorization.
- The API is the policy enforcement point for tool scope, budgets, redaction, and future user authorization.
- OpenShift RBAC is the hard ceiling on cluster capability.

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

## Model Data Policy

- Minimize collected fields before redaction.
- Remove tokens, authorization headers, credentials, private keys, cookies,
  connection strings, Secret values, and other configured patterns.
- Preserve provenance through stable object references and timestamps, not raw credentials.
- Do not retain raw evidence by default until retention and deletion rules are defined.
- Evals must use synthetic or explicitly sanitized incident data.

## PoC Authentication And Application Roles

The SNO lab uses the cluster's built-in OAuth server with the
`podpilot-htpasswd` identity provider. PodPilot places an OAuth-aware proxy in
front of its Route, accepts identity only from that proxy, and maps these OpenShift
groups to application permissions:

| Group | PodPilot permission |
| --- | --- |
| `podpilot-viewers` | View health, alerts, investigations, and audit history |
| `podpilot-investigators` | Start analyses and use investigation-scoped chat |
| `podpilot-approvers` | Approve registered low/moderate-risk actions |
| `podpilot-breakglass` | Enter future high-risk approval workflows; no direct cluster-admin grant |

The group hierarchy is expressed by placing higher-role test users in each lower
group. Human users do not receive mutation RBAC; the executor service account
performs approved changes and the application records the authenticated actor.

The Route and Service expose only the OAuth proxy. FastAPI listens on Pod loopback,
so clients cannot directly forge `X-Forwarded-User`. The proxy does not forward
access tokens or bearer tokens upstream, uses secure same-site cookies, and
performs a SubjectAccessReview for `get` on the `ai-ops/podpilot` Service before
granting access. The API then reads only the four configured Group objects to
derive the application role.

OpenShift usernames may contain colons, including virtual users and service-account
identities. PodPilot accepts that identity syntax but still denies access unless
the resolved user belongs to a configured PodPilot application-role group. A valid
upstream identity with no application role is an authorization failure (403), not
an authentication failure (401).

Milestone 3 retains only one state-changing application operation: creating a local
investigation record. It requires Investigator-or-higher application role and a
same-site double-submit CSRF token. The server re-reads the active Alertmanager
fingerprint instead of accepting alert content from the browser. Alert labels,
annotations, events, status messages, image references, and bounded Pod logs are
secret-pattern redacted before investigation persistence and treated as untrusted
evidence; no model receives them. Secret resources and pull-secret contents are
never read by the workload collector.
There are still no cluster mutation endpoints.

Milestone 4 permits Approver-or-higher users to update one fixed model-credential
Secret through a dedicated settings endpoint. RBAC limits `get`, `patch`, and
`update` to `ai-ops/podpilot-model-credentials`; it cannot create or enumerate
Secrets. The browser may submit a replacement token over the protected Route, but
the server never returns it, stores it in SQLite, includes it in audit details, or
sends it to model prompts. Model profile save and probe operations require the
same-site CSRF token and create audit events. Provider errors are normalized to
type and HTTP status without response bodies that may echo sensitive material.

Normalized alert and workload evidence is framed as untrusted JSON for every
model call. Responses must pass PodPilot's Pydantic schema and remain advisory;
they cannot register or execute actions. `store=false`, bounded timeouts, disabled
SDK retries, and output-token limits apply to both probes and investigations.

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
