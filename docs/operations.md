# PodPilot Operations

Last reviewed: 2026-08-24
Update when: setup, environment variables, deployment, external services, or runbooks change.

## Remote OpenShift PoC

Use [`remote-poc-deployment.md`](remote-poc-deployment.md) for a methodical
deployment on an existing OpenShift cluster. That path builds and pushes the root
`Dockerfile` as a versioned ImageStreamTag, pulls it through the integrated
registry's internal Service, requests storage from the target's default
StorageClass, uses existing OAuth identities, and applies only read-only runtime
and monitoring permissions. The local SNO sections below remain development-lab
procedures and must not be combined with the remote overlay.

## Local Setup

Prerequisites:

- `git`
- Python 3.12
- `oc` authenticated to a disposable development cluster
- network and DNS access to the OpenShift API and application routes

Never use or copy the installer workspace as an application configuration source.
Use a short-lived developer login locally and the projected service-account token in-cluster.

Create the development environment and run the model-free unit and synthetic
incident tests:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.lock
python -m pip install -e . --no-deps
python -m pytest --cov --cov-report=term-missing
```

Run a local schema migration against a disposable database:

```powershell
$env:PODPILOT_DATABASE_URL = 'sqlite:///./.data/podpilot.db'
python -m alembic -c apps/api/alembic.ini upgrade head
```

## Local SNO Login

Use the checked-in helper to turn the existing external administrator kubeconfig
into a short-lived PoC `ai-observer` kubeconfig with cluster-admin rights:

```powershell
. .\scripts\connect-sno.ps1
oc whoami
oc whoami --show-server
```

Expected results:

```text
system:serviceaccount:ai-ops:ai-observer
https://api.sno.192-168-0-200.sslip.io:6443
```

The leading dot is important: it dot-sources the helper so `KUBECONFIG` remains
set in the current PowerShell process. Codex commands normally run in fresh
shells, so future agents should connect and test in one invocation:

```powershell
. .\scripts\connect-sno.ps1; oc get clusteroperators
```

The helper:

- verifies that the bootstrap kubeconfig targets the expected SNO API
- requests a time-limited token for `ai-ops/ai-observer`
- writes the generated kubeconfig under the Windows temporary directory, outside Git
- validates the resulting identity and confirms the expected PoC cluster-admin permissions
- never prints either kubeconfig or token

Set the external bootstrap kubeconfig path for the current shell without copying
the file into this repository:

```powershell
$env:PODPILOT_BOOTSTRAP_KUBECONFIG = 'C:\secure\external\kubeconfig'
. .\scripts\connect-sno.ps1
```

Apply the PoC RBAC overlay to this disposable lab with:

```powershell
$env:KUBECONFIG = $env:PODPILOT_BOOTSTRAP_KUBECONFIG
oc apply -k deploy/openshift
oc apply -k deploy/openshift/overlays/poc-cluster-admin
```

Application integration tests should use the generated service-account identity,
not the external kubeadmin identity. Production packaging must use the read-only
base at `deploy/openshift/` and must not install the PoC overlay.

## PoC HTPasswd Users

The live SNO cluster has a `podpilot-htpasswd` OpenShift OAuth identity provider
and four test identities: `podpilot-viewer`, `podpilot-investigator`,
`podpilot-approver`, and `podpilot-breakglass`. Apply their application-role groups
and minimal UI-access RBAC with:

```powershell
oc apply --dry-run=server -k deploy/openshift/auth/poc-htpasswd
oc apply -k deploy/openshift/auth/poc-htpasswd
```

Initial random passwords are held temporarily in the untracked cluster Secret
`openshift-config/podpilot-test-user-credentials`. Retrieve an individual value
to the Windows clipboard without printing it:

```powershell
. .\scripts\connect-sno.ps1
.\scripts\copy-poc-user-password.ps1 -User podpilot-viewer
```

Delete the bootstrap Secret after all credentials have been recorded or reset:

```powershell
oc -n openshift-config delete secret podpilot-test-user-credentials
```

The durable
`podpilot-htpasswd` Secret contains only bcrypt password verifiers and must remain.

The HTPasswd provider authenticates users to OpenShift. The deployed OAuth proxy
protects the Route and supplies the authenticated username to the loopback-only
backend. Every authenticated user receives Viewer. Lab groups map the three
elevated roles; the remote overlay accepts arrays of existing LDAP-synchronized
groups for those roles.

The proxy issues a fixed eight-hour signed browser cookie and sets
`--cookie-refresh=0`. OpenShift's provider in the pinned proxy does not implement token renewal;
a non-zero cookie-refresh interval only revalidates the original access token. A one-hour refresh
therefore logs users out after approximately one hour on clusters whose OAuth access-token lifetime
is also one hour. Disabling that ineffective refresh keeps the browser session valid for its bounded
eight-hour lifetime and allows it to survive Pod or proxy restarts as long as the
`podpilot-oauth-cookie` Secret is unchanged. Explicit logout still clears the cookie. FastAPI
continues to resolve application roles from current configured Group membership.

The OAuth proxy uses the `podpilot-investigator` projected service-account token as its
OpenShift OAuth client secret. The workload requests an eight-hour token and snapshots the exact
value used by each proxy process into a proxy-only memory volume. Because the pinned proxy reads
its client secret only at startup, a foreground supervisor compares the projected file with that
snapshot every second. The supervisor owns the proxy child process directly, forwards container
termination signals, and exits as soon as kubelet rotates the token; this keeps the stale-secret
callback window below one polling interval and lets the container restart policy launch the proxy
with a fresh snapshot. Only the `oauth-proxy` container restarts; the API, SQLite state, and stable
OAuth cookie key remain in place. A periodic increase in that container's restart count accompanied
by `Projected OAuth client token rotated` is expected. Repeated
`unauthorized_client` callback failures without that message indicate that this rotation supervisor
is absent or unhealthy.

### Troubleshoot an interactive login loop

OpenShift OAuth can reuse an existing browser SSO session. If the PodPilot access
page identifies an account such as `kube:admin`, clearing only the PodPilot cookie
can cause OpenShift to select that same account again. This is an authorization
failure for the selected account, not an HTPasswd password failure.

Use a private browser window, or clear site data for both hosts before retrying:

- `podpilot-ai-ops.apps.sno.192-168-0-200.sslip.io`
- `oauth-openshift.apps.sno.192-168-0-200.sslip.io`

Then sign in as one of the four `podpilot-*` users. Use
`copy-poc-user-password.ps1` to copy that user's current lab password without
printing it. Do not repeatedly follow an access-error sign-in link: reused OAuth
callbacks can end at the proxy's generic 500 page even though the HTPasswd
provider and credentials are healthy.

## Environment Variables

- `PODPILOT_DELEGATED_ACCESS_ENABLED`; checked-in workload manifests set it to `true`, making
  user-owned tokens mandatory for Ask. The code-level `false` default remains for migration tests.
- `PODPILOT_DELEGATED_SESSION_LIFETIME_SECONDS`, workload default `86400`; bounds API-memory retention and the
  HttpOnly delegated-session cookie. It does not change the remote OpenShift OAuth token TTL.
- `PODPILOT_DELEGATED_LOGIN_TIMEOUT_SECONDS`, default `15`; bounds OAuth discovery, login, identity,
  and revocation calls.
- `PODPILOT_DELEGATED_LOGIN_ATTEMPTS_PER_MINUTE`, default `5`; process-local per-PodPilot-user
  throttling for multi-cluster credential submissions.
- `PODPILOT_DELEGATED_PROXY_TIMEOUT_SECONDS`, default `310`; bounds one brokered Kubernetes API
  request from the runner.
- `PODPILOT_DELEGATED_SYSTEM_API_URL`, default `https://kubernetes.default.svc`, and
  `PODPILOT_DELEGATED_SYSTEM_OAUTH_AUTHORIZATION_URL`, defaulting to the internal
  `oauth-openshift` service, are the verified in-cluster endpoints used when a delegated user
  selects PodPilot's system cluster. The API and service CA paths come from
  `PODPILOT_SERVICE_ACCOUNT_CA_PATH` and `PODPILOT_SERVICE_CA_PATH`.
- Users manage private entries and configuration administrators manage shared entries under
  **Clusters**. Save and run **Test OAuth discovery**; a tokenless entry reports successful
  TLS and OAuth discovery without asking for a user's credentials.
- Owners may permanently delete their private entries from **Clusters**. PodPilot deletes any
  stored credential and revokes live delegated connections before removing the registry entry;
  historical conversations remain available. Shared entries use **Disable** instead.

- `PODPILOT_AGENT_MODE`; checked-in workload manifests set `unrestricted` and deploy the runner.
  Conversation mode chooses the read-only collector or Action loop.
- `PODPILOT_AGENT_RUNNER_URL`, default `http://127.0.0.1:8090`; keep it on Pod loopback.
- `PODPILOT_AGENT_COMMAND_TIMEOUT_SECONDS`, default `300`; the runner terminates the complete shell
  process group at this deadline and returns exit code `124`.
- `PODPILOT_AGENT_COMMAND_MAX_OUTPUT_BYTES`, default `262144`; the runner continuously drains each
  command stream while retaining at most this many bytes from stdout and independently from stderr.
  Truncated results include an explicit marker, and logs retain the true byte count.
- `PODPILOT_AGENT_HEARTBEAT_SECONDS`, default `10`; controls silent runner polling and in-flight
  model/command progress updates persisted to the active Ask run. It does not emit periodic
  container-log heartbeat messages.
- TLS verification is stored per cluster. Users may disable certificate and hostname verification
  for private entries; configuration administrators make that choice for shared entries.

The current deployment uses these variables:

- `PODPILOT_ENVIRONMENT`
- `PODPILOT_CLUSTER_NAME`
- `PODPILOT_DATA_DIR`, `/var/lib/podpilot` in the SNO overlay
- `PODPILOT_DATABASE_URL`, `sqlite:////var/lib/podpilot/podpilot.db` in the SNO overlay
- `PODPILOT_AUTH_MODE=proxy`
- `PODPILOT_ROLE_CACHE_SECONDS`, default `30`
- `PODPILOT_ROLE_INVESTIGATOR_GROUPS`, JSON array defaulting to
  `["podpilot-investigators"]`
- `PODPILOT_ROLE_READ_WRITE_GROUPS`, JSON array defaulting to `["podpilot-read-write"]`
- `PODPILOT_CONFIGURATION_ADMIN_GROUPS`, an orthogonal capability array defaulting to
  `["podpilot-configuration-admins"]`
- `PODPILOT_ROLE_APPROVER_GROUPS`, JSON array defaulting to `["podpilot-approvers"]`
- `PODPILOT_ROLE_BREAKGLASS_GROUPS`, JSON array defaulting to `["podpilot-breakglass"]`;
  arrays may contain multiple existing groups or be empty, but the same group
  cannot map to more than one role; all arrays may be empty, leaving every
  authenticated user at Viewer
- the **Manage** navigation and its Clusters, Model settings, and Cluster memory
  pages are available only to users resolved as Approver or Breakglass; the API
  applies the same authorization to configuration reads and writes
- role-mapping environment changes require a Pod rollout; membership changes in
  an already configured OpenShift Group are observed after the role cache expires
- `PODPILOT_ALERTMANAGER_URL`, defaulting to the in-cluster
  `https://alertmanager-main.openshift-monitoring.svc:9094`
- `PODPILOT_SERVICE_ACCOUNT_TOKEN_PATH`, default projected token path
- `PODPILOT_SERVICE_CA_PATH`, default projected OpenShift service CA path
- `PODPILOT_ALERTMANAGER_TIMEOUT_SECONDS`, default `8`
- `PODPILOT_ALERTMANAGER_MAX_ALERTS`, default `250`
- `PODPILOT_THANOS_URL`, defaulting to the in-cluster
  `https://thanos-querier.openshift-monitoring.svc:9091`
- `PODPILOT_THANOS_TIMEOUT_SECONDS`, default `8`
- `PODPILOT_THANOS_MAX_SERIES`, default `20`, with a hard accepted range of
  `1` through `100`
- `PODPILOT_ADHOC_METRICS_MAX_RESPONSE_BYTES`, default `1048576` (1 MiB), with a
  hard accepted range of `65536` through `4194304` bytes
- `PODPILOT_LOKI_URL`, defaulting to
  `https://logging-loki-gateway-http.openshift-logging.svc:8080/api/logs/v1/application`
- `PODPILOT_LOKI_ROUTE_NAME`, default `logging-loki`, for registered remote clusters
- `PODPILOT_LOKI_TIMEOUT_SECONDS`, default `90`, with a hard accepted range of
  `1` through `120`
- `PODPILOT_LOKI_MAX_SERIES`, default `50`, with a hard accepted range of `1` through `100`
- `PODPILOT_ADHOC_LOGS_MAX_RANGE_SECONDS`, default `86400` (24 hours)
- `PODPILOT_ADHOC_AUDIT_INITIAL_RANGE_SECONDS`, default `3600` (one hour), is the
  first bounded window for a “last N” audit request without an explicit period; PodPilot
  expands that window backward until it finds N matches or reaches the configured ceiling
- `PODPILOT_ADHOC_AUDIT_MAX_RANGE_SECONDS`, default `86400` (24 hours)
- `PODPILOT_ADHOC_AUDIT_DEFAULT_LIMIT`, default `20`, used only when the operator does
  not supply a result count
- `PODPILOT_ADHOC_AUDIT_MAX_RESPONSE_BYTES`, default `1048576` (1 MiB), with a hard
  accepted range of 64 KiB through 4 MiB. This ceiling applies only to raw audit-tenant
  HTTP responses; persisted evidence still contains only the bounded safe projection.
- `PODPILOT_WORKLOAD_MAX_EVENTS`, default `30`
- `PODPILOT_WORKLOAD_LOG_TAIL_LINES`, default `200`
- `PODPILOT_WORKLOAD_MAX_LOG_BYTES`, default `16384` per collected log stream
- `PODPILOT_DIAGNOSTIC_MAX_CHECKS`, default `4`, with a hard accepted range of
  `1` through `10`
- `PODPILOT_CHAT_MAX_MESSAGES`, default `20`, counting both operator and assistant
  messages, with a hard accepted range of `2` through `50`
- `PODPILOT_CHAT_MAX_CHARS`, default `4000` characters per operator message, with
  a hard accepted range of `100` through `4000`
- `PODPILOT_MODEL_CREDENTIAL_STORE`, `environment` for local development or
  `kubernetes` in the OpenShift workload
- `PODPILOT_MODEL_SECRET_NAMESPACE`, default `ai-ops`
- `PODPILOT_MODEL_SECRET_NAME`, default `podpilot-model-credentials`
- `PODPILOT_MODEL_SECRET_KEY`, default `api_key`
- `PODPILOT_ROLE_READ_WRITE_GROUPS`, groups whose members may start Action-mode chats
- `PODPILOT_CONFIGURATION_ADMIN_GROUPS`, groups whose members may manage shared cluster metadata
- `PODPILOT_MODEL_TIMEOUT_MAX_SECONDS`, default `240`, controls the highest timeout
  an Approver may save on a model profile (configuration range `30`–`300` seconds)
- `PODPILOT_ADHOC_MAX_CLUSTERS_PER_CONVERSATION`, default `10`
- `PODPILOT_POC_MODE=true` for the lab-only runtime policy

Model profile metadata (API type, base URL, model names, available reasoning levels,
TLS mode/custom CA, capability hints, per-attempt timeout, transient retry count, and token budgets) is configured through
`/settings/model` and stored in SQLite. Local development reads `OPENAI_API_KEY`
without persisting it. In OpenShift, every profile has an opaque key in the fixed
Secret above. Saving a token sends it through the OAuth-protected HTTPS Route;
FastAPI patches only that key through the Kubernetes API using the runtime
ServiceAccount. The UI never reads the saved value back. Model calls reread the
key, so token creation and rotation require no Deployment restart.

Each model profile declares the explicit reasoning levels it supports and a default for
users who have not made a choice. **Provider default** is always available and omits the
reasoning parameter for compatibility with unknown or non-reasoning endpoints. Ask PodPilot
offers the configured levels beside the raw-response switch and persists each user's choice
per model across conversations. PodPilot snapshots that choice on a queued run and sends
`reasoning.effort` to the Responses API or `reasoning_effort` to Chat Completions. Capability
probes use the model profile's configured default. Supported values vary by model, so save the
profile and run **Test connection** after changing its available levels or default.
Because the provider's output-token limit includes hidden reasoning tokens, an explicit
effort uses the profile's full maximum-output budget instead of PodPilot's smaller
non-reasoning per-operation cap.

Each profile may also set an optional sampling temperature from `0` through `2`. A blank
value is **Provider default** and omits the parameter entirely, preserving compatibility
with endpoints that do not accept temperature. An explicit value is sent to classification,
planning, answer, analysis, and capability-probe calls through both supported API types.
Temperature `0` generally reduces sampling variation but is not a determinism guarantee;
providers may ignore or reject it, so test the profile after changing the value.

Each profile also sets **Transient retries**, default `3` and allowed range `0`–`10`. The OpenAI
client applies that retry count to timeouts, abrupt connection failures, rate limits, and transient
server responses. Authentication, validation, and ordinary client errors are not made successful
by retrying. The profile timeout applies per attempt; the durable Ask execution deadline remains
the outer limit for the complete agent run.

Completed Ask replies persist a bounded model-diagnostics record for the calls made during that
turn. The collapsed **Model usage** control beneath the PodPilot author rail shows aggregate input,
output, reasoning, cached, and total tokens when the provider reports them, plus the largest
single-call input. Aggregate usage measures processing across the turn; only the largest individual
request is relevant to context-window pressure. Compatible providers may omit some or all usage
fields, which PodPilot reports without estimating them.
PodPilot also records provider termination metadata when it is supplied: Chat Completions
`finish_reason`, or the Responses API's incomplete reason. The Ask page displays the distinct
values under **Model usage**, which makes output-budget truncation distinguishable from a
schema-valid but semantically incomplete answer.
The same disclosure lists the tools invoked for that reply, grouped by tool name with call and
status counts. This view uses persisted activity metadata only; commands, arguments, results, and
credentials are not added to model diagnostics.

When a structured model response fails validation, the same collapsed control shows a bounded
failure summary: failure category, schema, attempt number, and up to six validation field paths,
codes, and safe messages. Rejected values, prompts, authorization headers, and response bodies are
not stored in normal Ask diagnostics. Empty responses, timeouts, and provider failures remain
separate categories so the operator-facing recovery message does not incorrectly call every
planner failure malformed.

Ask answers are also checked for operator shell commands, dangling colons, and unclosed Markdown
code fences. A response that tells the operator to run
`oc` or `kubectl` receives one model correction attempt; if it remains unsafe, PodPilot replaces it
with a deterministic evidence summary. Declarative configuration guidance remains allowed.

**Test connection** is a compatibility smoke test, not a quality benchmark. It verifies the
endpoint, authentication, selected model, required transport capabilities, and that the production
workflow schemas can be parsed. It does not grade the model's synthetic investigation choices,
candidate selection, or citation strategy; practical quality is evaluated through normal Ask usage.
The test persists the latest bounded synthetic-probe trace on the model profile. The
collapsed **Request diagnostics** section includes the probe operation/schema, endpoint path, HTTP
status, duration, request ID, token usage, and a redacted response preview. It never stores request
bodies, authorization headers, API tokens, or complete HTTP headers. Response previews are enabled
only for the fixed synthetic capability probes, capped at 4,000 characters per response, and passed
through normal secret redaction.

Workflow-schema smoke-test failures remain informational and do not put an otherwise compatible
profile into `reduced_capability`. Ask does not display degraded-model warnings; connection-test
status and diagnostic details remain on Model settings for configuration administrators. Normal
code still validates every typed response and uses deterministic fallbacks during real
conversations. Profiles missing a required transport, endpoint, authentication, model,
structured-output, or configured embedding capability remain `reduced_capability` and may be
unavailable.

### Multi-cluster Ask and curated memory

Configuration administrators manage shared OpenShift entries at `/settings/clusters`; authorized
users manage their own private entries separately. Each entry stores an HTTPS API origin, exact
key/value tags, enabled state, and per-cluster TLS verification setting, but no bearer token. The
runtime cluster is registered automatically. Users sign in to selected clusters and PodPilot keeps
their OAuth tokens only in API-process memory for the delegated session.

**Test connection** and Ask Kubernetes requests use the signed-in user's identity. HTTP 401 means
that delegated connection must be established again; HTTP 403 means the user lacks the requested
API permission. Remote Ask metrics require the same user to have the relevant monitoring and Route
access. PodPilot reduces Kubernetes client exceptions to actionable messages and never returns raw
headers or authorization material to the browser. Disabling TLS verification changes certificate
and hostname validation for the registered Kubernetes API and telemetry endpoints discovered from
that API; it does not remove or alter bearer authentication.

Kubernetes normally exposes API discovery to authenticated non-admin users through its default
discovery roles, but clusters may customize that access. In unrestricted Ask, PodPilot exposes a
bounded `discover_resources` helper through the delegated read-only broker. It searches a
five-minute, policy-filtered catalog using exact aliases, normalized compound names, and lexical
overlap before the agent uses an unfamiliar operator or CRD name. A discovery match confirms only
that the API type is advertised; it does not prove the delegated identity may read its objects.
Discovery denial or failure remains a non-blocking limitation, and the full catalog is never placed
in the model prompt.

Before an unrestricted Ask command containing an inline `jq` filter is allowed to read cluster
input, PodPilot runs the filter with `jq -n` and no cluster input. A failed compile is returned as a
`jq filter parse error`, and the original read is not run. Agent prompts require parentheses around
fallback expressions used as object values, such as `{value: (.path // "unknown")}`.

Answer-derived Markdown tables render through the same raw-HTML-disabled boundary as chat prose.
Within table headers and cells only, PodPilot normalizes model-authored `<br>`, `<br/>`, and `<br />`
variants into safe line breaks even when the model mistakenly wraps the tag in an inline-code span.
All other raw HTML remains escaped and visible as text rather than becoming browser markup.

Remote namespace log-volume questions additionally require the standard `logging-loki` Route,
`cluster-logging-application-view`, and cluster-wide LokiStack OpenShift authorization for the
registered identity. The base runtime identity is also bound to
`cluster-logging-infrastructure-view` and `cluster-logging-audit-view`. OpenShift names the audit
role `cluster-logging-audit-view`; there is no `cluster-monitoring-audit-view` role.

Ask audit questions are classified separately from workload-log questions. The classifier derives
an optional supplied username, period, count, all-versus-mutation-versus-delete-only scope, and
all/successful/failed outcome;
normal code validates those values and runs a fixed query against
`/api/logs/v1/audit/loki/api/v1/query_range`. With no username, the query searches all users;
with one, username matching is exact and case-insensitive.
For example, “show the last 5 successful changes by Druciare-Adm over 2 hours” produces a five-row,
two-hour mutation query without encoding that username or time window in application code.
Investigators, Approvers, and Breakglass users can use this Ask capability. A 403 from Loki should
be resolved by verifying the registered cluster identity has `cluster-logging-audit-view` and
cluster-wide LokiStack tenant authorization.

Explicit audit-log wording also has a narrow server-owned semantic fallback. If an OpenAI-compatible
provider returns empty, fenced, truncated, or otherwise invalid classification JSON, PodPilot accepts
one fenced JSON object when valid and otherwise compiles only the grounded audit username, count,
period, mutation scope, and outcome present in the operator's text. A missing username compiles to
a bounded cluster-wide audit query instead of falling through to Kubernetes API inventory discovery.

An audit request such as “last 5 actions” does not treat the initial one-hour window as the answer
boundary. It doubles the bounded query range until five matching events are found or
`PODPILOT_ADHOC_AUDIT_MAX_RANGE_SECONDS` is reached, then reports the actual searched period. An
elliptical continuation such as “what about the last 24hrs” inherits the prior validated username,
limit, operation scope, and outcome while replacing its period. A malformed classification is
retried once; the strict duration-only continuation can still be compiled from the prior typed
audit evidence, but unrelated questions never inherit that audit target.
The Loki request limit now matches the requested result count because its LogQL already applies the
validated stage, operation, outcome, and optional exact-username filters. Audit traffic uses the
separate 1 MiB default response ceiling rather than
overfetching four times the requested number of verbose raw records under the generic 64 KiB cap.
OpenShift Logging can store the Kubernetes audit event directly, as JSON text in `message`, or as a
parsed object in `structured`. PodPilot tries each reviewed record profile with the same bounded
server-side filters and compact projection until one matches, then deduplicates projected events by audit ID. An empty
result is reported as an inconclusive Loki/forwarding observation rather than proof that no cluster
activity occurred.

TLS verification defaults on. If an internal API cannot present a trusted certificate,
an Approver may disable verification on that cluster entry. This also disables hostname
verification for a credential-bearing request and permits interception of the bearer token
and evidence. The UI, audit event, connection status, and a compact affected-session indicator keep
the exception visible without repeating it beneath every Ask answer. Prefer repairing trust and do
not use the exception in production.
PodPilot suppresses urllib3's identical per-request `InsecureRequestWarning` for these explicitly
accepted connections to avoid log spam; this does not suppress connection failures or remove the
operator-visible session indicator and audited TLS warning.

An Investigator selects one to ten enabled clusters beside the Ask composer. A generic new-chat
link starts with no preselected clusters and requires an explicit choice; selecting a cluster name
in the sidebar intentionally starts a new chat with only that cluster preselected. The cluster
drawer defaults to signed-in targets, while **All** also shows targets that still require
authentication; text search applies within the active filter. The selection is pinned when the
first question is submitted; **Change** opens a blank new conversation while the prior session
remains in history. All selected clusters share the 25-unit weighted turn
budget. Typed metric reads are executed independently for every selected cluster by
discovering its Thanos Querier Route and authenticating with that cluster's registered
bearer token; failures remain attributed to that cluster. Alert, investigation, dashboard,
and remediation workflows continue to use only the runtime cluster.

The empty Ask view offers a read-only starter action for failing workloads plus a scoped workload
troubleshooter that collects a namespace and resource name. The former broad recent-warning starter
is intentionally absent because unprojected cluster-wide Event output can exhaust a provider's
context window; operators may still ask a specifically scoped warning-event question.
Delegated sessions additionally offer effective-access and visible-project summaries.
Each button remains disabled until a cluster is selected and the model/session is ready, then
submits its bounded prompt through the normal new-conversation endpoint with the current cluster
selection and reasoning settings. Starter actions never contain write instructions.

An Approver can edit the display name, environment, and tags of the automatically registered runtime
cluster from **Manage → Clusters**. The display name is used on the dashboard, in new Ask evidence,
and in future runtime-cluster operations. The environment labels and groups the runtime cluster in
cluster-selection and delegated sign-in UI just like a registered remote cluster. Tags make
tag-scoped cluster memory eligible for the runtime cluster. These metadata changes do not alter the
projected service-account identity or Kubernetes API connection. Historical evidence keeps the
cluster name recorded when it was collected.

The `podpilot-runtime` ConfigMap `environment` key remains the deployment-level
`PODPILOT_ENVIRONMENT` setting. It seeds the runtime cluster's persisted environment when the
system-cluster record is first created and remains available to deployment safety checks. Once that
record exists, changing the GUI field controls its operator-facing environment label; later
ConfigMap changes do not overwrite saved cluster metadata.

Runtime- and remote-cluster tags are entered as removable text chips rather than JSON. Use a
single-word label such as `production` or an exact key/value tag such as `region:toronto`; press
Enter or comma after each tag. A cluster supports up to 30 tags, and adding another value for an
existing key replaces that key's earlier value.

Cluster-memory target tags use the same removable-chip editor. The form previews the configured
clusters whose tags satisfy every required tag, while explicitly checked clusters remain an
additional OR target. With neither explicit clusters nor required tags, the entry is global.

Ask PodPilot accepts free-form operational questions; it does not gate cluster reads on a
catalog of recognized phrases or sentiment. The model may propose only the registered read
tools, normal code validates every target, sensitive resources remain denied, and the
selected cluster ServiceAccount provides the final Kubernetes RBAC boundary. A bounded object list
is evidence, never a server-owned completion decision. The server does not automatically follow
discovered objects, retry TLS without verification, read referenced ConfigMaps, collect Pod logs,
or expand an answer-authored evidence gap. Those exact reads remain available as grounded
candidates; the agent chooses whether they are material and whether to continue or answer.
For resource wording, normal code canonicalizes generic noun variants against the live catalog—for
example, `KafkaCluster` or “Kafka clusters” can resolve to the uniquely discovered `Kafka` kind. A
catalog miss triggers one fresh API-discovery pass. The generic `list_resources` agent helper is not
registered or offered. Read-only planning can use exact GETs, bounded field searches, API discovery,
and typed summaries; if none can establish the requested inventory, PodPilot reports insufficient
evidence instead of inferring an empty result. Unrestricted delegated agents may issue a deliberately
bounded read-only `oc get` command through the shell tool.
This applies to health, diagnosis, comparison, explanation, configuration, topology, behavior,
inventory, count, existence, and snapshot-replay questions. No collector result is
inventory-terminal. Every answer that cites successful current-turn historical LIST evidence or
`search_resources` evidence also persists a bounded `grouped_resource_list` presentation. Ask
renders one collapsible section per cluster with Kind, namespace, resource name, Ready state,
completeness, scan count, and the matched field value when retained. Each populated cluster table
can be downloaded as CSV. These rows come from normalized evidence and are HTML-escaped by the
template; the UI does not parse or trust the model response as a table contract. At most 1,000
rows are duplicated into presentation metadata, with omitted counts shown when the evidence
contains more. Ask keeps the complete agent prose visible alongside the normalized evidence card.
Other answer Markdown tables, including agent-authored tables with
additional interpreted columns, are parsed through the CommonMark token stream and rendered as
native dynamic-column tables with collapsing and CSV export. Their surrounding prose remains in
place and the UI labels them as answer-derived; this presentation conversion does not make their
contents authoritative evidence. Extraction is bounded to eight tables, 24 columns, 1,000 rows per
table, and 4,096 characters per cell. Tables beyond those bounds remain in the safe Markdown fallback.
The final-answer contract requires equal cell counts and `<br>` item separators and forbids raw
cell pipes or JSON/schema decoration. As a defensive display repair, extraction removes only
unmatched braces at cell-item boundaries and drops a leading quoted or code-formatted `unknown`
placeholder when substantive content follows. Balanced values such as `{}`, JSON snippets, and
OpenShift Logging templates like `{kubernetes.namespace_name}` remain unchanged.
The stored complete Markdown remains a fallback for clients that do not consume presentation metadata.
The generic `list_resources` helper has been removed from guarded planning, authored object-read
schemas, runtime configuration, and unrestricted tool schemas. Existing persisted LIST evidence and
low-level Kubernetes LIST operations inside purpose-built typed collectors remain readable; they are
implementation details, not an agent-selectable skill. A configuration comparison therefore requires
matching exact-object GET evidence from every selected cluster, normally from operator-supplied
coordinates or a sufficiently narrow field search. Without it, PodPilot returns insufficient evidence
and withholds equality and difference claims.
Presentation-only follow-ups may refer to the latest resource result as `these`, `those`, `them`,
or the previous results. PodPilot restores the validated Kind and filters from evidence rather than
asking the model to infer them from prose. Naming one uniquely matching selected cluster narrows the
display to that cluster without changing the conversation's locked cluster selection. The reply
states that it reused an earlier snapshot and includes the original evidence provenance. Wording
such as `current`, `still present`, `now`, `latest`, `refresh`, or `recheck` disables snapshot reuse
and repeats the same bounded resource query against the requested cluster scope.
PodPilot does not issue a style correction or replace a valid answer because a quality heuristic
finds it terse, table-shaped, or incomplete. Exact-object and relationship candidates remain
available to the agent on later planning rounds. Deterministic cited summaries are used only when
the provider or structured response contract fails after successful evidence collection; the
fallback never renders the whole object and does not treat intended configuration as proof of
external behavior.
An exact ConfigMap display is a deliberate exception to the small-field fallback: PodPilot renders
the redacted `data` entries directly without asking the model to reproduce them. The display is
bounded to 24 keys, 16,000 characters per value, and 32,000 characters total, and labels any
truncation rather than silently ending the answer.
The active Ask page uses one session header for the conversation title, cluster-lock boundary,
and evidence count. Agent JSON supplied as a fenced block or standalone JSON paragraph is
validated and pretty-printed in a scrollable monospace block; invalid JSON remains ordinary text.
For namespaced resources, including operator-managed custom resources such as Strimzi
`Kafka`, the table preserves cluster, namespace, resource name, observed `Ready` condition,
and whether the bounded list was complete. A cluster-scoped read can therefore return more
objects than an `oc get` issued after selecting one namespace.

Approvers and Breakglass users can open `/memory`, test scoped lexical retrieval,
and create cluster facts, runbooks, approved incident summaries, and product
knowledge; revising an entry creates a new immutable version. Draft, disabled,
expired, nonmatching, and wrong-namespace entries do not appear in results. An entry
may select explicit clusters, require exact cluster tags, or leave both empty for global
guidance. All required tags must match; explicit-cluster and tag matches use OR semantics.
Restricted entries are visible only to Approvers and Breakglass users and are not supplied to Ask. Assign an
expiry to operational facts likely to drift.

The `0011_cluster_memory` migration creates the relational metadata/chunk tables
and the SQLite FTS5 virtual table. The application verifies that the FTS table is
available at startup. `0012_multi_cluster_ask` adds the cluster registry, immutable
conversation selections, and knowledge target fields. Eligible internal chunks are supplied
to standalone Ask guarded answers and delegated-agent context as guidance; they are not live
evidence and do not enter investigation-chat or remediation prompts. Delegated-agent retrieval is
bounded to four de-duplicated chunks of at most 1,200 characters each and labels their applicable
clusters. `0013_raw_model_responses` adds the
default-off per-run capture choice and bounded redacted answer bodies stored with the
assistant message. No new environment variable or credential permission is required.

Later integrations may add:

- investigation limits and timeouts
- Ask PodPilot read rounds, reads per turn, recent-context size, context-digest
  size, display history, evidence retention, and per-user request-rate limits
- optional OpenShift API override for local development
- `PODPILOT_BOOTSTRAP_KUBECONFIG` for the external local bootstrap credential path
- logging and tracing configuration

Do not put real values in tracked `.env` files. Commit only a redacted `.env.example` once variable names exist.

## OpenShift Deployment

### Agentic investigation on SNO

The agentic SNO overlay uses OpenRouter at `https://openrouter.ai/api/v1`, exact model ID
`openai/gpt-oss-120b`, and API type `chat-completions`. It builds a second
`podpilot-oc-runner` image from `Dockerfile.oc-runner`; the pinned OpenShift CLI stage supplies the
Linux `oc` binary. The runner is a sidecar in the PodPilot Pod and therefore uses
`system:serviceaccount:ai-ops:podpilot-investigator`, which must be able to read Pods and must not be
able to patch Deployments.

Set `OPENROUTER_API_KEY` and the external bootstrap kubeconfig in the Windows process, user, or
machine environment, then run:

```powershell
.\scripts\deploy-agentic-sno.ps1
```

The helper connects through the existing short-lived lab bootstrap flow, checks the runtime RBAC,
applies both binary BuildConfigs, builds both images, deploys the SNO overlay, waits for rollout,
and pipes the OpenRouter key over stdin to the API container. The bootstrap module stores it under
`openrouter_api_key` in the existing resourceName-restricted model credential Secret, activates the
fixed profile, and probes Chat Completions/tool-calling support. It never prints the key.

Agentic turns expose `search_resources`, `http_probe`,
`query_audit_events`, and `query_metrics` as model-selected helper tools alongside
`execute_shell`. The probe performs a bounded unauthenticated HEAD or GET for an exact observed
HTTP(S) URL; an optional connect address preserves the URL hostname for Host and TLS SNI, and TLS
verification remains enabled unless the model explicitly selects a scoped HTTPS trust diagnostic.
They never execute
automatically and never decide whether the turn is complete. Their normalized observations return
to the model as tool results, are persisted as evidence, and can drive native tables and metric
cards. The agent interprets the results and decides whether to invoke another helper, use the shell
escape hatch, or answer. Delegated Investigator and Action conversations use this same loop. The
read-only capability rejects Kubernetes writes, exec/attach/proxy/port-forward requests, and Secret
reads; the Action capability passes the user's requests to normal RBAC and admission. When
enumeration is necessary, the agent uses a deliberately bounded read-only `oc get` command. Wording such as “show”, “list”, “top”, “why”,
“investigate”, “diagnose”, and “root cause” does not create a server-owned completion route. A
native card is a rendering choice, not a completion signal. For example, a top-namespace log-volume
question uses the Loki application tenant's fixed `bytes_over_time` query and renders payload bytes
and average byte rate. Every renderable normalized metric result—not only top CPU, memory, and log
volume—uses a native evidence card. This includes node, PVC, Kafka, ingress, and future metric
profiles without a UI allowlist change. The complete agent response remains visible beside the
card. Empty or unsupported shapes keep the deterministic text fallback. Kubernetes Event counts
are not an acceptable proxy for that result.

Field-constrained resource questions use the live catalog plus a bounded client-side search rather
than returning the entire resource inventory. For example, “Routes whose hostname contains
`.example.com`” compiles to `Route` search on `spec.host` with the literal `contains` predicate and
runs independently on every selected cluster. The filter value must be grounded in operator text.
If the semantic result omits a predicate detected in the question, the ordinary list is retained
only as initial evidence and cannot terminate the turn. A zero-match answer is conclusive only when
`searchComplete=true`; reaching the configured scan ceiling reports uncertainty instead.

Thanos is the preferred historical metric source. If it is unavailable, Node CPU/memory rankings
and namespace-scoped Pod CPU/memory rankings use the Kubernetes Metrics API for a current-only
snapshot. The UI records that no historical average or peak was available. The equivalent OpenShift
CLI commands are `oc adm top node` and `oc adm top pod`; `oc top` is not a valid OpenShift command.
When all registered reads and shell verification attempts fail, Ask reports the exact collection
errors without accepting an agent-invented explanation for why a source was unavailable.
Successful explicit audit retrieval returns a normalized observation to the agent; it does not end
the turn. Audit
queries can be bounded simultaneously by namespace, operation class, outcome, username, and an
explicit common Kubernetes resource kind; for example, “who deleted Pods in ai-ops” queries Loki
for completed delete operations on `pods` in `ai-ops` across all users. It does not fall back to the
nonexistent `events.audit.k8s.io` Kubernetes resource.
Normal code re-applies explicit audit constraints after model classification. Requests such as
“show the last 5 audit entries for failed delete operations” therefore compile with `limit=5`,
delete-only verbs, and failed HTTP outcomes even if the model returns broader defaults. Numeric
limits from 1 through 100 and number words from one through twenty are recognized.
An explicit count such as “last 5” starts at the initial audit window and expands backward only
until five matches are found or the policy ceiling is reached. “Recent” without a count performs
one initial-window query and returns however many matches exist; it does not widen merely to fill
the default 20-row display limit.
If the Loki audit query times out, is denied, or only succeeds on some selected clusters, that exact
registered result returns to the agent. The tool contract identifies Kubernetes Events and
`events.audit.k8s.io` as different data sources, and the result remains an observation rather than a
stop signal. The unrestricted tool boundary canonicalizes harmless natural-language variants such
as `delete` to `deletes` and `any` to `all`; omitted operation and outcome filters default to the
broad `all` semantics. Other invalid arguments return compact field-level guidance without echoed
model input or Pydantic documentation URLs. The audit helper does not depend on `jq` being installed
in `oc-runner`.

Kafka deployment inventory wording such as “show me all the deployed Kafka clusters” uses the
registered `kafkas.kafka.strimzi.io` list on every selected OpenShift cluster. The rendered table
distinguishes found Kafka CRs, a readable API with zero Kafka objects, and a failed or unavailable
Kafka API. This inventory is terminal and never falls through to model-guessed resource names in
`oc-runner`.

Metric period follow-ups preserve the latest registered top CPU, top memory, or namespace
application-log-volume ranking. For example, after a top-namespace log-volume result, “show the log
volume over a 3 day period” repeats the same Loki query with `rangeSeconds=259200`; it does not exec
into Loki Pods or require `pods/exec`. An explicitly different metric does not inherit the prior
query. The shipped `adhoc_logs_max_range_seconds` ceiling is seven days (`604800` seconds); longer
requests are reduced to that bound and reported as limited.

The unrestricted metric helper canonicalizes harmless metric and scope spelling variants before
validating a typed request. A question that explicitly ranks namespaces by generated log volume is
bound to the dedicated `top_log_volume_by_namespace` contract with cluster scope, rank operation,
and namespace grouping. Exact namespace and Pod totals, plus Pod rankings within a namespace, use
the separate scoped `application_log_volume` contract.
When the operator supplies no period, this Loki query uses the bounded five-minute default instead
of accepting a model-invented wider range; explicit numeric periods remain authoritative. Invalid
metric arguments return compact field-level feedback to the agent so it can correct its next tool
call without exposing raw validation internals in the chat.

When an operator selects an object from prior multi-cluster evidence, PodPilot carries the opaque
reference's source cluster into the next turn. Investigative reads and shell commands are limited
to that cluster when the evidence uniquely identifies it; unqualified names typed from scratch
still apply to the conversation's selected clusters.

Verify the deployed boundary:

```powershell
. .\scripts\connect-sno.ps1
oc get pod -n ai-ops -l app.kubernetes.io/name=podpilot -o jsonpath='{.items[0].spec.serviceAccountName}{"`n"}'
oc auth can-i get groups.user.openshift.io --as=system:serviceaccount:ai-ops:podpilot-investigator
oc auth can-i get pods --all-namespaces --as=system:serviceaccount:ai-ops:podpilot-investigator
oc auth can-i patch deployments --all-namespaces --as=system:serviceaccount:ai-ops:podpilot-investigator
oc get deployment podpilot -n ai-ops -o jsonpath='{.spec.template.spec.containers[*].name}{"`n"}'
```

Expected results are `podpilot-investigator`, `yes`, `no`, `no`, and a container list containing
`oc-runner`. Do not apply `deploy/openshift/overlays/poc-cluster-admin` to this simulation.

### Delegated Action mode

The remote overlay includes the runner component and sets `agent_mode: unrestricted`.
It creates no second Deployment: `oc-runner` is the third container in the existing
PodPilot Pod. For multi-cluster conversations the model supplies one selected cluster
ID per shell call. The API brokers only that cluster's in-memory delegated user token
to the loopback runner, which deletes its temporary kubeconfig after the command.
The conversation's immutable mode determines whether the broker exposes read-only
typed access or the user's full cluster authorization. Investigation mode blocks mutations and
other prohibited operations at the broker. Action mode forwards operations directly under the
signed-in user's OpenShift RBAC and admission controls; there is no PodPilot preview or approval
step. The Ask session-cautions disclosure reflects this persisted conversation mode rather than
the internal agent-loop mode. PodPilot classifies each completed `oc`/`kubectl` command as a read or
write operation in the tool result and command audit. The Action-mode prompt must call successful
patches and other mutations writes, even when they are safe or narrowly scoped; final-answer
validation rejects claims that all commands were read-only when a successful write was recorded.
Within one agent turn, each raw tool result is returned to the model once so it can be interpreted.
Subsequent model calls receive a bounded rolling evidence ledger instead of replaying completed raw
logs, object YAML, stdout/stderr, and tool-call arguments. Later user turns continue to use the
bounded visible chat history and persisted typed evidence, not an earlier turn's raw tool transcript.
The ledger can retain detailed excerpts for the full 50-operation budget within an 80 KiB ceiling.
When that ceiling is reached, successful read-only shell detail is reduced before typed evidence,
write results, or failures, preserving the findings most likely to matter later in the turn.
One app-wide 50-unit default action budget is configured with
`PODPILOT_ADHOC_MAX_READS_PER_TURN`; it applies to typed planning and delegated-agent Investigation
and Action conversations and may be set from 1 to 100.
The same retained excerpts and operation metadata are operator-inspectable beneath the answer in the
expandable **Agent evidence ledger** section.
The agent has only a lightweight presentation preference: lists of comparable items should use a
concise Markdown table, while other answers use whichever format is clearest.
**Cluster sign-ins** manages the current
browser session independently of chat history: select unconnected clusters to add them, use
**Remove** to revoke one cluster token, or **Remove all sign-ins** to revoke the complete set.
Removing a cluster used by an existing conversation makes that conversation require reconnection;
it does not delete the conversation. Inspect redacted execution metadata with
`oc logs deployment/podpilot -n ai-ops -c oc-runner`; failed command summaries also appear in Ask.
The runner logs startup plus command start, completion, termination, and timeout events. The API
logs a matching runner request ID, command hash, a redacted command preview capped at 4 KiB,
duration, shell exit code, timeout and truncation flags, and a bounded redacted stderr tail for
non-zero commands. The runner client's HTTP transport log records every runner-protocol status.
Responses from the actual OpenShift API are diagnosed at the API's delegated-proxy boundary; 4xx
and 5xx responses add only a redacted 2 KiB body preview, original byte count, truncation flag,
and digest.
Typed Kubernetes/OpenShift collector failures
include a diagnostic reference plus a bounded redacted exception chain and traceback frame
locations. Use the diagnostic reference shown in Ask to find the matching API log entry; neither
log stream records cluster credentials or complete command output. The API
publishes changing model/command elapsed-time messages to Ask without periodic runtime, model-wait,
or command heartbeat log entries. A command is bounded by
`agent_command_timeout_seconds` (240 seconds by default), while the complete Ask job remains bounded
by `adhoc_run_timeout_seconds` (900 seconds by default). The agent stops starting ordinary work during
the final `adhoc_finalization_reserve_seconds` (60 seconds by default) and asks the model to produce the
best supported answer from retained evidence. Keep command and model-attempt timeouts below the Ask
deadline so PodPilot can preserve redacted timeout details and persist an answer. New model profiles
default to a 180-second attempt timeout with one transient retry; tune those values to the provider's
observed latency rather than allowing one call's retry window to consume the complete Ask deadline.
While a durable Ask run is queued or running, its owner can request cancellation from the live
progress card. PodPilot records the run as cancelled, sends the correlated runner request ID to the
loopback sidecar, terminates that command's process group when it is still active, and cancels the
owning model task. Cancellation is best-effort and does not roll back Kubernetes operations that
completed before the request. The composer remains available for drafting the next message; the
browser retains that draft across the run-completion refresh, but does not submit it until the
current run reaches a terminal state.
See `docs/remote-poc-deployment.md` for ordered image-promotion, air-gap, dry-run,
authorization-audit, and rollback instructions.

Some OpenAI-compatible reasoning models may occasionally return an empty assistant turn or serialize
the next tool arguments as answer content after successful tool calls. PodPilot rejects both shapes
and makes at most two finalization attempts from the existing command results. Look for
`podpilot.agentic.final_answer_retry` in API logs; the legacy `podpilot.agentic.empty_step_retry`
marker is also emitted for an empty turn. PodPilot never automatically replays successful commands.
If both bounded attempts remain unusable, it displays deterministic collected evidence or a safe
unresolved message instead of the malformed model output.

1. Connect and apply the reusable namespace, service account, and read-only RBAC:

   ```powershell
   . .\scripts\connect-sno.ps1
   oc apply --dry-run=server -k deploy/openshift
   oc apply -k deploy/openshift
   ```

2. The SNO lab uses the integrated registry with ephemeral storage. If a rebuilt
   lab reports the registry configuration as `Removed`, enable this explicitly
   disposable configuration and wait for the operator:

   ```powershell
   oc patch configs.imageregistry.operator.openshift.io/cluster --type=merge --patch '{"spec":{"managementState":"Managed","storage":{"emptyDir":{}}}}'
   oc wait clusteroperator/image-registry --for=condition=Available=True --timeout=180s
   ```

   Registry images are lost when the registry Pod is replaced. This is a lab build
   path, not a release registry.

3. Apply the binary BuildConfig and send the current source tree to OpenShift:

   ```powershell
   oc apply -k deploy/openshift/build/sno-binary
   oc start-build podpilot --from-dir=. --follow -n ai-ops
   ```

4. Create the generated OAuth cookie key without putting its value in Git:

   ```powershell
   $cookieFile = Join-Path ([IO.Path]::GetTempPath()) ("podpilot-oauth-cookie-{0}" -f [guid]::NewGuid())
   try {
       [IO.File]::WriteAllBytes($cookieFile, [Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
       oc -n ai-ops create secret generic podpilot-oauth-cookie "--from-file=session_secret=$cookieFile" --dry-run=client -o yaml | oc apply -f -
       if ($LASTEXITCODE -ne 0) { throw 'Unable to create the OAuth cookie Secret.' }
   }
   finally {
       Remove-Item -LiteralPath $cookieFile -Force -ErrorAction SilentlyContinue
   }
   ```

   Do not Base64-encode the random bytes before passing them to `--from-literal`.
   That stores a 44-byte string instead of the required raw key material. Keep the mounted file
   at exactly 16, 24, or 32 raw bytes (the documented deployment uses 32 bytes) so it remains a
   valid stable signing/encryption key across proxy and Pod restarts.

   The workload overlay creates an empty `podpilot-model-credentials` Secret without embedding
   any token in source control. Do not create or populate it before the overlay apply in step 5.
   After deployment, open `/settings/model` as a configuration administrator to add one or more
   endpoints. Choose
   **Responses** for providers implementing `/responses`, or **Chat Completions**
   for gateways implementing `/chat/completions`; enter the token on first save,
   then run **Test connection** and activate a ready profile. A blank token field
   preserves the existing Secret value. Prefer system trust or a custom CA.
   For a model exposed directly by an in-cluster Service without TLS, select
   **Plain HTTP — in-cluster Service only** and use an explicit URL such as
   `http://model-server.spt-llm.svc:8000/v1` or
   `http://model-server.spt-llm.svc.cluster.local:8000/v1`. PodPilot rejects
   plaintext external hosts and IP literals. Confirm that NetworkPolicy permits
   egress from `ai-ops/podpilot` to the model Service; the token and prompts are
   unencrypted on this path.
   The connection test checks endpoint reachability, authentication, the selected
   model, streaming/tool behavior, basic structured output, and the exact
   `ReadPlan` and `AdHocAnswer` schemas used by Ask PodPilot. The page displays a
   success or failure notification after the test and lists **Ask PodPilot
   schemas** separately. A reachable model that cannot satisfy those operational
   schemas remains reduced-capability and cannot be activated as ready.
   The Ask compatibility smoke test exercises classification, one compact action-selection call,
   final-answer formatting, and bounded log-analysis formatting. It verifies schema exchange only;
   it does not grade whether the model chose PodPilot's preferred synthetic troubleshooting path.
   For Chat Completions endpoints, PodPilot makes one bounded correction attempt
   when a response fails schema validation. The retry includes only validation
   field locations/types and never echoes the rejected model response.
   Ask-schema probes cap their synthetic final-answer budget at 1,400 tokens even
   when the profile permits larger operational answers. This reduces probe load
   on slower on-premises models without changing the configured live-answer cap.
   Configuration administrators can delete any model from its edit page, including the active model.
   Deleting a profile also removes its opaque credential key. If the deleted
   profile was active, PodPilot activates the most recently probed ready profile;
   when none exists, it continues safely without AI until another model is tested
   and activated.
   **Insecure** disables certificate and hostname verification and is intended
   only for a disposable PoC endpoint. Rotate the provider key if it ever appears
   in terminal or application output.

   `model-credentials.yaml` is included in the workload Kustomization but deliberately declares
   no `data` or `stringData`. A fresh deployment therefore creates the required Secret container,
   while later applies preserve credential keys added through the UI. Before the first upgrade of
   an installation whose Secret was created with client-side `oc apply`, remove its
   `kubectl.kubernetes.io/last-applied-configuration` annotation so the earlier declaration cannot
   remove credential keys. Remote-cluster credentials are not stored in a Kubernetes Secret.

5. Validate and deploy the complete SNO overlay. Optionally retain the separate
   PoC cluster-admin binding for the `ai-observer` development/break-glass identity;
   the application does not run as that identity. The SNO overlay now includes `base/`, so a
   fresh apply creates `podpilot-role-reader` and its binding without a separate prerequisite:

   Before the first upgrade of an existing installation whose model Secret was created with
   client-side `oc apply`, remove the old apply annotation so the empty manifest cannot remove
   credential keys owned by that earlier declaration:

   ```powershell
   oc annotate secret podpilot-model-credentials -n ai-ops `
     kubectl.kubernetes.io/last-applied-configuration- --overwrite
   ```

   ```powershell
   oc apply --dry-run=server -k deploy/openshift/overlays/sno-milestone-one
   oc apply -k deploy/openshift/overlays/sno-milestone-one
   oc apply -k deploy/openshift/overlays/poc-cluster-admin
   oc -n ai-ops rollout status deployment/podpilot --timeout=180s
   ```

6. Audit effective access and application health:

   ```powershell
   oc auth can-i --list --as=system:serviceaccount:ai-ops:podpilot-investigator
   oc auth can-i get groups.user.openshift.io --as=system:serviceaccount:ai-ops:podpilot-investigator
   oc auth can-i get pods --all-namespaces --as=system:serviceaccount:ai-ops:podpilot-investigator
   oc auth can-i get pods/log --all-namespaces --as=system:serviceaccount:ai-ops:podpilot-investigator
   oc auth can-i get configmaps --all-namespaces --as=system:serviceaccount:ai-ops:podpilot-investigator
   oc auth can-i get secrets --all-namespaces --as=system:serviceaccount:ai-ops:podpilot-investigator
   oc auth can-i create pods/exec --all-namespaces --as=system:serviceaccount:ai-ops:podpilot-investigator
   oc -n ai-ops get deployment,pod,service,route,pvc
   $pod = oc -n ai-ops get pod -l app.kubernetes.io/name=podpilot -o jsonpath='{.items[0].metadata.name}'
   oc -n ai-ops exec $pod -c api -- python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8080/health/ready').read().decode())"
   oc -n ai-ops logs deployment/podpilot -c api --since=10m | Select-String 'podpilot\.'
   ```

   The `podpilot.model_probe.*` and `podpilot.adhoc.*` events identify the actor,
   profile, workflow phase, outcome, and bounded schema-validation field/type.
   Reduced model-probe events identify whether the operational failure occurred
   in the `ReadPlan` or `AdHocAnswer` contract and include the sanitized provider
   error class/status.
   They deliberately omit API tokens, prompts/questions, model response bodies,
   and collected evidence. HTTP access logs remain disabled to avoid logging
   request paths and routine probe noise.

Review `deploy/openshift/base/rbac.yaml` whenever a diagnostic adds a new API dependency.
Production packaging must omit both SNO overlays, use a supported storage class,
and pin an immutable application image digest.

The current delegated runtime binds `podpilot-investigator` only to the custom
`podpilot-role-reader` ClusterRole for exact OpenShift Group GETs; it is not a
`cluster-reader`. ConfigMaps, Pod logs, and other Ask Kubernetes evidence are read with
the signed-in user's brokered capability, which denies Secrets and mutations in read-only mode.
For well-known built-in resources, the broker canonicalizes plural/case variants
and their authoritative apiVersion (for example, `pods` becomes `v1`/`Pod`) before
validation. This prevents model syntax variation from becoming a failed cluster
read; it does not broaden RBAC or permit unknown resource coordinates.

### Typed remediation in the PoC lab

The normal runtime is now read-only. The `poc-cluster-admin` overlay applies only
to `ai-observer`, not the application Pod. Existing action records and approval UI
remain available for evaluation, but live execution will fail closed until a
separate action executor ServiceAccount and workload are implemented.

For every live action, confirm the investigation shows `server dry-run: passed`,
the expected UID/resourceVersion, target namespace, operation, verification, and
recovery note. Use an Approver test identity, expand **Review approval**, and only
then press **Approve and run**. A stale or expired preview must be regenerated by
creating a fresh investigation. Do not retry a mutation from an old investigation.
The investigation creator or an Approver can instead press **Cancel preview**;
this records a closure and audit event without calling a Kubernetes mutation API.
Refreshing the dashboard reconciles expiry and resolved source alerts, while
opening an investigation performs a read-only exact-target check.

After a lab action, inspect the persisted result and cluster state:

```powershell
. .\scripts\connect-sno.ps1
oc -n <fixture-namespace> get deployment,pod -o wide
oc -n ai-ops logs deployment/podpilot -c api --since=10m
```

Production packaging must introduce a separate action identity and namespace
policy before enabling these endpoints outside the disposable lab.

The sanitized live fixture is optional and disposable:

```powershell
oc apply -f evals/live/remediation-crashloop.yaml
oc -n podpilot-remediation-fixture wait --for=jsonpath='{.status.containerStatuses[0].state.waiting.reason}'=CrashLoopBackOff pod -l app=broken-api --timeout=180s
# After PodPilot creates the preview, make the next Pod healthy without changing its Pod/StatefulSet preconditions:
oc -n podpilot-remediation-fixture patch configmap fixture-mode --type=merge --patch '{"data":{"MODE":"healthy"}}'
# Approve only the controller-owned Pod replacement in the UI, verify the new UID is Ready, then remove the exact lab resources:
oc delete prometheusrule podpilot-remediation-fixture -n openshift-monitoring
oc delete namespace podpilot-remediation-fixture
```

The fixture rule is installed in `openshift-monitoring` because user-workload
monitoring is disabled on this SNO. The rule observes only the disposable
fixture namespace; PodPilot still rejects remediation targets in protected
system namespaces.

### Bounded diagnostic plans

`TargetDown` investigations that identify a namespace and Service show a
server-owned **Safe diagnostic plan**. An Investigator can press **Run safe
checks** once. PodPilot first runs fixed instant `ALERTS` and `up` queries through
Thanos, then reads the Service, at most 20 matching Pods, at most 20
EndpointSlices, and events from at most five Pods within the configured event
limit. It adds those observations to the investigation and asks a ready model
profile to reassess them. No model is required to run or retain the checks.

Exercise the disposable live fixture with:

```powershell
. .\scripts\connect-sno.ps1
oc apply -f evals/live/targetdown-investigation.yaml
oc -n podpilot-targetdown-fixture rollout status deployment/check-endpoints --timeout=120s
# Analyze the synthetic TargetDown alert and press Run safe checks as an Investigator.
oc delete prometheusrule podpilot-targetdown-fixture -n openshift-monitoring --ignore-not-found
oc delete namespace podpilot-targetdown-fixture --ignore-not-found
```

The plan should report matching firing-rule state, passive scrape health, Service
selector, EndpointSlice readiness, selected Pod health, bounded events, tool
names, and the requesting OpenShift user. A second run returns a conflict and
must not duplicate tool activity. PodPilot does not actively probe the alert
destination; `instance` is only an escaped exact-match label in the fixed Thanos
queries.

### Unrestricted-agent synthetic challenges

The disposable `podpilot-test` and `podpilot-test2` namespaces contain five
independent challenges for the unrestricted-agent lab: an unmatched node selector, a missing PVC, an
oversized CPU request, a misspelled ConfigMap reference, and cross-namespace
traffic denied by a NetworkPolicy. The last challenge runs `network-client` in
`podpilot-test`; it exits whenever it cannot reach the `network-target` HTTP
Deployment in `podpilot-test2`, then remains running once connectivity is restored.

The fixture creates no RBAC objects. The signed-in delegated user must already
have the required access to inspect or modify these disposable namespaces.

```powershell
. .\scripts\connect-sno.ps1
oc apply --dry-run=client -f evals/live/agentic-challenges.yaml
oc apply -f evals/live/agentic-challenges.yaml
oc apply --dry-run=server -f evals/live/agentic-challenges.yaml
oc get deployment,pod,pvc -n podpilot-test
oc get deployment,pod,service,networkpolicy -n podpilot-test2
```

Remove both namespaces to reset the complete challenge set:

```powershell
oc delete namespace podpilot-test podpilot-test2
```

The in-cluster URL, bearer-token pattern, and `cluster-monitoring-view` binding
for Thanos follow Red Hat's [OpenShift 4.22 monitoring API CLI guidance](https://docs.redhat.com/en/documentation/monitoring_stack_for_red_hat_openshift/4.22/html/accessing_metrics/accessing-monitoring-apis-by-using-the-cli).
Alertmanager is separate: PodPilot defines and binds its own narrow namespaced
`podpilot-alertmanager-api-view` **Role** in `openshift-monitoring`. It grants
`get`/`list` only on `monitoring.coreos.com` `alertmanagers/api` named `main`.
Do not reference this as a ClusterRole or place it in `openshift-logging`; either
mistake leaves the authenticated platform Alertmanager request unauthorized.
The normalized vector shape follows the [Prometheus HTTP API](https://prometheus.io/docs/prometheus/latest/querying/api/).

### Investigation-scoped chat

An Investigator can ask follow-up questions on an investigation page. Incident
facts in an AI answer link to server-validated evidence IDs. `General guidance`
and `Insufficient evidence` answers deliberately show no incident citation. If
the question asks for further investigation, incident chat may perform the same
bounded read-only resource, Pod-log, and HTTP-probe collection used by Ask PodPilot. Alert
labels seed exact persisted scope where available; collected observations are
added to the incident evidence panel and audited as `chat.investigate`. Secrets,
commands, authenticated probes, and mutations remain blocked. If
queued registered checks exist, the model may display a `run_queued_checks`
proposal; it does not run anything until the operator presses **Review and run
queued checks**. Viewer users can read attributed history but cannot post.

Chat messages are redacted before persistence and provider use, limited by the
two environment settings above, and never copied into audit details. Reaching the
history budget requires a new investigation rather than silently truncating the
durable transcript. A provider outage stores a visible unavailable response while
leaving deterministic evidence and checks usable.

For evidence-based Ask replies, the collapsed **Evidence used in this answer**
rounded control replaces the separate inspected-target activity disclosure and expands into a
compact vertical timeline of supporting observations.
Selecting one opens and focuses its
card in **Collected evidence**. The drawer shows normalized OpenShift coordinates
and material fields, probe connection/SNI/TLS diagnostics, metric query bounds, or
the exact Pod/container and bounded log excerpt as applicable. **View technical
details** displays the complete persisted redacted payload used by the answer.
Replies that cite a top-consumer metric render its persisted ranking directly as
an operator-visible horizontal bar table with average, current, and peak values.
The table can be downloaded as CSV; neither the visualization nor the export depends
on the model reproducing numeric values in Markdown. When that structured card is
available, the Ask page renders it as the sole table and suppresses duplicate deterministic or
model-authored Markdown tables while retaining adjacent explanatory prose.
The complete deterministic table remains stored as the answer and is rendered if
the cited observation cannot be recognized or converted into a metric card.
This is evidence provenance, not model chain-of-thought.
Evidence-backed and Not-confirmed states appear as short pills beside the reply
time; hover or keyboard focus exposes their explanation. Ask UI timestamps use
fixed `EST (-4)` presentation while database and API timestamps remain UTC.
When a model answer remains incomplete after its correction attempt, question-focused
deterministic rendering may reuse exact-object evidence collected earlier in the same
conversation. Kafka namespace follow-ups honor a cluster named in the question and list
only explicit namespace include rules from CLF inputs linked to a Kafka output.

StorageClass discovery remains a deterministic convenience. Other free-form information
requests use model planning against the live, safe API discovery catalog, which works for
common Kubernetes and OpenShift resources plus installed CRDs. The planner can propose only
registered, read-only operations; the broker validates exact API coordinates, rejects
sensitive kinds and unsupported operations, applies collection ceilings, and relies on the
selected ServiceAccount's `get`, `list`, and `watch` permissions. Named reads require exact
namespace scope; inventory LISTs may be cluster-wide when the operator supplies no
namespace and remain subject to ServiceAccount RBAC. Investigative questions still use iterative model planning, but the
question-relevant catalog entries are supplied so the model proposes a resource
name rather than guessing apiVersion/Kind coordinates. Interpretation still
requires the configured model.

Before planning, Ask requests a typed semantic read description containing the operation shape,
resource concept, singular-versus-collection cardinality, grounded object name and namespace,
requested object-field paths, explicit label selector, and bounded log semantics when applicable.
Normal code resolves that description through the live safe API catalog and compiles only registered
reads. Exact names must occur in the current question or recent conversation; an ungrounded
model-authored coordinate is ignored. Exact namespaced objects without a grounded namespace are
located with a bounded `metadata.name` search before any GET. Related-object Event questions use a
bounded client-side exact field search, and explicit log periods become Kubernetes `sinceSeconds`
only after an observed Pod/container candidate is selected. Static phrase matching remains a
recovery path for a small set of unambiguous requests rather than the primary semantic vocabulary.

The default ad-hoc budget is ten planning rounds and 50 weighted investigation units,
configured with `PODPILOT_ADHOC_MAX_ROUNDS` and
`PODPILOT_ADHOC_MAX_READS_PER_TURN`. The default
`PODPILOT_ADHOC_FOLLOWUP_RESERVE_UNITS=0` makes the full budget available to the dynamic
model-directed loop. A deployment may reserve units for additional agent-selected reads.
Discovery and ordinary resource reads cost
one unit; Pod logs, HTTP probes, and metric queries cost two; bounded watches cost three.
The planner may search live API discovery for any resource advertising `get`, `list`, or
`watch`, but the broker still rejects sensitive resources and subresources and RBAC remains
authoritative. A watch lasts at most 15 seconds and retains at most 50 projected events. A typed
`http_probe` read can issue an unauthenticated HEAD or bounded GET to any absolute
HTTP/HTTPS URL. `connect_host` overrides only DNS/TCP routing; the URL hostname
remains the HTTP Host and HTTPS SNI name for passthrough Route tests. TLS verification
is enabled by default. For a private, self-signed, or component-managed certificate,
the planner may set `tls_verify=false` on that individual HTTPS probe; the result is
marked insecure and cannot verify server identity. Redirects are not followed, and no cookies, authorization, custom
headers, or request bodies are sent. Configure probe timeout and response ceilings
with `PODPILOT_ADHOC_HTTP_PROBE_TIMEOUT_SECONDS` and
`PODPILOT_ADHOC_HTTP_PROBE_MAX_BYTES`. The mounted OpenShift service CA is added to
system trust. Installing additional private issuers remains preferred when authenticated
identity matters; bypass is intended for bounded troubleshooting reachability tests.
Treat a certificate verification error reported at the TLS stage as evidence that
the peer spoke TLS and presented a certificate. It establishes neither trusted
identity nor application health, but it must not be interpreted as proof that the
backend is plain HTTP. Istio/Envoy sidecar logs alone also do not establish the
application container's listener protocol; collect direct endpoint, container
configuration, readiness-probe scheme, or application-log evidence before making
that claim.

For trust-only failures such as a private, self-signed, or unknown issuer, PodPilot exposes an
optional grounded candidate for the same bounded HTTPS probe with verification disabled. The
agent decides whether that probe is material and must select it explicitly within the normal read
budget. The first observation remains the certificate warning; a selected insecure probe can
establish the HTTP/connectivity outcome but never server identity.

PodPilot prioritizes bounded logs when Pod evidence shows an unready, restarting,
or non-running container. It scans any selected application, init, or sidecar log
excerpt for typed operational signals: crash/exception, resource pressure, TLS,
DNS, network, authorization, storage/mount, dependency/upstream, general error, and
warning patterns. Repeated messages are normalized into signature counts rather than
duplicated evidence. Findings include exact Pod/container coordinates, occurrence
counts, timestamps when present, up to three bounded samples, and extracted paths or
endpoints. Material findings expose exact coordinates and potential correlations to the
planner, which decides whether Pod, Event, previous-log, owner, metric, or configuration reads
are relevant. Findings do not automatically expand the investigation.
Missing TLS certificate/key assets are correlated across a bounded neighboring-line
window so split Python or application tracebacks that name a `.pem`, `.crt`, or `.key`
file before a `FileNotFoundError` remain visible in the deterministic answer section.

Route, HTTP 5xx, and connectivity questions expose observed Route backends, Service selectors,
EndpointSlice/Endpoints targets, Pod candidates, and owner references to each planning round.
The model chooses the relevant traversal and logs dynamically. Every proposed hop shares the
normal 25-unit budget and is grounded and validated by the broker; a malformed plan is reported
as a limitation and does not trigger a server-authored diagnostic path.

For a TCP/connectivity question, the model may read the source and destination Pods, Namespace
label sets, and bounded NetworkPolicies when policy evaluation is relevant. Ask replies evaluate source egress
and destination ingress separately and treat matching selectors as a potential factor, not
proof of a dropped connection; PodPilot does not exec a probe inside the source Pod.

The answer must treat matches as signals rather than conclusions, correlate them
with Pod state, Events, owner/configuration, metrics, or probes, and keep root cause
unconfirmed when that support is absent. Log text remains untrusted data. Secret
contents remain unavailable even when a signal or Pod volume references a Secret.

Before requesting the final model answer, PodPilot converts current evidence to at most eight
resource-agnostic fact cards within a 7.5 KB aggregate target. Current-turn reads are prioritized,
Pod-log samples are capped at 500 characters, and material object fields are projected rather than
sending raw observation envelopes. Only the question, cluster ID/name pairs, fact cards, up to three
collection issues, and an optional bounded prior answer or retry code accompany the concise
`answer`/`citations` contract.
The planning graph, capability ledger, catalog, tool policy, findings, knowledge chunks, and domain
tutorials remain server-side.
This does not truncate persisted evidence or the operator's
provenance drawer. Grounding and certainty are separate: a cited interpretation can remain
`unresolved` without being discarded. An uncited refusal or response containing only headings
is retried once; concise readable answers are accepted. A second incomplete response uses
a deterministic cited answer; recognized Route/TLS and inventory questions retain
their specialized renderers. Inventory-only citations produce a limitation rather than
discarding readable prose. Normal code always appends a bounded **Backend log findings**
section for current signals, including exact Pod/container, category, severity, count,
paths/endpoints, one sample, completed correlation checks, and citations. This section is
composed with—not replaced by—the Route/TLS fallback. Equivalent TLS trust/bypass and
empty-Event limitations are shown once rather than repeated.
Single-line chat-completions answers that begin with a Markdown heading are normalized into
real heading, paragraph, and bullet blocks before this quality check. Recognized operator-facing
headings flattened after Unicode bullets are also moved onto physical lines outside fenced code.
This prevents a substantive flattened response from being mistaken for a heading-only answer;
a genuine standalone heading still receives the bounded correction.

Answers that serialize top-level fields such as `investigation_gaps` inside visible prose receive
`podpilot.adhoc.answer_quality_rejected` with `reason=structured_fields_embedded_in_answer`; the
bounded correction asks only for clean prose. A trailing recommendation heading or
`recommended_actions` serialization is removed before rendering. Markdown style is otherwise not a
quality contract, and recommendation prose is not parsed into actions.

Chat Completions responses with an empty content field receive one minimal schema-only retry. If
the final answer remains empty, invalid, or unavailable after cluster reads succeeded, PodPilot logs
`podpilot.adhoc.provider_fallback` and renders the specialized Route/resource/inventory answer when
available plus a cited collection summary. The message retains `invalid_response` or `unavailable`
provider status and displays the failure as a limitation; collected evidence is not discarded.
The generic exact-resource fallback keeps three-character operational terms such as `DNS` and `Pod`,
removes conversational and resource-kind terms before matching fields, and suppresses labels,
annotations, managed fields, and image inventories unless an explicit metadata renderer owns the
request. It renders at most six matched fields across three objects with individually bounded values;
when no material field matches, PodPilot uses the concise cited collection summary instead of dumping
object content.

Every turn that successfully collects Pod logs also sends all current bounded, redacted
log excerpts through a separate structured model request with no conversation history. The
payload includes a two-sentence OpenShift investigation context and the bounded original
operator request so the analyzer can prioritize relevant connectivity or TLS signals without
assuming the operator's suspected mechanism is correct.
The request is capped across excerpts and treats log text as untrusted data. PodPilot accepts
only issue citations from the supplied log IDs and displays a supporting excerpt only when it
can be found verbatim after whitespace normalization in the cited evidence. The resulting
**Model-assisted log analysis** describes semantic potential issues and confidence without
claiming root cause. Every anomaly mentioned by the analyzer must be a structured issue with an
exact supporting passage; accepted passages are displayed as text blocks. An overview-only clue is
not presented as a finding because it cannot show the operator the implicated log lines. With an
empty issue list, only an overview that explicitly reports no meaningful anomaly is accepted; vague
language such as “problem patterns” cannot bypass the excerpt requirement. After
successful analysis, raw tails are omitted from the main final-answer
request and replaced by the validated structured analysis; persisted evidence remains complete.
Failure of this optional analysis does not fail the investigation.

The planner infers a goal and collection decision from natural language; users do
not need to use exact command-like phrases. When grounded reads exist, the provider receives a
compact action-selection context and small schema rather than the full tool-intent union. It may
select up to four exact opaque IDs from twelve server-derived choices. For unfamiliar resources,
normal code converts bounded live-catalog matches to the same action cards; the resource catalog and
curated knowledge are not sent to the planning model. An operational no-read response is
retried once with structured feedback. If both attempts stop before any evidence, or the first
valid response stops and its correction fails schema validation,
and the operator supplied one exact coordinate that normal code can compile into a
single safe read (for example, a Route hostname in a URL), PodPilot uses that read
as a discovery anchor. All later troubleshooting direction returns to the model;
there is no generic catalog fallback or server-authored traversal. Application logs
record `podpilot.adhoc.plan_repair` and
`podpilot.adhoc.operator_anchor_recovery` without the question or evidence payload.
The recovery event records `reason=repeated_stop` or `reason=invalid_correction`.
A later `403` is an RBAC limitation, not a planner failure, and the UI names the
denied ServiceAccount, resource, verb, and scope.

After evidence exists, the first model decision to stop a diagnostic, log, or
explanation investigation receives one sufficiency review. If an allowed typed
read can materially verify an uninspected next hop or resolve a limitation that
would otherwise be deferred to **Suggested next checks**, the model should request
that read immediately. Repeating the evidence-backed stop is allowed when another
read would not materially improve the answer. Logs record this review as
`podpilot.adhoc.plan_repair reason=evidence_sufficiency_review`; the displayed
recommendation text itself is never executed.

PodPilot derives the relationship graph and capability ledger in trusted server code. The model does
not receive those structures, the discovery catalog, executable tool policy, Kubernetes coordinate
schemas, or the `ReadIntent` union during ordinary candidate selection. It receives bounded evidence
fact cards and server-owned action cards, then returns `investigate`, `answer`, or `uncertain` with a
short reason and, for `investigate`, up to four opaque action IDs. The ledger still distinguishes
`collected`, `attempted_failed`, `budget_exhausted`, `requires_target`, and
`available_not_attempted`; normal code uses those states to prevent completed checks from being
described as missing and to reserve **unavailable** for an explicit failure, denial, unsupported
operation, or exhausted budget.
Before the evidence-follow-up answer, PodPilot recomputes that ledger and supplies separate
`resolved_investigation_gaps` and `remaining_investigation_gaps`. Claiming that a collected Service,
endpoint, Pod, log, metric, or probe is still not collected is rejected with
`reason=collected_check_described_as_uncollected`. Internal single- or multi-ID
`cited_evidence_ids` markers are removed from displayed prose after citation allowlisting.
Saved structured gaps are also filtered against the final trusted ledger. After a TLS-capable endpoint
returns an HTTP status, Pod/log evidence is prioritized over repeated topology collection. Route
fallback answers combine current Route, Service, endpoint, Pod, and probe evidence rather than
reverting to a Route-only summary. Repeated model-stop, duplicate-read, and fallback notices collapse
into one orchestration limitation; TLS bypass, certificate trust, RBAC, and read failures remain visible.

Candidate planning keeps only the current question, at most six compact fact cards within a 5 KB
aggregate target, and twelve grounded action ID/label pairs. It omits conversation history, completed
action summaries, unresolved-question schemas, budgets, graphs, ledgers, catalogs, and tool policy.
Unknown but listable resource types discovered in the
cluster catalog are converted to the same bounded action-card format; the catalog itself is not sent.
The response contract is only `action_ids`: any valid non-empty list continues, while an empty or
omitted list stops. Unknown or malformed IDs still execute nothing.
If the model twice stops while a structured medium/high gap has a matching candidate, PodPilot logs
`podpilot.adhoc.gap_candidate_recovery`, performs that one broker-validated read, and states the
recovery as a limitation.
For a Route investigation, an exact URL in the operator question becomes a grounded bounded GET
probe candidate once Route evidence is present. A structured `pod_logs` gap also admits exact
Running/Ready containers at normal priority, allowing application-error investigation without
requiring a restart or readiness failure first. The same healthy-container eligibility applies to
explicit failure questions such as HTTP 500, timeout, crash, or unavailable reports. EndpointSlice
and Endpoints Pod target references are accepted as exact observed coordinates. If the model twice
stops while one of these exact log reads remains available, PodPilot records
`podpilot.adhoc.diagnostic_log_candidate_recovery`, performs one broker-validated log read, and
discloses the recovery in the answer limitations.

The collection pass pins its first goal and tracks normalized read signatures. Goal drift is logged
as planner feedback without pinning the agent's goal; accepted plan decisions use `podpilot.adhoc.plan_decision`; and a
duplicate-only plan is repaired with `podpilot.adhoc.plan_repair reason=no_progress`. The final answer
uses a separate concise contract containing only answer Markdown and exact citations. Suggested
checks are derived afterward from remaining unread server-owned candidates, never from model prose.
Collected Pod logs are always eligible for the dedicated bounded log-analysis request, including logs
obtained during this recommendation-driven follow-up, before the regenerated final answer.

Up to three remaining exact candidates may display **Run check**. Clicking one
creates a linked run in the same conversation, but sends no previous chat messages or context summary to
the model. The selected cluster, capability, opaque candidate ID, and supporting evidence IDs are stored
on the run and revalidated against current persisted evidence before collection. Unknown, stale,
cross-conversation, mutation-worded, or non-owner actions fail closed. Apply migration
`0014_adhoc_followup_actions` before enabling this UI on an existing database.

Discovery is cached for five minutes per Pod. Newly installed or removed APIs may
therefore take up to five minutes to appear without a restart. Cross-group name
collisions are represented as `resource.group` (for example,
`events.events.k8s.io`). List reads paginate up to the configured object ceiling
and return compact projections. Separate limitations identify either additional
matching objects or compacted detail without conflating the two conditions.

List evidence stores all collected object names separately from compact details.
`objectListComplete: false` means the configured object ceiling was reached and
more matches exist. `detailsTruncated: true` means only verbose detail was omitted;
it does not make the collected name list incomplete. Provider-facing observation
paths are not valid citations and are removed from displayed answers.

For Pod lists, evidence additionally stores a bounded `logCandidates` projection
containing exact Pod and container coordinates. These are not extra Kubernetes
requests. Later planning receives opaque candidate IDs and cannot replace their
coordinates. Application logs record `podpilot.adhoc.plan_repair` with
`reason=invalid_log_target` when a provider invents a target, and
`podpilot.adhoc.log_target_fallback` when normal code selects up to three exact
candidates after the repair also fails. Rejected proposals do not count against
`PODPILOT_ADHOC_MAX_READS_PER_TURN`. A later `OpenShift RBAC denied ... pods/log`
message means the exact request reached the ServiceAccount authorization boundary.

Purpose-built typed collectors and historical LIST evidence retain the 500-object default ceiling,
configurable from 50 to 1,000 with `PODPILOT_ADHOC_INVENTORY_MAX_OBJECTS`. In OpenShift manifests,
edit `data.adhoc_inventory_max_objects` in `podpilot-runtime`; the Deployment maps it into both
application and migration containers. This setting does not enable a generic agent LIST helper.

A bounded field search is inventory evidence, not configuration or health analysis. PodPilot may
follow a complete, sufficiently small search result with exact GETs, but it never blanket-GETs an
unknown collection. Configure the independent search-detail cap from 1 to 25 with
`PODPILOT_ADHOC_DETAIL_FANOUT_MAX_OBJECTS`, or edit
`data.adhoc_detail_fanout_max_objects` in `podpilot-runtime`. If search coverage is incomplete,
exceeds the cap, or lacks every exact object reference, PodPilot performs no blanket or sampled GET
fan-out and tells the operator to narrow the scope. A complete analysis claim requires exact GET
detail for every compared object to be present in the final model context.

Detailed object projections have a separate byte ceiling. Configure it with
`PODPILOT_ADHOC_MAX_PAYLOAD_BYTES`, or edit `data.adhoc_max_payload_bytes` in
`podpilot-runtime`. The shipped OpenShift value is 96,000 bytes and applies to both runtime and
registered remote cluster readers. Increasing this value does not increase the number of objects
collected or scanned; it allows more of their bounded projections to remain in evidence.

The inventory ceiling applies only to explicit inventory requests. A diagnostic
catalog LIST retains its small requested sample and is never promoted to 500 merely
because its limit equals the schema default. A failure question containing an exact
Pod name and namespace starts with one exact Pod GET even when model classification
returns generic `cluster_investigation`. PodPilot then uses the observed container
coordinates for bounded logs and searches Events by exact `involvedObject.name`;
it does not list every Pod in the cluster or every Event in the namespace.

Field searches use a separate scan ceiling so a small result can be found beyond the
ordinary inventory window. `PODPILOT_ADHOC_SEARCH_MAX_SCAN_OBJECTS` defaults to 2000 and
accepts 250–5000; in OpenShift set `data.adhoc_search_max_scan_objects` in
`podpilot-runtime`. Searches support exact/contains matching on validated dot-separated
object field paths, including paths through nested objects and lists. For a Route URL, the
model can select an exact hostname search. Search evidence reports
both match count and scanned count, plus whether a ceiling stopped the scan.

Cluster-wide or namespace-scoped Pod health questions use the deterministic
`pod_health_summary` read rather than a generic Pod inventory. It evaluates every Pod reached
within `PODPILOT_ADHOC_SEARCH_MAX_SCAN_OBJECTS`, then retains only compact anomalous records and
aggregate counts. `CrashLoopBackOff` and other container waiting failures are evaluated from
container and init-container status even when the Pod phase remains `Running`. Every Pod whose
phase is neither `Running` nor `Succeeded` is treated as anomalous; this includes fresh `Pending`,
`Failed`, `Evicted`, `Unknown`, and unrecognized phases. A failed Pod's specific status reason is
preserved when available. Successfully completed Pods are not treated as unhealthy. The result
distinguishes scan completeness from
the separate anomaly-detail result/payload ceiling; PodPilot confirms that no anomalies exist
only when the scan is complete. Raising the evidence payload is therefore not required for large
healthy inventories. The Kubernetes transport currently receives ordinary Pod API objects and
compacts them immediately; the model receives only the bounded health summary.

The same anomaly-first envelope is used by `node_health_summary`,
`cluster_operator_health_summary`, `machine_health_summary`, and
`workload_health_summary`, but each has its own evaluator:

- Nodes are cluster-scoped and use `Ready`, pressure, network-unavailable, and schedulability
  conditions.
- ClusterOperators are cluster-scoped and use `Available`, `Degraded`, and `Progressing`.
- Machines use `machine.openshift.io/v1beta1`, can be limited to a namespace, and evaluate phase,
  age of transitional phases, error conditions, and Node linkage. A missing Machine API is
  unavailable coverage rather than a healthy empty result.
- Deployments, StatefulSets, and DaemonSets can be scanned together or by kind, cluster-wide or in
  one namespace. Their evaluator compares desired, ready, available, and updated replicas,
  observed generation, controller conditions, and DaemonSet misscheduling.

All summaries use `PODPILOT_ADHOC_SEARCH_MAX_SCAN_OBJECTS`; a combined workload summary applies the
ceiling independently to each controller kind. Healthy objects contribute only aggregate coverage
counts. The model receives bounded anomaly records, not the full YAML collection.

OpenShift ingress and browser Route lookups are qualified as
`routes.route.openshift.io`. `routes.serving.knative.dev` is reserved for questions that
explicitly concern Knative or Serving. If logs report an ambiguous plural, inspect the
qualified choices and the proposed `apiVersion`/`Kind`; ambiguity is a rejected preflight
and does not use a cluster-read slot. A 403 for one API group does not justify silently
substituting another group with different semantics.

For a host-matched OpenShift Route, PodPilot recognizes `spec.to.name` and alternate backend
names as observed Service targets for exact follow-up reads. TLS interpretation follows the
Route contract: `edge` means HTTP from router to backend, `reencrypt` means a new backend TLS
connection, `passthrough` means the backend terminates the original TLS stream, and no TLS
termination means an unsecured HTTP Route. The answer labels this as configured behavior,
not a live connectivity result or a complete explanation of an HTTP 500.

Metric trend questions use authenticated Thanos `/api/v1/query_range` through the
`podpilot-investigator` ServiceAccount. Supported metrics are CPU usage, requests, limits,
and throttling; memory working set, requests, and limits; network receive/transmit rate;
container restarts; PVC byte/inode utilization; Pod readiness; workload availability; HPA
current/desired/maximum replicas; Kafka topic message/byte rates, storage, consumer lag, and
under-replicated partitions; Route or IngressController request/error rates; cluster-wide,
namespace, Route, and IngressController inbound/outbound HAProxy bandwidth; MachineConfigPool
updated/degraded state; ClusterOperator conditions; API server/scheduler/etcd request, queue,
latency, leadership, and size signals; Prometheus target, ingestion, active-series, rule-evaluation,
and Alertmanager state; and LokiStack ingestion and query latency. Pod, namespace, and Deployment
scopes require an exact namespace; Pod and
Deployment scopes also require a name. Node scope requires an exact node name and may
optionally narrow to a namespace. Exact PVC utilization requires a namespace/claim; namespace and
cluster storage requests may rank claims instead.
Deployment totals and rankings follow ReplicaSet/Pod ownership, including multiple ReplicaSets during a
rollout. Namespace and node rankings identify monitored namespace/Pod/container consumers. They cannot
identify arbitrary operating-system processes unless separate process-level telemetry is
installed. Overall node CPU and memory utilization uses node-exporter metrics. For “what is
using everything” questions, PodPilot collects both the overall node value and top workload
containers; a gap can represent kernel, filesystem cache, host services, or unmonitored work.
Requests and limits are configuration gauges, not measured usage.
Ingress bandwidth uses the router frontend byte totals for aggregate controller or cluster traffic
and backend byte totals for namespace/Route breakdowns. PodPilot converts those cumulative HAProxy
values to bytes per second with server-owned, reset-aware rate expressions. Explicit periods such as
three days use bounded range queries and the native metric card renders the retained samples as a
time-series chart with the observed peak value and timestamp. This does not represent packet capture,
client identity, or traffic that bypasses OpenShift ingress.
Requests to rank Nodes by CPU or memory use overall node-exporter utilization grouped by Node,
honor the requested top-N limit, and default to five minutes when no period is supplied. This is
not the same as ranking monitored Pods or containers that happen to run on a Node.
When a metric question supplies no period, PodPilot uses a five-minute window and reports the
requested current/average/minimum/maximum statistic from that bounded result. Explicit periods such
as `15m`, `2h`, `7d`, or `last week` remain authoritative within the configured maximum-range policy. A current
request already uses the five-minute minimum, so failure guidance does not recommend shortening it
or ask the operator to author PromQL.

Ask renders bounded metric rankings through one reusable metric table instead of repeating the
deterministic Markdown table. Identity columns come from the returned series labels: node metrics
show nodes, workload metrics can show namespace/Pod/container, and domain metrics can expose
dimensions such as Kafka topic, partition, and consumer group. Unknown safe label dimensions are
rendered generically, up to six identity columns, so new registered metrics do not require a bespoke
table template. Each native metric table remains separate per queried cluster and places that
cluster's friendly name in the table heading; internal cluster IDs are not displayed as operator
labels.

LokiStack application-volume reads use two model-visible contracts.
`top_log_volume_by_namespace` is the dedicated cluster-scope namespace ranking;
`application_log_volume` supports scoped namespace and Pod totals and Pod rankings within an exact
namespace. Legacy cluster totals and Node-oriented variants remain readable for persisted/internal
compatibility but are not the advertised namespace-ranking path. These
queries use the reviewed OpenShift log labels `kubernetes_namespace_name`, `kubernetes_pod_name`,
and `kubernetes_host`. Their average is bytes per second; the total is not compressed object-store
consumption, and the tool returns no log lines. Explicit relative
periods such as `5m`, `30 minutes`, `2h`, and `7d` are converted to bounded seconds; `today`
means elapsed time since 00:00 UTC. An omitted period defaults to five minutes, the minimum is five
minutes, and `PODPILOT_ADHOC_LOGS_MAX_RANGE_SECONDS` defaults to seven days. A Loki deadline
failure identifies the configured timeout instead of reporting generic gateway unavailability.

`PODPILOT_ADHOC_METRICS_MAX_RANGE_SECONDS` defaults to 2592000 (30 days) and accepts up to
7776000 (90 days). `PODPILOT_ADHOC_METRICS_MAX_POINTS_PER_SERIES` defaults to 300 and accepts
50–1000. `PODPILOT_ADHOC_METRICS_MAX_RESPONSE_BYTES` defaults to 1048576 (1 MiB) and accepts
65536–4194304 bytes. Configure `adhoc_metrics_max_range_seconds`,
`adhoc_metrics_max_points_per_series`, and `adhoc_metrics_max_response_bytes` in
`podpilot-runtime`. PodPilot may increase the
requested step to stay within the point ceiling. Thanos retention, unavailable metrics,
series/response ceilings, and access failures are returned as explicit limitations.

The model-visible metric catalog is intentionally focused on CPU, memory, numeric application-log
volume, Kafka consumer lag, and Kafka topic disk utilization. Legacy server-owned templates remain
readable for persisted evidence but are not advertised to the model. Kafka topic disk utilization
supports the current Strimzi `kafka_log_log_size` JMX profile and the legacy
`kafka_log_log_size_value` spelling. It uses the exact cluster label when present and otherwise
matches only broker Pods belonging to the requested Kafka resource; broker-PVC capacity matching
supports both legacy `kafka` and named KafkaNodePool Pods. The capability still requires kubelet
Kafka-PVC capacity metrics, while consumer lag requires Kafka Exporter metrics. A
successful Kubernetes object read does not imply
that telemetry exists. If the registered query returns no samples, PodPilot names the expected
exporter/profile rather than treating the object as idle or allowing the model to invent PromQL.
Metric label names can vary across operator/exporter releases; unsupported profiles require a new
reviewed server-owned template or label alias, not an operator-supplied query.

Topic-grouped Kafka disk requests use the percentage query as the authoritative bounded result and
perform two additional server-owned reads for replicated topic bytes and partition-replica bytes.
The Ask result ranks topics first and lets the operator expand each topic to see partition ID,
replica bytes, broker ID, and broker Pod placement. Partition replicas are collected separately for
at most the first five displayed topics so one high-partition topic cannot consume the shared Thanos
series ceiling and silently truncate another topic. An explicit `topic,partition` grouping keeps the
flat partition-first result. Companion-read failures do not invalidate the topic utilization result;
they mark the expandable detail incomplete and appear as operator-visible limitations.
Common model spellings such as `kafka_topic_disk_usage` and
`kafka_topic_disk_usage_bytes` are normalized server-side to the registered
`kafka_topic_disk_utilization` capability; they never become model-authored PromQL.
The typed metric target remains the owning `Kafka` custom resource (`namespace` plus
`name`). An optional exact `topic` argument is compiled into the reviewed server-owned
selector and ensures named-topic byte and partition details are collected even when the
topic would not appear among the first five entries of an unfiltered ranking.

Remote monitoring and logging authorization failures preserve `HTTP 403` in the per-cluster Ask
limitation. A Thanos denial names the required `cluster-monitoring-view` role. Application-log
volume is a Loki tenant query rather than a Thanos metric; its denial names
`cluster-logging-application-view`. Route discovery denials identify the affected Thanos or
LokiStack Route separately from query authorization, while transport and TLS failures remain
reported as availability failures rather than being mislabeled as RBAC denials.

In unrestricted agent mode, a recognized Kafka topic-disk-utilization request remains on this registered
metrics path even when Thanos or the required exporter is unavailable. PodPilot reports the
authoritative collection failure and does not fall through to a broker Pod shell or recommend
granting `pods/exec`. The result compares replicated topic log bytes with aggregate allocated Kafka
broker-PVC capacity. Kafka topics share broker disks rather than owning private allocations, so the
evidence always states that broker-local headroom is still required when partition placement is skewed.

Unknown CRDs use the generic safe resource path: live API discovery resolves the served resource,
bounded LIST/GET reads expose redacted spec/status evidence, and opaque observed relationships can
be traversed without model-authored API coordinates, field paths, or selector values. PodPilot does
not dynamically convert an unknown Kind into PromQL. If a third-party operator exposes useful
telemetry, add a reviewed capability profile declaring its stable metric names, label mapping,
units, aggregation, cardinality bounds, and exporter prerequisite.

### Ask PodPilot job progress

Each question creates an `adhoc_runs` row before execution. The production default
starts three in-process workers inside the one supported SQLite API replica. At most two
runs from one user execute concurrently, leaving capacity for another operator when work is
available. Configure these limits with `PODPILOT_ADHOC_WORKER_CONCURRENCY` and
`PODPILOT_ADHOC_MAX_CONCURRENT_RUNS_PER_USER`. The browser redirects immediately and subscribes to
`/api/v1/adhoc-runs/<id>/events`; 10-second SSE heartbeats reduce idle Route
disconnects, and EventSource reconnects automatically. The current phase is also
available from `/api/v1/adhoc-runs/<id>` and is reconstructed on page reload.
Both endpoints are visible only to the conversation owner.

On Pod startup, interrupted `running` rows are returned to `queued` and retried.
The work is read-only, but a restart can therefore repeat model inference and
bounded reads. While a run is active, a second turn returns HTTP 409. The owner may
still delete the conversation: queued runs are removed before claim, an in-process
running task is cancelled, and the deletion audit record stores the cancelled-run
count without question or evidence content. Inspect phase transitions without payloads through
`podpilot.adhoc.*` application logs. The active assistant placeholder groups human-readable
updates into phase sections in stable chronological order, including the planner's bounded working
hypothesis, its proposed next check, and summaries of evidence actually found. New phase sections
append without reordering existing sections; each section displays its latest three updates. These
transient updates disappear when the
final answer replaces the spinner. They are structured plan/action summaries, not hidden model
reasoning. The final structured
answer appears after the job reaches `succeeded` or `failed`.
The supported single-replica SQLite deployment has one bounded global Ask worker pool. A question
submitted after the pool or the sender's concurrency allowance is full remains queued and starts
automatically; the pending UI distinguishes this waiting state from an actively running
investigation. A raw
model-response request remains visibly checked but disabled while its specific run is pending.

SQLite connections use WAL mode, `synchronous=NORMAL`, a 30-second connection timeout, and a
30-second `busy_timeout`. Keep the database on the single Pod's block-backed PVC; WAL is not a
multi-replica or network-filesystem coordination mechanism. Increase API CPU/memory and verify
model-provider and Kubernetes API quotas before raising concurrency above the default three.

Every run has an overall execution deadline, defaulting to 300 seconds through
`PODPILOT_ADHOC_RUN_TIMEOUT_SECONDS`. A run that exceeds it is atomically marked
`failed`, receives an operator-visible insufficient-evidence message, and emits a
terminal SSE event. Status and event requests also expire stale `running` rows,
so an abandoned worker cannot leave the browser spinner active indefinitely. The
browser stops its own progress animation after the server deadline plus a short
delivery grace period if it cannot retrieve terminal state. While a run is active,
the browser also reconciles persisted status alongside SSE so a missed terminal
event still refreshes the completed answer promptly.

The OpenShift workload coordinates slow-model limits: model profiles may use at
most 240 seconds by default, the overall Ask deadline is 300 seconds, and both the
OAuth proxy upstream timeout and Route timeout are 300 seconds. Keep the model
ceiling below the overall deadline so cluster reads, response validation, and
answer persistence retain time to complete. Changing ConfigMap-backed values
requires a Deployment restart because they are injected as environment variables.

Migration `0010_adhoc_runs` creates the durable job table. The workload migration
init container runs Alembic before the API starts; apply the matching image and
manifests together and verify the migration completes before troubleshooting the
worker.

### Trust the SNO router CA for interactive login

The lab Route uses the private OpenShift ingress CA. TLS clients must trust that CA;
do not click through certificate warnings or use `--insecure-skip-tls-verify`.
Export the public certificate to a temporary file:

```powershell
. .\scripts\connect-sno.ps1
$routerCa = oc -n openshift-ingress-operator get secret router-ca -o jsonpath='{.data.tls\.crt}'
$caDir = Join-Path $env:TEMP 'PodPilot'
New-Item -ItemType Directory -Force -Path $caDir | Out-Null
$caPath = Join-Path $caDir 'sno-router-ca.crt'
[IO.File]::WriteAllBytes($caPath, [Convert]::FromBase64String($routerCa))
certutil -dump $caPath
```

After verifying the subject and fingerprint are for this disposable SNO cluster,
an operator may import it into the current Windows user's trusted roots:

```powershell
$certificate = Import-Certificate -FilePath $caPath -CertStoreLocation Cert:\CurrentUser\Root
$certificate.Thumbprint
```

Restart the browser, open
`https://podpilot-ai-ops.apps.sno.192-168-0-200.sslip.io`, and sign in with one
of the PoC users. Remove the certificate after the lab is destroyed:

```powershell
Remove-Item -LiteralPath ("Cert:\CurrentUser\Root\" + $certificate.Thumbprint)
```

### SNO-local PoC storage

Install the lab-only static storage separately from the reusable base:

```powershell
oc apply --dry-run=server -k deploy/openshift/storage/sno-local
oc apply -k deploy/openshift/storage/sno-local
oc get storageclass podpilot-local
oc -n ai-ops get pvc podpilot-data
```

The claim uses `WaitForFirstConsumer`, so it can remain `Pending` until a Pod
mounts it. The node directory `/var/mnt/podpilot` must exist before applying the
local PV. The current lab initializes it with group `1000740000` and mode `0770`;
re-read the namespace allocation after a rebuild. The workload Pod requests the
same OpenShift-assigned supplemental group so kubelet can prepare the volume label
and ownership. This one-node local volume has a Retain reclaim policy but no quota,
HA, snapshot, or backup. Do not install it on production or multi-node clusters.

Verify scheduling and write access with the disposable smoke-test Pod:

```powershell
oc apply -f deploy/openshift/storage/sno-local/smoke-test-pod.yaml
oc -n ai-ops wait --for=condition=Ready pod/podpilot-storage-smoke --timeout=120s
oc -n ai-ops logs podpilot-storage-smoke
oc -n ai-ops delete pod podpilot-storage-smoke
```

The first run logs `podpilot-storage-ok`. Delete and recreate the test Pod to
confirm the next run also logs `podpilot-storage-persisted` before the marker.
The test Pod is intentionally not part of the Kustomize resources and should be
deleted after validation.

## Monitoring APIs

- Query metrics through Thanos Querier at `/api/v1/query` or `/api/v1/query_range`.
- Query rule state through Thanos Querier at `/api/v1/alerts`.
- Query active Alertmanager instances at `/api/v2/alerts`.
- The Alertmanager route root (`/`) is not a supported UI and can report “Application is not available”; use the OpenShift console for the alerting UI.
- Authenticate with a bearer token and validate the route or service CA.

PodPilot uses the in-cluster Alertmanager Service on port 9094, the projected
service-account token, and
`/var/run/secrets/kubernetes.io/serviceaccount/service-ca.crt`. It does not disable
TLS validation, log the token, or retain a second alert database. Dashboard
collection failures appear as degraded state rather than zero alerts.

### Verify Milestone 2 alert ingestion

```powershell
. .\scripts\connect-sno.ps1
$pod = oc -n ai-ops get pod -l app.kubernetes.io/name=podpilot -o jsonpath='{.items[0].metadata.name}'
oc -n ai-ops exec $pod -c api -- python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8080/health/ready').read().decode())"
oc -n ai-ops logs $pod -c migrate
```

Use an HTPasswd Investigator-or-higher user in the OAuth-protected UI. `Watchdog`
should appear under Expected heartbeat. Analyze re-checks that the fingerprint is
still active, creates a durable `recommendation_ready` investigation and audit
event, and displays only deterministic triage. Viewer users can see results but
cannot start analysis.

### Historical Milestone 3 workload-evidence gate

This pre-delegation gate is retained for history only. It expected the runtime ServiceAccount to
read workloads and must not be used to validate a current deployment. Current release checks expect
Group GET to succeed and ordinary Pod, Pod-log, ConfigMap, Secret, and mutation access to fail for
`podpilot-investigator`; the signed-in user's delegated capability owns Ask evidence access.

```powershell
.\.venv\Scripts\python.exe -m pytest --cov --cov-report=term-missing
. .\scripts\connect-sno.ps1
oc auth can-i get groups.user.openshift.io --as=system:serviceaccount:ai-ops:podpilot-investigator
oc auth can-i get pods --all-namespaces --as=system:serviceaccount:ai-ops:podpilot-investigator
oc auth can-i get pods/log --all-namespaces --as=system:serviceaccount:ai-ops:podpilot-investigator
oc auth can-i get configmaps --all-namespaces --as=system:serviceaccount:ai-ops:podpilot-investigator
oc auth can-i get secrets --all-namespaces --as=system:serviceaccount:ai-ops:podpilot-investigator
oc -n ai-ops rollout status deployment/podpilot --timeout=180s
```

Expected results are `yes`, then `no` for every ordinary Kubernetes data read. The separate
disposable PoC cluster-admin overlay affects only the `ai-observer` development identity.

## Runbooks

### Verify the lab monitoring stack

```powershell
oc get clusteroperator monitoring
oc -n openshift-monitoring get pods
oc -n openshift-monitoring get prometheus,alertmanager,servicemonitor,prometheusrule
oc -n openshift-monitoring get route thanos-querier alertmanager-main
```

`Watchdog` is expected to remain firing as an end-to-end alert pipeline signal.

### Audit for accidentally staged secrets

```powershell
git status --short
git diff --cached --name-only
```

If a credential was committed or pasted into a task, remove it from the working
tree and rotate it at the provider. Deleting a file or message does not make an
exposed credential safe again.
