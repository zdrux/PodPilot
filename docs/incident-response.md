# Incident response PoC

Status: implemented on `codex/incident-response-poc`; enabled in the disposable SNO lab.
Other deployment compositions remain opt-in, single-process PoC.

## Operator workflow

Incidents is a shared fleet view for PodPilot Investigator, Approver and Breakglass
roles. Viewer and Delegated Operator roles cannot access incident evidence. Assign
these SRE roles only to the intended OpenShift administrator audience. PodPilot
does not infer cluster-admin membership from a remote token.

Each cluster's Alertmanager sends an authenticated webhook to its registered
incident connection. PodPilot admits only critical alerts in a reviewed allowlist,
groups by connection and Alertmanager group key, and queues one read-only run.
Repeated notifications update alert states without additional model calls.
Resolution never erases the investigation. A newer firing occurrence after
resolution creates a new incident; delayed firing notifications from a resolved
occurrence do not reopen it. Manual reruns preserve previous run snapshots.

The shared sidebar lists the five most recently updated incidents below the cluster
tree, with links to each case and an indication when more are available on the full
**Incidents** dashboard. The dashboard opens directly with queued and running
investigations in a live table above fleet history; active work is marked with a
green pulse. Rows expand in place to show the current
coordinator phase, retained evidence results, specialist counts, and specialist
start/end times, work descriptions, results and queued/running/completed/error state.
The history table begins directly with its column headings rather than a redundant
section banner. Each collapsed row provides a right-aligned full-investigation action;
when expanded, that action moves beneath the current phase title. Final assessment
findings appear above Workstream as soon as the coordinator persists its briefing.
The coordinator currently authors these findings together during its final evidence
pass, so they normally arrive as one terminal update rather than incrementally during
collection. Specialist activity and retained evidence continue to update progressively.
The board and each active incident detail page subscribe to authenticated server-sent events.
The detail page compares a server-authored state version before replacing content, preserves
expanded activity and limitation rows, the selected run tab, and an open evidence modal, then
stops replacing the report after the final terminal-state render. Completed reports do not
open a live stream; rerunning one reloads it into active mode. EventSource reconnects
automatically, and a bounded polling fallback is used while active when streaming is unavailable.
The incident detail
page opens the newest immutable Investigation run directly, without a separate Overview
tab. Every run identifies its source alert, alert state and cluster in its summary, and
queued or running work is marked with a green pulse in the title and run tab. Briefings,
hypotheses and next steps
render as sanitized narrative Markdown without table parsing, so pipe-delimited model
output cannot distort the report layout. The preliminary briefing presents distinct
findings as a flat at-a-glance list with its evidence basis. Each evidence-ledger row opens
the run-scoped retained payload and projected object coordinates in the same modal pattern
as Ask activity; large JSON payloads are never expanded inline into the report. Valid E-ID
citations in briefing prose, hypotheses and next steps activate the owning run, scroll the
exact evidence row into view, and open its modal. Limitations use a
compact reading list. Continue in Ask creates a private read-only conversation
with an immutable copy of the selected incident run's evidence. Ask presents the
source incident, run, timestamps and evidence range in a dedicated imported-context
panel rather than manufacturing a PodPilot reply. A focused continuation question
asks PodPilot to revalidate the current state, investigate remaining gaps and
compare new observations with the historical snapshot. The question is submitted
automatically when the operator's required delegated cluster session is active—on
arrival when already signed in, or after a successful reconnect. The server claims
the handoff once, so reloads and duplicate browser requests cannot queue duplicate
runs. The submitted question then appears as the operator's user message, while
imported and newly collected evidence retain distinct provenance.

Collector footnotes are outcome-based. Configured safety ceilings remain silent when a
collection completes within them. If Kubernetes pagination, evidence projection, retained
bytes, or a result-count ceiling is actually reached, the footnote identifies the collector,
the applicable limit, and the observed/retained count when available. Failed Kubernetes reads
retain a sanitized reason such as the HTTP status, connection failure, request timeout,
configured read deadline, invalid JSON response, or configured response-byte limit; arbitrary exception
text is never persisted. A successful cluster-health survey with no failed or partial resource
reads therefore has no generic cap warning. Limitations authored by Argo CD, GitHub, and Pod-log
specialist model calls appear under model-reported uncertainty rather than collection/policy limits.

## Configuration

Set `incidents_enabled: "true"` in the `podpilot-runtime` ConfigMap after applying
the incident-response component (credential RBAC and webhook proxy routing).
The Deployment reads this key as `PODPILOT_INCIDENTS_ENABLED`; the base defaults
to false and the incident-response component sets it to true. Restart the
`podpilot` Deployment after changing the ConfigMap because this is a startup
setting, not a live admin UI toggle. Preserve the value in your deployment
configuration so a later manifest apply does not reset it.

For standalone application runs, use `PODPILOT_INCIDENTS_ENABLED=true` after applying migrations through
`0027_model_runtime_policy`. The default is false. Connectors configuration requires
configuration-administrator access as well as an SRE role.

**Manage → Connectors** lists independent OpenShift cluster, Argo CD, and GitHub
instances in three groups. Its adjacent add control opens a type chooser. Adding
an OpenShift instance registers its API identity first and returns directly to
incident setup; already registered clusters without incident access remain visible
as not configured. Supply the cluster-reader token and
a distinct randomly generated webhook bearer credential (at least 32 characters).
The cluster registry owns API URL, environment and TLS policy; unattended access
does not modify Ask credentials. An optional Thanos/Prometheus HTTPS origin enables
fixed platform-availability range queries with the same cluster token. Its custom
CA bundle is configured on the connection. Connection tests check the core reads;
operators must separately ensure that this identity is read-only in cluster RBAC.
Kubernetes current/previous Pod logs use ordinary Pod `get`/`log` access. The optional
deep-history path also requires `cluster-logging-infrastructure-view` and a conventional
`openshift-logging/logging-loki` Route on registered remote clusters; absence or denial is
reported as a limitation and does not fail the investigation.

**Manage → Connectors** is the connector directory. Its nested **Clusters**,
**GitHub**, and **Argo CD** groups link directly to each configured instance, and
its dedicated add control opens the type chooser. Registered shared clusters remain
listed when incident access is not yet configured, while **Cluster Management** owns
their API identity and trust metadata. A divider separates this
configuration-administrator-only section from the shared workspace navigation.
Webhook credentials and the generated receiver path are configured on each cluster
connector; there is no separate webhook-receivers page. The receiver is a POST API,
not an interactive browser page. The cluster connector also shows its last accepted
delivery, incident count, and a collapsible summary of deployment-level investigation
limits. The former `/settings/webhooks` URL redirects to the connector directory after
enforcing configuration-administrator access.

Secrets are opaque keys in the pre-created `podpilot-incident-credentials` Secret.
Override its namespace/name with `PODPILOT_INCIDENT_SECRET_NAMESPACE` and
`PODPILOT_INCIDENT_SECRET_NAME`. Database rows contain key references, never tokens.
Blank token fields preserve existing credentials. To rotate, save a replacement;
to revoke use cluster/GitHub token revocation and disable the connection. Disabled
connections reject new webhooks and queued investigations; a run already executing
may finish its bounded reads. Credential updates affect subsequent runs.

For **Argo CD**, configure an independent HTTPS API origin, read-only API token,
optional CA, and allowed projects. It has no configured cluster or GitHub dependency.
During an investigation PodPilot queries each enabled instance and retains only
Applications whose exact destination server matches the incident cluster API URL or
whose destination name matches the cluster name or one of that cluster incident
connector's explicit aliases. Saved Kubernetes-hosted Argo connectors without a URL
remain readable through their former namespace/hosting-cluster path while they are
migrated, but all new connectors use the direct Argo CD API.

For **GitHub**, configure the corporate HTTPS origin, REST prefix (`/api/v3` for
Enterprise Server, empty for an API origin), optional custom CA, PAT and exact
allowed `owner/repository` entries. Connection tests validate repository metadata
reads. Hosting type is configured, not inferred solely from a custom hostname.
The current correlation matches repository hostname to connector hostname; the
PoC targets custom-host Enterprise installations. Separate github.com/api.github.com
host mapping is not implemented. Use a PAT restricted to read access to the same
platform repositories. PodPilot cannot prove every scope attached to a PAT.

Argo CD projections retain bounded matching Application ownership, managed-resource
coordinates, repository origins, monorepo paths, current sync revisions, and history
from the two hours preceding the source alert onset through collection time. A
repository is joined to an enabled GitHub connector only when its hostname and exact
`owner/repository` allowlist match; only exact commit SHAs are queried. Git commit
metadata and associated PR metadata are projected; diffs and PR bodies are not
sent to the model. Current health and nearby changes are correlation, not proof of
causation. Missing history or unsupported revisions remain visible limitations.

## Alertmanager delivery

The save page displays `/api/v1/incident-webhooks/<connection-id>`. Configure an
HTTPS webhook receiver at the PodPilot Route plus this path, with `send_resolved:
true` and HTTP bearer authorization matching the connection's webhook credential.
Keep the credential in Alertmanager's supported Secret-backed configuration. Do
not put it in URL query strings. Route only the selected platform-critical alerts.
Use `max_alerts: 100` or lower; PodPilot accepts at most 100 alerts / 128 KiB per
delivery and 200 fingerprints per incident. Existing rule `for` durations provide
the initial firing delay. PodPilot adds no further delay.

Reviewed SNO seed allowlist (severity must also be critical):

- etcdNoLeader
- etcdInsufficientMembers
- etcdDatabaseQuotaLowSpace
- KubeAPIDown
- KubeAPIErrorBudgetBurn
- KubeControllerManagerDown
- KubeSchedulerDown
- ClusterOperatorDown
- NoRunningOvnControlPlane
- NoOvnClusterManagerLeader
- KubeletDown

The list seeds new cluster connectors, but Approvers may add or remove exact
Prometheus alert names on each connector. Critical severity alone does not admit
an alert; its exact name must also be configured.
Unknown/non-admitted alerts return success with zero admitted entries. Queue
saturation returns 503 for retry. Truncated notifications explicitly report
incomplete coverage and cannot assert full group resolution. Missing alerts are
not implicitly marked resolved. Group-key changes can create separate incidents;
automatic cross-group merging is intentionally absent.

## Execution and evidence boundaries

The incident worker is separate from Ask and exposes no shell or mutation tool.
It uses server-owned GET collectors and allowlisted field projections; arbitrary
annotations, Pod environment variables, credentials and full specs remain excluded.
Normal Kubernetes collections follow all continuation pages. The cluster-health
survey discards healthy objects and retains unhealthy observations within the
configured collection byte budget, without a fixed object-count cutoff. Failures,
repeated continuation tokens, byte ceilings and deadlines report incomplete coverage.
Argo CD and GitHub collection also follows supported pagination without first-N
application, revision or PR cutoffs. Exact destination and repository allowlists
remain mandatory.

**Model settings** owns the active profile's Incident policy: collection and response
bytes, page size, namespace ceiling (0 means no count ceiling), log/history windows,
metric range and series, coordinator turns, collectors per turn, specialist calls,
concurrency and deadlines. Policy is snapshotted at the beginning of each run.
Worker concurrency changes affect new claims; existing investigations finish under
their captured policy. No Pod restart is needed. Without a usable model, the
validated default policy bounds deterministic collection.

Source evidence is retained independently of model input budgets. Large evidence
is partitioned for specialists with the original evidence ID retained in every
partition. The coordinator receives cited reports. Accumulated coordinator evidence
is summarized when it exceeds the configured evidence share of the input budget;
structural input compaction remains a final safeguard. Reaching a specialist-call,
retention or time budget is explicit and does not imply complete coverage. Summary
and report schemas no longer impose arbitrary character or finding-count caps;
the model output allowance bounds generated content.

Synthetic connectivity tests keep a dedicated four-minute/six-turn harness.
Incident runtime tuning controls is described in
[model-runtime-policy.md](model-runtime-policy.md).

Every coordinator and specialist model call inherits the active model profile's transient
retry allowance, which defaults to three retries for timeouts, disconnects, rate limits and
transient server failures. The timeout applies per attempt. As the outer incident safety
deadline approaches, PodPilot shortens the per-attempt timeout so retry opportunities remain
available without discarding the hard deadline.

The total model window, input/output allowances and protocol reserve now come from
Model settings for both Ask and Incidents. The former Incident-only window override,
quarter-window output cap, fixed coordinator byte ceiling and short specialist
output caps have been removed. The effective input ceiling is the smaller of the
configured maximum input and total window minus maximum output minus protocol reserve.
Provider-bound guards cover both Responses and Chat Completions, including retries.
The count remains an estimate rather than the endpoint's exact tokenizer.

## Packaging, operations and limits

`deploy/openshift/components/incident-response` adds the feature environment flag,
an empty Secret, a resourceName-restricted Secret get/patch Role and RoleBinding,
and an exact webhook-path OAuth proxy exception. The webhook handler always
validates its own bearer credential; other routes retain normal proxy identity.
The reusable base remains unchanged. The disposable SNO composition is
`deploy/openshift/overlays/sno-incident-response`. Validate it with server dry-run
before deployment. Never replace a populated Secret with a credential-bearing
manifest in source control.

This PoC requires one application process/replica. The serialized ingress lock and
three process-local worker slots are not a distributed queue design. At most 100 runs can be
queued/running. Startup marks interrupted runs explicitly and continues queued
runs; it does not automatically repeat an interrupted investigation. Set
`PODPILOT_INCIDENT_WORKER_ENABLED=false` to pause processing while retaining ingress.
Retention/archival and production HA require a later operational design; the UI
shows the latest 100 incidents and latest 25 runs per incident, and storage grows
until operators apply an approved retention procedure.

A total cluster outage may prevent that cluster's Alertmanager from delivering
anything. This trigger cannot replace independent external availability monitoring.
SNO rule presence validates seed names, not multi-node failure behavior. Corporate
Argo CD/GitHub end-to-end verification requires configured instances and credentials.

## SNO specialist stress test

`scripts/stress-incident-sno.py` creates one owned, non-privileged log fixture Pod in
`openshift-monitoring`, submits four controlled scenarios through the real TLS-verified,
authenticated webhook, waits for their runs, sends resolved notifications, and removes
the fixture in `finally`. It never changes an OpenShift control-plane workload. Run it
only against the documented disposable SNO after using `connect-sno.ps1`:

```powershell
.\.venv\Scripts\python.exe scripts/stress-incident-sno.py
```

The scenarios cover an API/log failure chain, contradictory etcd+kubelet alerts, a
supposed monitoring rollout regression, and a 20-series API error-budget fanout.
`--resolve-open` is a narrowly scoped recovery command for a terminated harness: it
closes only firing `[SIMULATION]` incidents and records an audit event.

The 2026-09-05 run first exposed serial-worker and soft-deadline bottlenecks. After
parallel fan-out and deadline propagation, four fresh investigations reached terminal
status in about 11 minutes while three coordinators ran concurrently: three completed
and the 36-item/12-specialist log-heavy run correctly became partial because its final
citation list was invalid. All four were resolved and the fixture was removed. No
provider context-limit failure occurred under the effective 45,952-token input cap.
SNO has no Argo CD Application CRD and no corporate GitHub connector, so connector
specialists remain covered by model-free isolation tests rather than this live run.

## SNO webhook smoke test

SNO runs Alertmanager 0.31.1 (`openshift-monitoring/alertmanager-main-0`). The lab
setup uses a dedicated `ai-ops/podpilot-incident-reader` ServiceAccount with
`cluster-reader` and `cluster-monitoring-view`. It has no Deployment patch,
Secret read, or ClusterRoleBinding create permission. PodPilot's own runtime
identity remains separate.

After connecting with the external bootstrap path through `connect-sno.ps1`:

```powershell
.\scripts\deploy-incident-sno.ps1 -BootstrapKubeconfig $env:PODPILOT_BOOTSTRAP_KUBECONFIG
. .\scripts\connect-sno.ps1
.\.venv\Scripts\python.exe scripts/configure-incident-sno.py configure
.\.venv\Scripts\python.exe scripts/configure-incident-sno.py fire
.\.venv\Scripts\python.exe scripts/configure-incident-sno.py status
.\.venv\Scripts\python.exe scripts/configure-incident-sno.py resolve
```

`configure` preserves existing Alertmanager routing and adds the
`podpilot-platform-incidents` receiver. The cluster's router CA is mounted through
`alertmanagerMain.secrets` as `podpilot-webhook-ca`; webhook HTTPS verification
remains enabled. Synthetic `podpilot_test=true` signals route exclusively to
PodPilot. Reviewed real critical alerts also reach PodPilot while retaining their
original routing. The previous Alertmanager Secret and monitoring ConfigMap are
backed up outside the repository under `%LOCALAPPDATA%/PodPilot/incident-backups`.
Deployment backs up the SQLite database on its existing PVC before migration.

The helper mints a **24-hour** reader token and stores it in PodPilot's incident
Secret. Run `configure` again to refresh it; the existing webhook token is preserved.
This lab helper is not a production credential-rotation solution. Token values are
never printed. A TokenRequest expiry is printed as non-secret setup metadata.

`fire` creates/updates only the owned `podpilot-webhook-smoke-test` PrometheusRule.
It uses the admitted `etcdNoLeader` name with explicit synthetic labels and
annotations, producing a `[TEST]` incident rather than implying a real outage.
`resolve` changes its expression to return no alert; the inert rule is retained
for repeatable testing. Allow time for Prometheus Operator reconciliation and
Alertmanager grouping. A repeat delivery should update the same incident while
retaining one run; resolution should preserve the incident and evidence history.
The agent treats synthetic signals as connectivity tests and does not pursue a
root cause based on the test signal alone.

Validated on 2026-09-05: unauthenticated ingress returns 401; a valid but
non-admitted signal returns 202 without creating an incident. The live synthetic
rule delivered repeated firing notifications into one investigation, which
completed with operator evidence and correctly identified the signal as a test.
Its resolved notification updated incident
`69fcfb0c-1386-40a7-bc40-2e8d022ecd0a` without removing the investigation history.
An earlier smoke run reached its evidence/time budget; bounded operator and Pod
projections were corrected before the successful rerun.

The specialist-orchestration deployment was revalidated with synthetic incident
`7822cbdd-2885-48ad-9a18-7d4944293c35`: one run completed with four cited platform
observations, repeat deliveries did not create another run, and the resolved
notification preserved its investigation history.

### Connector credential-save troubleshooting

Connector saves persist credentials through the API's hosting-cluster service
account to the named `podpilot-incident-credentials` Secret. They do not use the
submitted reader token or oc-runner to store credentials, even for the hosting
cluster itself. Enabling the incident flag alone does not provision that Secret,
its get/patch Role, its RoleBinding, or incident webhook proxy routing.

Save failures now include a diagnostic reference and emit a credential-free API
log (`podpilot.incident.connector_save_failed`) and attributed failure audit.
HTTP 403/404/401 from the credential store are distinguished. Unexpected internal
failures are not labeled as Secret failures; discovery queue failures after a
successful save explicitly say the connector was saved. Raw exception messages,
request bodies, tokens and Kubernetes response bodies are not logged.

For a deployment in `ai-ops`, inspect only Secret metadata and check the actual
Deployment service account's get/patch access to that named Secret. Do not dump
Secret data. A new enabled incident cluster also requires a separate webhook
bearer token (at least 32 characters); leaving it blank retains an existing token
but cannot initialize a new enabled connector.

Discovery UI and failure handling: Test & discover uses persisted credentials;
unsaved form edits now block that action with an instruction to save first.
Queued/running statuses display progress indicators, and polling continues every
four seconds while discovery is queued or running, even when a proxy buffers SSE
without disconnecting. Connector polling and streaming stop once discovery is idle
and restart after Test & discover. Unchanged results never replace the content;
expanded lists and live-status labels are excluded from change detection. The API logs
safe discovery start/completion/failure identifiers without tokens or raw errors.
Credential loading is inside the terminal-state handler. HTTP 401 on protected
Kubernetes reads fails discovery; public version reads alone do not validate a
token. Missing capability reads produce partial coverage. Previously stranded
running records from older builds are not automatically reset by this change.

### Incident-cluster Argo CD inventory

Test & discover now uses the incident cluster's saved reader token to enumerate
ArgoCD custom resources (v1beta1, falling back to v1alpha1 when absent), server
Deployments labeled component=server/part-of=argocd, and paginated Applications and ApplicationSets. ApplicationSet inventory retains
identity, project template and generator type names, without generator bodies or
credentials. Generated Applications are included in the Application inventory.
Previously saved results require a discovery rerun to populate ApplicationSets.
Operator-owned Deployments are deduplicated against observed owner UIDs. It reads
server Services and Routes targeting those Services in discovered namespaces.
It does not contact the discovered endpoint addresses. Nonstandard unlabeled
installations may not be recognized; Applications can still appear independently.

The results show installation evidence and UIDs, namespaces, health/sync,
repository paths/revisions, endpoints, checks and resource coverage. Missing or
denied APIs and deadline/size limits remain explicit. Collection is bounded to
500 objects per resource query and endpoints in 50 namespaces, within the reader
budget. Namespace co-location does not establish an Application's controller.
The shared connector layout groups Applications by namespace and project behind
collapsed disclosures. ApplicationSets, repository admission and coverage have
separate matching sections across all themes; open sections survive refreshes.
Cluster-level Application observations also populate the existing exact
repository/destination correlation table.

Configure Argo CD opens a draft using the registered host and observed namespace;
it does not create credentials or enable a connector. Operators still select
project scope. An enabled incident-cluster credential takes precedence for hosted
Argo CD access, including the system cluster, with no fallback to runtime identity
when that explicitly configured credential is missing. Referenced repositories
use existing matching GitHub admission rules and attributed audit records.

Validation: paginated inventory, denied APIs, bounds, source URL credential
stripping, rendered findings/draft prefill, saved-token precedence and repository
admission have regression tests. A read-only SNO probe found one Argo CD custom
resource, one Application, two Services and a Route. Corporate discovery still
requires deployment and adequate scope on the supplied reader token.
