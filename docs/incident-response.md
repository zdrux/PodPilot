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
**Incidents** dashboard. The dashboard pins queued and running investigations in a
separate live table above fleet history. Rows expand in place to show the current
coordinator phase, retained evidence results, specialist counts, and specialist
start/end times, work descriptions, results and queued/running/completed/error state.
The board and each incident detail page subscribe to authenticated server-sent events and
refresh their own content only when durable orchestrator state changes. Expanded rows,
selected run tabs and open evidence are preserved. EventSource reconnects automatically;
a bounded polling fallback is used when streaming is unavailable. The incident detail page uses a flat tabbed report: Overview
groups identical source alerts into table rows with occurrence counts, and every
immutable run has its own Investigation tab. Briefings, hypotheses and next steps
render as sanitized narrative Markdown without table parsing, so pipe-delimited model
output cannot distort the report layout. The preliminary briefing is presented as a
bounded assessment card with its evidence basis, while a sticky quick-view rail lists
retained evidence and exact object coordinates projected from that evidence. Valid E-ID
citations in the briefing, hypotheses and next steps, along with evidence and object links
in the rail, activate the owning run, expand the exact run-scoped evidence row and scroll
it into view. Retained payloads remain collapsed until requested. Limitations use a compact
reading list. Continue in Ask
creates a private read-only conversation with copied historical evidence and
requires the operator's own delegated sign-in before additional reads.

## Configuration

Enable `PODPILOT_INCIDENTS_ENABLED=true` after applying migrations through
`0024_incident_activity`. The default is false. Connectors configuration requires
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
It uses server-owned GET collectors for cluster operators, OpenShift versions and
upgrade history, nodes, MachineConfigPools, and a bounded cluster-wide exception survey
covering unhealthy Pods, Deployments, StatefulSets, DaemonSets, unbound PVCs, and recent
warning events. Validated namespaces from firing alerts are prioritized. Unhealthy-resource
observations and degraded ClusterOperator related objects can add exact namespaces for
deeper Pod, Deployment, PVC, warning-event, and log collection. Pod environment variables,
arbitrary annotations and full specs are excluded. Only exact observed incident
Pod/container names can become bounded log capabilities. Current Kubernetes logs default
to 1,000 lines / 96 KiB from the last two hours. A container with observed restart or
last-termination state additionally exposes a bounded `previous=true` read. If Kubernetes
no longer retains that previous stream, PodPilot attempts an exact namespace/Pod/container
query against the Loki infrastructure tenant; the same scoped Loki collector remains
available for deeper history when useful. Loki defaults to 2,000 lines / 96 KiB over a
six-hour window anchored thirty minutes before alert onset. Missing Kubernetes or Loki
history remains an explicit limitation and does not stop other collection. Alerts without
a valid Kubernetes `namespace` label begin with the cluster-wide exception survey rather
than losing workload visibility. A run accepts no more than 20 initial alert namespaces and
40 total namespaces after evidence-led expansion. Each cluster-wide resource list is capped
at 60 objects and the combined unhealthy projection at 120 observations.
Optional metric collection uses one fixed platform availability query over 30
minutes at 60-second resolution, capped at 12 series.

An initial operator snapshot and configured change enrichment seed a model-guided
coordinator. The model chooses only available collector IDs, or finalizes with cited
evidence, hypotheses and next steps. A normal incident is primarily bounded by ten
coordinator turns, with a 45-minute outer safety deadline and up to three reads per turn.
The coordinator can finish early when the evidence is sufficient; productive collection is
not stopped merely because a shorter elapsed-time target was crossed. Retained evidence is capped at
384 KiB while the coordinator context has a separate 128 KiB ceiling. These defaults
are configurable with the `PODPILOT_INCIDENT_*` settings defined in `settings.py`;
schema bounds prevent unbounded autonomy. Synthetic smoke tests retain their shorter
four-minute/six-round path. Missing or
invalid citations label the briefing unverified. Model failures preserve collected
evidence. Without a configured usable model, deterministic cluster snapshots are retained
with partial status and an explicit limitation. Every run uses the currently active
model profile behind the existing API provider boundary.

Oversized row-based evidence is projected progressively instead of being replaced by
an empty limitation marker. Recent warning Events are ranked toward failure/error signals,
then retained within a 32 KiB projection with an explicit retained-row count. Incident
reports display trusted collection/policy limits separately from distinct model-reported
uncertainty and suppress equivalent model paraphrases of a system limit.

Every coordinator and specialist model call inherits the active model profile's transient
retry allowance, which defaults to three retries for timeouts, disconnects, rate limits and
transient server failures. The timeout applies per attempt. As the outer incident safety
deadline approaches, PodPilot shortens the per-attempt timeout so retry opportunities remain
available without discarding the hard deadline.

`PODPILOT_INCIDENT_CONTEXT_WINDOW_TOKENS` models the provider's complete context
window and defaults to 64,000. Incident mode reserves the smaller of the profile's
output allowance and one quarter of that window, plus a 2,048-token protocol margin;
the remainder becomes the effective input ceiling. With the SNO profile this is
45,952 input tokens plus 16,000 output tokens and the reserve. Provider-bound
incident payloads use the same tokenizer-independent estimate as Ask. If needed,
PodPilot structurally compacts coordinator evidence, retaining alerts, operator
health and specialist reports first. It stops a request locally when even the fixed
context cannot fit. The active setting and evidence ceilings remain deployment-level
runtime policy configured through the `PODPILOT_INCIDENT_*` settings and are summarized
on cluster connector records.

Large or separate evidence domains use isolated specialist calls. Argo CD and GitHub
specialists each receive only one connector result and return a compact cited report.
The coordinator receives that report; the bounded source result remains in the
operator evidence timeline. When the coordinator discovers and selects an exact
platform-container log capability, the existing structured Pod-log analyzer receives
only that one redacted excerpt. Its compact issue report enters coordinator context,
while the raw bounded log remains available in retained evidence. At most 12 specialist
reports are admitted per run. A failed or uncited specialist is recorded as a
limitation and cannot silently establish a conclusion.

Up to three Pod-log specialists selected in one coordinator round execute concurrently.
The single Pod also runs three incident-worker slots, allowing separate coordinators
to progress concurrently. Queue claims remain process-local and serialized. A durable
multi-replica queue, per-specialist lifecycle records, cancellation and join policy
remain production work. Each provider call receives only the time remaining in its
run, so a late specialist call cannot overrun the outer deadline by its full timeout.

Credentials are kept out of model context; projected observations, webhook data,
Git metadata and model output are redacted before durable evidence/display.
All external content remains untrusted. Evidence carries IDs, source, cluster and
observation time. Connector save/test, webhook acceptance, rerun, handoff and run
completion write metadata-only audit events. Connector HTTP requests use HTTPS,
bounded GETs and no redirects. Existing explicitly accepted per-cluster TLS bypass
is honored and displayed; GitHub/model TLS is not bypassed by this feature.

Each run also retains a bounded activity journal with at most 24 coordinator/specialist
tasks and 12 recent transitions. Entries contain server-authored task labels, state,
timestamps, bounded work descriptions, evidence IDs and short redacted results. Raw
logs, connector payloads, prompts, credentials and model reasoning remain in their
existing evidence or provider boundaries and are not copied into activity telemetry.
Only the current workstream animates running tasks. Historical journal transitions use
a static started marker so an earlier start event cannot appear to still be active.

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
