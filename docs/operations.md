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

The current deployment uses these variables:

- `PODPILOT_ENVIRONMENT`
- `PODPILOT_CLUSTER_NAME`
- `PODPILOT_DATA_DIR`, `/var/lib/podpilot` in the SNO overlay
- `PODPILOT_DATABASE_URL`, `sqlite:////var/lib/podpilot/podpilot.db` in the SNO overlay
- `PODPILOT_AUTH_MODE=proxy`
- `PODPILOT_ROLE_CACHE_SECONDS`, default `30`
- `PODPILOT_ROLE_INVESTIGATOR_GROUPS`, JSON array defaulting to
  `["podpilot-investigators"]`
- `PODPILOT_ROLE_APPROVER_GROUPS`, JSON array defaulting to `["podpilot-approvers"]`
- `PODPILOT_ROLE_BREAKGLASS_GROUPS`, JSON array defaulting to `["podpilot-breakglass"]`;
  arrays may contain multiple existing groups or be empty, but the same group
  cannot map to more than one role; all arrays may be empty, leaving every
  authenticated user at Viewer
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
  `1` through `100`; the adapter also enforces a fixed 64 KiB response ceiling
- `PODPILOT_WORKLOAD_MAX_EVENTS`, default `30`
- `PODPILOT_WORKLOAD_LOG_TAIL_LINES`, default `200`
- `PODPILOT_WORKLOAD_MAX_LOG_BYTES`, default `16384` per collected log stream
- `PODPILOT_DIAGNOSTIC_MAX_CHECKS`, default `4`, with a hard accepted range of
  `1` through `10`
- `PODPILOT_CHAT_MAX_MESSAGES`, default `20`, counting both operator and assistant
  messages, with a hard accepted range of `2` through `50`
- `PODPILOT_CHAT_MAX_CHARS`, default `1000` characters per operator message, with
  a hard accepted range of `100` through `4000`
- `PODPILOT_MODEL_CREDENTIAL_STORE`, `environment` for local development or
  `kubernetes` in the OpenShift workload
- `PODPILOT_MODEL_SECRET_NAMESPACE`, default `ai-ops`
- `PODPILOT_MODEL_SECRET_NAME`, default `podpilot-model-credentials`
- `PODPILOT_MODEL_SECRET_KEY`, default `api_key`
- `PODPILOT_CLUSTER_CREDENTIAL_STORE`, `environment` for local development or
  `kubernetes` for managed cluster entries
- `PODPILOT_CLUSTER_SECRET_NAMESPACE`, default `ai-ops`
- `PODPILOT_CLUSTER_SECRET_NAME`, default `podpilot-cluster-credentials`
- `PODPILOT_MODEL_TIMEOUT_MAX_SECONDS`, default `240`, controls the highest timeout
  an Approver may save on a model profile (configuration range `30`–`300` seconds)
- `PODPILOT_ADHOC_MAX_CLUSTERS_PER_CONVERSATION`, default `10`
- `PODPILOT_POC_MODE=true` for the lab-only runtime policy

Model profile metadata (API type, base URL, model names, TLS mode/custom CA,
capability hints, timeout, and token budgets) is configured through
`/settings/model` and stored in SQLite. Local development reads `OPENAI_API_KEY`
without persisting it. In OpenShift, every profile has an opaque key in the fixed
Secret above. Saving a token sends it through the OAuth-protected HTTPS Route;
FastAPI patches only that key through the Kubernetes API using the runtime
ServiceAccount. The UI never reads the saved value back. Model calls reread the
key, so token creation and rotation require no Deployment restart.

### Multi-cluster Ask and curated memory

Approvers and Breakglass users manage remote OpenShift entries at
`/settings/clusters`. Each entry has an HTTPS API origin, opaque Secret key, exact
key/value tags, enabled state, and per-cluster TLS verification setting. The runtime
cluster is added automatically and uses its projected service-account identity. Remote
tokens are never stored in SQLite or returned by the API. Disabling an entry removes its
Secret value but keeps metadata for historical conversations.

**Test connection** performs remote Kubernetes API discovery with the stored identity.
HTTP 401 means the bearer token must be replaced; HTTP 403 means the identity needs API
discovery and read-only `cluster-reader` access on the remote cluster. PodPilot reduces
Kubernetes client exceptions to these actionable messages and never returns raw response
headers or authorization material to the browser. The remote adapter sends tokens through
the Kubernetes client's `BearerToken` authentication setting, producing an
`Authorization: Bearer …` header whether TLS verification is enabled or explicitly
disabled. Disabling verification changes certificate and hostname validation only; it
does not remove or alter bearer authentication.

TLS verification defaults on. If an internal API cannot present a trusted certificate,
an Approver may disable verification on that cluster entry. This also disables hostname
verification for a credential-bearing request and permits interception of the bearer token
and evidence. The UI, audit event, connection status, and affected Ask answers keep the
exception visible. Prefer repairing trust and do not use the exception in production.
PodPilot suppresses urllib3's identical per-request `InsecureRequestWarning` for these explicitly
accepted connections to avoid log spam; this does not suppress connection failures or remove the
operator-visible and audited TLS warning.

An Investigator selects one to ten enabled clusters beside the Ask composer. The selection
is pinned when the first question is submitted; **Change** opens a new conversation while
the prior session remains in history. All selected clusters share the 25-unit weighted turn
budget. Remote metrics are not available in this phase; alert, investigation, dashboard,
and remediation workflows continue to use only the runtime cluster.

An Approver can rename the automatically registered runtime cluster from **Manage →
Clusters**. This changes its PodPilot display name on the dashboard, in new Ask evidence,
and in future runtime-cluster operations without changing the projected service-account
identity or Kubernetes API connection. Historical evidence keeps the cluster name recorded
when it was collected.

Remote-cluster tags are entered as removable text chips rather than JSON. Use a single-word
label such as `production` or an exact key/value tag such as `region:toronto`; press Enter or
comma after each tag. A cluster supports up to 30 tags, and adding another value for an
existing key replaces that key's earlier value.

Cluster-memory target tags use the same removable-chip editor. The form previews the configured
clusters whose tags satisfy every required tag, while explicitly checked clusters remain an
additional OR target. With neither explicit clusters nor required tags, the entry is global.

Ask PodPilot accepts free-form operational questions; it does not gate cluster reads on a
catalog of recognized phrases or sentiment. The model may propose only the registered read
tools, normal code validates every target, sensitive resources remain denied, and the
selected cluster ServiceAccount provides the final Kubernetes RBAC boundary. When a
question is not an explicit list or count request, a bounded object list is treated as discovery
rather than a complete answer. PodPilot follows up on up to three discovered
objects per read with exact namespace/name reads, within the existing per-turn budget, and the
answer must interpret material fields from those details rather than returning object names alone.
This applies to health, diagnosis, comparison, explanation, configuration, topology, and behavior
questions. Explicit list and count questions remain inventory-only. When a
`list_resources` plan omits a deliberate limit, the broker replaces the model schema's
20-object default with the configured bounded inventory window. When the model cannot turn
validated list evidence into a useful final answer, PodPilot renders that evidence as a
deterministic table instead.
If the model still returns an incomplete non-inventory answer after the bounded correction, exact
object reads feed a redacted, question-focused deterministic answer with evidence citations.
Known relationships such as CLF Kafka outputs and their pipelines are summarized directly;
other resources expose at most a small set of fields matching the question. The fallback never
renders the whole object and does not treat intended configuration as proof of external behavior.
The active Ask page uses one session header for the conversation title, cluster-lock boundary,
and evidence count. Agent JSON supplied as a fenced block or standalone JSON paragraph is
validated and pretty-printed in a scrollable monospace block; invalid JSON remains ordinary text.
For namespaced resources, including operator-managed custom resources such as Strimzi
`Kafka`, the table preserves cluster, namespace, resource name, observed `Ready` condition,
and whether the bounded list was complete. A cluster-scoped read can therefore return more
objects than an `oc get` issued after selecting one namespace.

Investigators can open `/memory` and test scoped lexical retrieval for one cluster.
Approvers can
create cluster facts, runbooks, approved incident summaries, and product
knowledge; revising an entry creates a new immutable version. Draft, disabled,
expired, nonmatching, and wrong-namespace entries do not appear in results. An entry
may select explicit clusters, require exact cluster tags, or leave both empty for global
guidance. All required tags must match; explicit-cluster and tag matches use OR semantics.
Restricted entries are visible only to Approvers and are not supplied to Ask. Assign an
expiry to operational facts likely to drift.

The `0011_cluster_memory` migration creates the relational metadata/chunk tables
and the SQLite FTS5 virtual table. The application verifies that the FTS table is
available at startup. `0012_multi_cluster_ask` adds the cluster registry, immutable
conversation selections, and knowledge target fields. Eligible internal chunks are supplied
only to standalone Ask planning and answers as guidance; they are not live evidence and do
not enter investigation or remediation prompts. `0013_raw_model_responses` adds the
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
   That stores a 44-byte string, while the OAuth proxy requires the mounted file
   to contain exactly 16, 24, or 32 raw bytes when cookie refresh is enabled.

   Create or replace the model Secret directly from the local OpenAI key
   without printing it or writing it to disk:

   ```powershell
   if ([string]::IsNullOrWhiteSpace($env:OPENAI_API_KEY)) { throw "OPENAI_API_KEY is not set" }
   oc -n ai-ops create secret generic podpilot-model-credentials --from-literal=api_key=$env:OPENAI_API_KEY --dry-run=client -o yaml | oc apply -f -
   oc -n ai-ops get secret podpilot-cluster-credentials *> $null
   if ($LASTEXITCODE -ne 0) { oc create -f deploy/openshift/workload/cluster-credentials.yaml }
   ```

   Open `/settings/model` as an Approver to add one or more endpoints. Choose
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
   The Ask probe exercises two planning rounds: Pod discovery without a fabricated
   log target, followed by selection of an exact synthetic Pod/container candidate.
   This catches endpoints that produce schema-valid JSON but substitute literal
   instructions or placeholders for values that should come from earlier evidence.
   For Chat Completions endpoints, PodPilot makes one bounded correction attempt
   when a response fails schema validation. The retry includes only validation
   field locations/types and never echoes the rejected model response.
   Ask-schema probes cap their synthetic final-answer budget at 1,400 tokens even
   when the profile permits larger operational answers. This reduces probe load
   on slower on-premises models without changing the configured live-answer cap.
   Approvers can delete any model from its edit page, including the active model.
   Deleting a profile also removes its opaque credential key. If the deleted
   profile was active, PodPilot activates the most recently probed ready profile;
   when none exists, it continues safely without AI until another model is tested
   and activated.
   **Insecure** disables certificate and hostname verification and is intended
   only for a disposable PoC endpoint. Rotate the provider key if it ever appears
   in terminal or application output.

   `model-credentials.yaml` and `cluster-credentials.yaml` document the fixed Secret
   identities but are deliberately excluded from the workload kustomization so a later
   manifest apply cannot erase existing tokens.

   If saving a managed cluster fails, verify the out-of-band Secret and its narrowly
   scoped runtime permission before checking the remote cluster. Saving does not contact
   the remote API; it first persists the submitted token in this Secret:

   ```powershell
   oc get secret podpilot-cluster-credentials -n ai-ops
   oc auth can-i patch secret/podpilot-cluster-credentials -n ai-ops --as=system:serviceaccount:ai-ops:podpilot-investigator
   oc logs deployment/podpilot -n ai-ops -c api --since=10m
   ```

   The first two commands must succeed. PodPilot returns a safe, specific message for a
   missing Secret or denied RBAC and logs the failed credential operation without the
   submitted token. A browser message stating that PodPilot returned no response instead
   points to the Route/OAuth proxy or a lost API pod connection.

5. Validate and deploy the complete SNO overlay. Optionally retain the separate
   PoC cluster-admin binding for the `ai-observer` development/break-glass identity;
   the application does not run as that identity:

   ```powershell
   oc apply --dry-run=server -k deploy/openshift/overlays/sno-milestone-one
   oc apply -k deploy/openshift/overlays/sno-milestone-one
   oc apply -k deploy/openshift/overlays/poc-cluster-admin
   oc -n ai-ops rollout status deployment/podpilot --timeout=180s
   ```

6. Audit effective access and application health:

   ```powershell
   oc auth can-i --list --as=system:serviceaccount:ai-ops:podpilot-investigator
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

Milestone 10 binds the normal `podpilot-investigator` runtime to OpenShift
`cluster-reader`. The application broker supports ConfigMaps and bounded Pod logs
but denies Secrets, access-review resources, arbitrary subresources, and mutations.
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
on the model reproducing numeric values in Markdown.
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

The default ad-hoc budget is ten planning rounds and 25 weighted investigation units,
configured with `PODPILOT_ADHOC_MAX_ROUNDS` and
`PODPILOT_ADHOC_MAX_READS_PER_TURN`. The default
`PODPILOT_ADHOC_FOLLOWUP_RESERVE_UNITS=0` makes the full budget available to the dynamic
model-directed loop; a deployment may reserve units for the mechanical TLS trust retry.
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

For trust-only failures such as a private, self-signed, or unknown issuer, PodPilot
automatically repeats the same bounded HTTPS probe once with verification disabled,
subject to the normal read budget. The first observation remains the certificate
warning; the retry can establish the HTTP/connectivity outcome but never server
identity. Durable progress events identify the retry as an automatic follow-up, and both probe
observations remain available through cited evidence.

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

Every turn that successfully collects Pod logs also sends all current bounded, redacted
log excerpts through a separate structured model request with no conversation history. The
payload includes a two-sentence OpenShift investigation context and the bounded original
operator request so the analyzer can prioritize relevant connectivity or TLS signals without
assuming the operator's suspected mechanism is correct.
The request is capped across excerpts and treats log text as untrusted data. PodPilot accepts
only issue citations from the supplied log IDs and displays a supporting excerpt only when it
can be found verbatim after whitespace normalization in the cited evidence. The resulting
**Model-assisted log analysis** describes semantic potential issues and confidence without
claiming root cause. After successful analysis, raw tails are omitted from the main final-answer
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
as `podpilot.adhoc.goal_pinned`; accepted plan decisions use `podpilot.adhoc.plan_decision`; and a
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

The default inventory ceiling is 500 objects per LIST and may be set from 50 to
1,000 with `PODPILOT_ADHOC_INVENTORY_MAX_OBJECTS`. In OpenShift manifests, edit
`data.adhoc_inventory_max_objects` in `podpilot-runtime`; the Deployment maps it
into both application and migration containers. Reapply the workload and restart
the Deployment after changing the ConfigMap. Explicit list requests render a
server-generated Markdown table containing every collected name. If the table
states that the object list is incomplete, increase the ceiling deliberately
rather than removing the bound.

Field searches use a separate scan ceiling so a small result can be found beyond the
ordinary inventory window. `PODPILOT_ADHOC_SEARCH_MAX_SCAN_OBJECTS` defaults to 2000 and
accepts 250–5000; in OpenShift set `data.adhoc_search_max_scan_objects` in
`podpilot-runtime`. Searches support exact/contains matching on validated dot-separated
object field paths, including paths through nested objects and lists. For a Route URL, the
model can select an exact hostname search. Search evidence reports
both match count and scanned count, plus whether a ceiling stopped the scan.
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
container restarts; PVC utilization percentage; Pod readiness; and top namespace,
Deployment, or node CPU/memory consumers. Pod, namespace, and Deployment scopes require an exact namespace; Pod and
Deployment scopes also require a name. Node scope requires an exact node name and may
optionally narrow to a namespace. PVC utilization requires an exact namespace/claim.
Deployment totals and rankings follow ReplicaSet/Pod ownership, including multiple ReplicaSets during a
rollout. Namespace and node rankings identify monitored namespace/Pod/container consumers. They cannot
identify arbitrary operating-system processes unless separate process-level telemetry is
installed. Overall node CPU and memory utilization uses node-exporter metrics. For “what is
using everything” questions, PodPilot collects both the overall node value and top workload
containers; a gap can represent kernel, filesystem cache, host services, or unmonitored work.
Requests and limits are configuration gauges, not measured usage.

`PODPILOT_ADHOC_METRICS_MAX_RANGE_SECONDS` defaults to 2592000 (30 days) and accepts up to
7776000 (90 days). `PODPILOT_ADHOC_METRICS_MAX_POINTS_PER_SERIES` defaults to 300 and accepts
50–1000. Configure `adhoc_metrics_max_range_seconds` and
`adhoc_metrics_max_points_per_series` in `podpilot-runtime`. PodPilot may increase the
requested step to stay within the point ceiling. Thanos retention, unavailable metrics,
series/response ceilings, and access failures are returned as explicit limitations.

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
bounded reads. While a run is active, a second turn and conversation deletion
return HTTP 409. Inspect phase transitions without payloads through
`podpilot.adhoc.*` application logs. The active assistant placeholder keeps only the latest six
human-readable updates, including the planner's bounded working hypothesis, its proposed next
check, and summaries of evidence actually found. These transient updates disappear when the
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

### Verify Milestone 3 workload evidence

Run the unit and sanitized evaluation suite, then confirm the deployed identity's
read ceiling and application readiness:

```powershell
.\.venv\Scripts\python.exe -m pytest --cov --cov-report=term-missing
. .\scripts\connect-sno.ps1
oc auth can-i get pods --all-namespaces --as=system:serviceaccount:ai-ops:podpilot-investigator
oc auth can-i get pods/log --all-namespaces --as=system:serviceaccount:ai-ops:podpilot-investigator
oc auth can-i get configmaps --all-namespaces --as=system:serviceaccount:ai-ops:podpilot-investigator
oc auth can-i get secrets --all-namespaces --as=system:serviceaccount:ai-ops:podpilot-investigator
oc -n ai-ops rollout status deployment/podpilot --timeout=180s
```

The investigator identity should allow Pod, event, controller, node, ConfigMap,
and Pod-log reads but not Secret reads. The separate disposable PoC cluster-admin
overlay affects only the `ai-observer` development identity. A workload investigation must persist collection failures,
not silently fall back to an empty evidence set. Crash-loop log collection is
limited to the alert-selected container's current and previous streams; image and
scheduling investigations do not collect logs.

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
