# PodPilot Operations

Last reviewed: 2026-08-23
Update when: setup, environment variables, deployment, external services, or runbooks change.

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

The current external bootstrap kubeconfig is used as the helper's fallback path.
If it moves, set the path for the current shell without copying the file:

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
backend. PodPilot resolves its application role from the named OpenShift groups.

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
- `PODPILOT_ALERTMANAGER_URL`, defaulting to the in-cluster
  `https://alertmanager-main.openshift-monitoring.svc:9094`
- `PODPILOT_SERVICE_ACCOUNT_TOKEN_PATH`, default projected token path
- `PODPILOT_SERVICE_CA_PATH`, default projected OpenShift service CA path
- `PODPILOT_ALERTMANAGER_TIMEOUT_SECONDS`, default `8`
- `PODPILOT_ALERTMANAGER_MAX_ALERTS`, default `250`
- `PODPILOT_WORKLOAD_MAX_EVENTS`, default `30`
- `PODPILOT_WORKLOAD_LOG_TAIL_LINES`, default `200`
- `PODPILOT_WORKLOAD_MAX_LOG_BYTES`, default `16384` per collected log stream
- `PODPILOT_MODEL_CREDENTIAL_STORE`, `environment` for local development or
  `kubernetes` in the OpenShift workload
- `PODPILOT_MODEL_SECRET_NAMESPACE`, default `ai-ops`
- `PODPILOT_MODEL_SECRET_NAME`, default `podpilot-model-credentials`
- `PODPILOT_MODEL_SECRET_KEY`, default `api_key`
- `PODPILOT_POC_MODE=true` for the lab-only runtime policy

Model profile metadata (base URL, model names, timeout, and output-token budget)
is configured through `/settings/model`, not environment variables. Local
development reads `OPENAI_API_KEY` without persisting it. OpenShift uses the fixed
Secret above; the UI never reads the saved value back.

Later integrations may add:

- investigation limits and timeouts
- optional custom CA Secret reference for internal providers
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
   $cookie = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
   oc -n ai-ops create secret generic podpilot-oauth-cookie --from-literal=session_secret=$cookie --dry-run=client -o yaml | oc apply -f -
   Remove-Variable cookie
   ```

   Create or replace the model Secret directly from the local OpenAI key
   without printing it or writing it to disk:

   ```powershell
   if ([string]::IsNullOrWhiteSpace($env:OPENAI_API_KEY)) { throw "OPENAI_API_KEY is not set" }
   oc -n ai-ops create secret generic podpilot-model-credentials --from-literal=api_key=$env:OPENAI_API_KEY --dry-run=client -o yaml | oc apply -f -
   ```

   Open `/settings/model` as an Approver, save the metadata with the token field
   blank, and run **Test connection**. A profile is used only when every required
   capability passes. Rotate the provider key if it ever appears in terminal or
   application output.

   `model-credentials.yaml` documents the fixed Secret identity but is deliberately
   excluded from the workload kustomization so a later manifest apply cannot erase
   an existing token.

5. Validate and deploy the complete SNO overlay, then add the separate PoC
   cluster-admin exception:

   ```powershell
   oc apply --dry-run=server -k deploy/openshift/overlays/sno-milestone-one
   oc apply -k deploy/openshift/overlays/sno-milestone-one
   oc apply -k deploy/openshift/overlays/poc-cluster-admin
   oc -n ai-ops rollout status deployment/podpilot --timeout=180s
   ```

6. Audit effective access and application health:

   ```powershell
   oc auth can-i --list --as=system:serviceaccount:ai-ops:ai-observer
   oc -n ai-ops get deployment,pod,service,route,pvc
   $pod = oc -n ai-ops get pod -l app.kubernetes.io/name=podpilot -o jsonpath='{.items[0].metadata.name}'
   oc -n ai-ops exec $pod -c api -- python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8080/health/ready').read().decode())"
   ```

Review `deploy/openshift/rbac.yaml` whenever a diagnostic adds a new API dependency.
Production packaging must omit both SNO overlays, use a supported storage class,
and pin an immutable application image digest.

### Typed remediation in the PoC lab

The reusable observer RBAC remains read-only. The disposable SNO lab's explicit
`poc-cluster-admin` overlay currently supplies mutation authority while the action
catalog is being evaluated. PodPilot nevertheless exposes only controller-owned
failed-Pod replacement and Deployment/StatefulSet/DaemonSet rollout restart.

For every live action, confirm the investigation shows `server dry-run: passed`,
the expected UID/resourceVersion, target namespace, operation, verification, and
recovery note. Use an Approver test identity, expand **Review approval**, and only
then press **Approve and run**. A stale or expired preview must be regenerated by
creating a fresh investigation. Do not retry a mutation from an old investigation.

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
# After PodPilot creates the preview, make the next Pod healthy without changing its Pod/ReplicaSet preconditions:
oc -n podpilot-remediation-fixture patch configmap fixture-mode --type=merge --patch '{"data":{"MODE":"healthy"}}'
# Approve only the controller-owned Pod replacement in the UI, verify the new UID is Ready, then remove the exact lab resources:
oc delete prometheusrule podpilot-remediation-fixture -n openshift-monitoring
oc delete namespace podpilot-remediation-fixture
```

The fixture rule is installed in `openshift-monitoring` because user-workload
monitoring is disabled on this SNO. The rule observes only the disposable
fixture namespace; PodPilot still rejects remediation targets in protected
system namespaces.

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
oc auth can-i get pods --all-namespaces --as=system:serviceaccount:ai-ops:ai-observer
oc auth can-i get pods/log --all-namespaces --as=system:serviceaccount:ai-ops:ai-observer
oc auth can-i get secrets --all-namespaces --as=system:serviceaccount:ai-ops:ai-observer
oc -n ai-ops rollout status deployment/podpilot --timeout=180s
```

The reusable observer role should allow Pod, event, controller, node, and Pod-log
reads but not Secret reads. The separate disposable PoC cluster-admin overlay makes
the live lab identity broader, so review `deploy/openshift/rbac.yaml` to evaluate
the production ceiling. A workload investigation must persist collection failures,
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
