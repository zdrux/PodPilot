# Remote OpenShift PoC Deployment

Last reviewed: 2026-08-24

This runbook installs one read-only PodPilot replica on an existing OpenShift
cluster with real workloads. It uses the cluster's existing OAuth identities,
default dynamic storage, Cluster Monitoring stack, and an externally pushed
PodPilot image. It does not grant PodPilot mutation rights.

The guarded `remote-poc` overlay is the default. The optional
`remote-poc-agentic` overlay inherits that configuration and adds the unrestricted
localhost `oc-runner` sidecar. It does not add RBAC; every command still runs as
`ai-ops/podpilot-investigator` with the permissions already granted by the base.

## 1. Understand the authorization boundaries

There are two separate authorization paths:

1. **Human GUI access** uses OpenShift OAuth and namespace-local RBAC. The OAuth
   proxy admits a user only when a SubjectAccessReview permits `get` on the exact
   `ai-ops/podpilot` Service. A RoleBinding grants that permission to OpenShift's
   built-in `system:authenticated` group. FastAPI assigns Viewer by default and
   reads configured LDAP-synchronized groups only to grant an elevated role.
   Human users do not receive `cluster-reader` or workload permissions.
2. **Cluster investigation access** belongs to the
`ai-ops/podpilot-investigator` ServiceAccount. ClusterRoleBindings attach the
built-in `cluster-reader`, `cluster-monitoring-view`,
`cluster-logging-application-view`, `cluster-logging-infrastructure-view`, and
`cluster-logging-audit-view` ClusterRoles. A narrow
   Role in `openshift-monitoring` grants `get`/`list` on only
   `monitoring.coreos.com` `alertmanagers/api` named `main`. A separate Role can
   read and patch only `ai-ops/podpilot-model-credentials`.

Platform Alertmanager runs in `openshift-monitoring`, not `openshift-logging`.
No logging-namespace Role is required for Alertmanager. Ordinary container logs
are read through the Kubernetes `pods/log` subresource under `cluster-reader`.
Aggregate Loki application-log analytics are implemented for registered namespace, Pod, and Node
volume queries. They use only server-owned LogQL and retain no log lines. The installation must
expose a standard `openshift-logging/logging-loki` Route and
grant the registered identity `cluster-logging-application-view` plus cluster-wide LokiStack
OpenShift authorization. The base runtime identity also receives the read-only infrastructure
and audit logging views. Arbitrary LogQL and raw Log Store queries remain unavailable.

## 2. Prerequisites

- A cluster administrator performs the installation because it creates
  ClusterRoleBindings and RBAC in `openshift-monitoring`.
- The target has Cluster Monitoring with the built-in `cluster-reader` and
  `cluster-monitoring-view` ClusterRoles.
- Exactly one suitable default StorageClass can dynamically provision a 5 GiB
  `ReadWriteOnce` volume.
- Cluster nodes can pull from the selected image registry.
- The `ai-ops` namespace can reach the Kubernetes API, in-cluster Alertmanager
  and Thanos services, and the configured model endpoint.
- The workstation has Git, Docker or Podman, and `oc` authenticated to the target.

Confirm the cluster and storage before changing anything:

```bash
oc whoami
oc get clusterversion
oc get clusterrole cluster-reader cluster-monitoring-view
oc get storageclass
oc get storageclass -o jsonpath='{range .items[?(@.metadata.annotations.storageclass\.kubernetes\.io/is-default-class=="true")]}{.metadata.name}{"\n"}{end}'
```

Stop if no default class is returned. The portable PVC intentionally omits
`storageClassName`; omission is Kubernetes' mechanism for requesting the default
class. PodPilot does not create a StorageClass or PersistentVolume remotely.

## 3. Build and push the ImageStreamTag

The repository root contains the production-shaped `Dockerfile`. It uses a
digest-pinned Red Hat UBI 9 Python 3.12 base, installs the locked dependencies,
contains no `oc` binary, and runs as a non-root user.

Create the namespace and ImageStream before the first push. These operations are
idempotent and are also included in the complete overlay:

```bash
oc apply -f deploy/openshift/base/namespace.yaml
oc apply -f deploy/openshift/overlays/remote-poc/image-stream.yaml
```

Use the integrated registry's external Route for the workstation push:

```bash
export PODPILOT_VERSION=0.12.0
export REGISTRY_HOST="$(oc get route default-route -n openshift-image-registry -o jsonpath='{.spec.host}')"
export PUSH_IMAGE="${REGISTRY_HOST}/ai-ops/podpilot:${PODPILOT_VERSION}"
oc whoami -t | podman login -u "$(oc whoami)" --password-stdin "${REGISTRY_HOST}"
podman build --pull -t "${PUSH_IMAGE}" .
podman push "${PUSH_IMAGE}"
oc get imagestreamtag "podpilot:${PODPILOT_VERSION}" -n ai-ops
```

For unrestricted mode, create the runner ImageStream and build and push the
second image with the same immutable version:

```bash
oc apply -f deploy/openshift/overlays/remote-poc-agentic/image-stream.yaml
export RUNNER_IMAGE="${REGISTRY_HOST}/ai-ops/podpilot-oc-runner:${PODPILOT_VERSION}"
podman build --pull -f Dockerfile.oc-runner -t "${RUNNER_IMAGE}" .
podman push "${RUNNER_IMAGE}"
oc get imagestreamtag "podpilot-oc-runner:${PODPILOT_VERSION}" -n ai-ops
```

The runner Dockerfile copies Linux `oc` from its digest-pinned CLI build stage.
For an air-gapped target, mirror both pinned `FROM` images into an approved
internal registry and update the Dockerfile references before building; do not
copy a workstation `oc.exe` into the Linux image.

Docker can replace Podman in the build and push commands. If `default-route` does
not exist, a cluster administrator must enable the integrated registry's default
Route. Never commit the login token or generated registry configuration.

## 4. Configure the remote overlay

Edit `deploy/openshift/overlays/remote-poc/kustomization.yaml`:

```yaml
images:
  - name: podpilot
    newName: image-registry.openshift-image-registry.svc:5000/ai-ops/podpilot
    newTag: 0.12.0
```

The push uses the external Route, while Pods use the stable internal Service
hostname above. A Kubernetes Deployment still needs an OCI image pull spec;
Kustomize renders that pull spec from the `ai-ops/podpilot:0.12.0` ImageStreamTag.
Use a new versioned tag for each promotion instead of overwriting an existing tag.
When using unrestricted mode, set the matching immutable runner `newTag` in
`deploy/openshift/overlays/remote-poc-agentic/kustomization.yaml` as well.

Edit `deploy/openshift/overlays/remote-poc/runtime-config-patch.yaml` and replace
`replace-with-target-cluster-name` with a recognizable non-secret cluster name.
In the same file, replace each role's JSON array with exact existing OpenShift
Group resource names for Investigator, Approver, and Breakglass. Multiple
synchronized LDAP groups can map to one elevated role; use `[]` for an unused
role. A group may appear in only one role array. Viewer has no group mapping:
every identity authenticated by OpenShift receives that role automatically.
The base runtime ConfigMap defaults `adhoc_inventory_max_objects` to `"500"` for
returned LIST evidence and `adhoc_search_max_scan_objects` to `"2000"` for bounded
projected-field searches that return only matches.
Metric trends default to a 30-day range and 300 points per series through
`adhoc_metrics_max_range_seconds: "2592000"` and
`adhoc_metrics_max_points_per_series: "300"`. Thanos response bodies default to a bounded
1 MiB through `adhoc_metrics_max_response_bytes: "1048576"`; set it between `"65536"` and
`"4194304"` when the target routinely returns more metric series or label data.

Group names are case-sensitive. Later changes to the role-group arrays require an
application rollout because ConfigMap-backed environment variables are read at
Pod start. LDAP membership changes within an already configured group do not
require a rollout; they become visible after the role cache expires (30 seconds
by default).

Review the rendered objects before connecting them to the API:

```bash
oc kustomize deploy/openshift/overlays/remote-poc > podpilot-rendered.yaml
```

The rendered file is a review artifact and should not be committed. Confirm it
contains no `storageClassName`, node name, local path, lab hostname, token, or
cluster-admin binding. Delete the rendered file after review.

## 5. Create namespace and runtime Secrets

Create the namespace first:

```bash
oc apply -f deploy/openshift/base/namespace.yaml
```

Create a random OAuth cookie key without printing or committing it. PowerShell:

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

Bash:

```bash
cookie_file="$(mktemp)"
trap 'rm -f "$cookie_file"' EXIT
chmod 600 "$cookie_file"
openssl rand 32 > "$cookie_file"
oc -n ai-ops create secret generic podpilot-oauth-cookie \
  --from-file="session_secret=$cookie_file" --dry-run=client -o yaml | oc apply -f -
rm -f "$cookie_file"
trap - EXIT
```

The mounted Secret value must be exactly 16, 24, or 32 raw bytes because cookie
refresh uses AES. Confirm the generated value is 32 bytes without printing it:

```bash
test "$(oc get secret podpilot-oauth-cookie -n ai-ops \
  -o jsonpath='{.data.session_secret}' | base64 -d | wc -c)" -eq 32
```

Create the empty, fixed-name model credential Secret. Configuration administrators
add model endpoints later through the GUI. Remote-cluster credentials are user-delegated
and are not stored in PodPilot Secrets:

```bash
oc get secret podpilot-model-credentials -n ai-ops >/dev/null 2>&1 || \
  oc create -f deploy/openshift/workload/model-credentials.yaml
```

## 6. Verify existing LDAP-synchronized elevated-role groups

Use identities supplied by the target cluster's existing OAuth identity provider;
no HTPasswd provider and no PodPilot-managed Group are required. No group is
needed for Viewer. Confirm every configured elevated-role name exists as an
OpenShift Group and contains the expected synced members:

```bash
oc get groups.user.openshift.io
oc get group corp-ocp-observers -o yaml
oc get group corp-ocp-operators -o yaml
oc get group corp-ocp-admins -o yaml
```

The remote overlay never creates, edits, or synchronizes Group membership. LDAP
remains authoritative. A user in multiple configured groups receives the highest
role in this order: Breakglass, Approver, Investigator, Viewer. An authenticated
user in none of those groups receives Viewer. A missing configured Group causes
role resolution to fail closed rather than silently granting a lower role.
Breakglass remains an application role only; it does not grant OpenShift
`cluster-admin`.

## 7. Validate and apply the manifests

Run a server-side dry run, inspect the diff, and then apply the same overlay:

```bash
oc apply --dry-run=server -k deploy/openshift/overlays/remote-poc
oc diff -k deploy/openshift/overlays/remote-poc
oc apply -k deploy/openshift/overlays/remote-poc
oc -n ai-ops rollout status deployment/podpilot --timeout=300s
```

To install the optional unrestricted variant, substitute the additive overlay
in all three commands:

```bash
oc apply --dry-run=server -k deploy/openshift/overlays/remote-poc-agentic
oc diff -k deploy/openshift/overlays/remote-poc-agentic
oc apply -k deploy/openshift/overlays/remote-poc-agentic
oc -n ai-ops rollout status deployment/podpilot --timeout=300s
```

Do not set `agent_mode=unrestricted` on the guarded overlay by itself; without
the sidecar, no runner listens on `127.0.0.1:8090`.

For a later role-mapping ConfigMap change, explicitly restart after applying:

```bash
oc -n ai-ops rollout restart deployment/podpilot
oc -n ai-ops rollout status deployment/podpilot --timeout=300s
```

The overlay applies, in dependency-safe form:

- `base/namespace.yaml`, `base/service-account.yaml`, and `base/rbac.yaml`;
- `auth/group-rbac/ui-access-rbac.yaml`, admitting `system:authenticated` to the
  exact PodPilot Service;
- `workload/runtime-config.yaml` and `workload/persistentvolumeclaim.yaml`;
- `workload/model-credentials-rbac.yaml`;
- `workload/deployment.yaml`, `service.yaml`, `route.yaml`, and
  `network-policy.yaml`.

The OAuth cookie and model credential Secret values remain out-of-band.

## 8. Verify access before inviting users

```bash
SA='system:serviceaccount:ai-ops:podpilot-investigator'
oc auth can-i get pods --all-namespaces --as="$SA"
oc auth can-i get pods --subresource=log --all-namespaces --as="$SA"
oc auth can-i get configmaps --all-namespaces --as="$SA"
oc auth can-i get groups.user.openshift.io --as="$SA"
oc auth can-i get secrets --all-namespaces --as="$SA"
oc auth can-i get secret/podpilot-model-credentials -n ai-ops --as="$SA"
oc auth can-i get secret/example-unrelated-secret -n ai-ops --as="$SA"
oc auth can-i patch deployments --all-namespaces --as="$SA"
oc auth can-i get alertmanagers.monitoring.coreos.com/main --subresource=api \
  -n openshift-monitoring --as="$SA"

oc -n ai-ops get pvc podpilot-data
oc -n ai-ops get deployment,pod,service,route
oc -n ai-ops logs deployment/podpilot -c migrate
oc -n ai-ops logs deployment/podpilot -c api --since=10m
```

Expected results are `yes` for Pods, Pod logs, ConfigMaps, Groups, the exact model
credential Secret, and the named Alertmanager API. Expect `no` for cluster-wide
Secrets, the unrelated Secret, and Deployment patch. PodPilot has `get`/`patch`
only on its exact model credential Secret in `ai-ops`.
The PVC must be `Bound`, the Deployment `1/1 Available`, and the migration log
must end at the repository's current Alembic head.

For the agentic overlay, verify the runner is a third container in the same Pod
and that the runtime identity has not gained mutation access:

```bash
oc -n ai-ops get deployment podpilot \
  -o jsonpath='{.spec.template.spec.containers[*].name}{"\n"}'
oc -n ai-ops get configmap podpilot-runtime \
  -o jsonpath='{.data.agent_mode}{"\n"}'
oc -n ai-ops get configmap podpilot-runtime \
  -o jsonpath='{.data.agent_command_timeout_seconds}{" "}{.data.agent_command_max_output_bytes}{" "}{.data.agent_heartbeat_seconds}{"\n"}'
oc -n ai-ops exec deployment/podpilot -c oc-runner -- oc version --client
oc auth can-i patch deployments --all-namespaces --as="$SA"
```

Expected results include `oc-runner api oauth-proxy`, `unrestricted`, `300 262144 10`, a Linux
OpenShift CLI client version, and the RBAC result appropriate to the remote
identity. Review any `yes` result before exposing agentic mode; the sidecar will
be able to exercise every permission granted to that service account.

In a multi-cluster Ask session, the API resolves the token for each model-selected cluster
from the in-memory delegated session and passes it only over Pod loopback for that command.
The runner follows the selected cluster's TLS policy, deletes the per-command kubeconfig,
and logs only cluster identity, TLS mode, exit code,
duration, and output byte counts:

```bash
oc logs -n ai-ops deployment/podpilot -c oc-runner --since=10m
oc logs -n ai-ops deployment/podpilot -c api --since=10m | grep podpilot.agentic.command
```

The runner and API suppress periodic idle, command, runtime, and model-wait heartbeat log entries.
The API still pushes changing elapsed-time messages into the live Ask timeline. At 300 seconds the
runner terminates the shell process group and returns exit code `124`; the complete Ask run still
expires at 900 seconds, and model waits still use the model profile's provider timeout.

Verify admission independently with any existing authenticated username:

```bash
oc auth can-i get service/podpilot -n ai-ops --as='<configured-group-member>'
oc get route podpilot -n ai-ops -o jsonpath='https://{.spec.host}{"\n"}'
```

Open the Route in a clean browser session. OpenShift OAuth authenticates the user;
the namespace Role admits authenticated identities; PodPilot shows Viewer or the
group-derived elevated role in the lower-left identity area.

## 9. Configure and test a model

Sign in as a `podpilot-approvers` user. In **Model settings**, add the endpoint,
API type, model ID, token, TLS mode, and limits. Test the endpoint before
activation. Prefer system trust or a custom CA. Insecure TLS disables certificate
and hostname verification and is inappropriate for a real-workload cluster.

Unrestricted mode requires a Chat Completions profile that passes the tool-call
capability probe. Responses API profiles remain valid for guarded mode but cannot
drive the unrestricted `execute_shell` loop.

Start with read-only questions against a designated test namespace. Confirm
evidence scope, redaction, Pod-log access, Alertmanager freshness, and audit
attribution before widening the user group.

## 10. Rollback and removal

For application rollback, restore the previous versioned `newTag` in the remote
Kustomization, run the server dry run, apply it, and wait for rollout. If an
existing tag was overwritten, explicitly restart `deployment/podpilot`; tag
changes do not otherwise guarantee a new rollout. Alembic migrations are
forward-only operationally; take a CSI snapshot or supported volume backup before
upgrading a valuable PoC database.

Do not use `oc delete -k` casually because it includes the PVC. To stop PodPilot
while preserving state, scale the Deployment to zero. Remove cluster bindings,
monitoring RBAC, Route, Service, and Deployment explicitly only after reviewing
their exact names. Delete `podpilot-data` only after its SQLite history is no
longer required and a recoverable backup exists.
