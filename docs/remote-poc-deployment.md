# Remote OpenShift PoC Deployment

Last reviewed: 2026-08-24

This runbook installs one read-only PodPilot replica on an existing OpenShift
cluster with real workloads. It uses the cluster's existing OAuth identities,
default dynamic storage, Cluster Monitoring stack, and an externally pushed
PodPilot image. It does not grant PodPilot mutation rights.

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
   built-in `cluster-reader` and `cluster-monitoring-view` ClusterRoles. A narrow
   Role in `openshift-monitoring` grants `get`/`list` on only
   `monitoring.coreos.com` `alertmanagers/api` named `main`. A separate Role can
   read and patch only `ai-ops/podpilot-model-credentials`.

Platform Alertmanager runs in `openshift-monitoring`, not `openshift-logging`.
No logging-namespace Role is required for Alertmanager. Ordinary container logs
are read through the Kubernetes `pods/log` subresource under `cluster-reader`.
Direct Loki/Log Store querying is not implemented and would require a separate,
future authorization design.

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

## 3. Build and push the image

The repository root contains the production-shaped `Dockerfile`. It uses a
digest-pinned Red Hat UBI 9 Python 3.12 base, installs the locked dependencies,
contains no `oc` binary, and runs as a non-root user.

Docker example:

```bash
export PODPILOT_IMAGE=registry.example.com/your-org/podpilot
export PODPILOT_VERSION=0.11.0
docker login registry.example.com
docker build --pull -t ${PODPILOT_IMAGE}:${PODPILOT_VERSION} .
docker push ${PODPILOT_IMAGE}:${PODPILOT_VERSION}
docker inspect --format='{{index .RepoDigests 0}}' ${PODPILOT_IMAGE}:${PODPILOT_VERSION}
```

Podman uses the same `build`, `push`, and `inspect` arguments. Record the pushed
`repository@sha256:...` digest. If the target uses a private or mirrored registry,
create a pull Secret and link it to the runtime ServiceAccount after step 5:

```bash
oc -n ai-ops create secret docker-registry podpilot-registry-pull \
  --docker-server=registry.example.com --docker-username='<username>' \
  --docker-password='<token>' --docker-email='<email>'
oc -n ai-ops secrets link podpilot-investigator podpilot-registry-pull --for=pull
```

Never commit registry credentials or generated pull Secrets.

## 4. Configure the remote overlay

Edit `deploy/openshift/overlays/remote-poc/kustomization.yaml`:

```yaml
images:
  - name: podpilot
    newName: registry.example.com/your-org/podpilot
    digest: sha256:REPLACE_WITH_PUSHED_DIGEST
```

Use `digest`, not a mutable tag, for the deployment candidate. Edit
`deploy/openshift/overlays/remote-poc/runtime-config-patch.yaml` and replace
`replace-with-target-cluster-name` with a recognizable non-secret cluster name.
In the same file, replace each role's JSON array with exact existing OpenShift
Group resource names for Investigator, Approver, and Breakglass. Multiple
synchronized LDAP groups can map to one elevated role; use `[]` for an unused
role. A group may appear in only one role array. Viewer has no group mapping:
every identity authenticated by OpenShift receives that role automatically.

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
$cookie = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
oc -n ai-ops create secret generic podpilot-oauth-cookie --from-literal=session_secret=$cookie --dry-run=client -o yaml | oc apply -f -
Remove-Variable cookie
```

Bash:

```bash
cookie="$(openssl rand -base64 32)"
oc -n ai-ops create secret generic podpilot-oauth-cookie \
  --from-literal=session_secret="$cookie" --dry-run=client -o yaml | oc apply -f -
unset cookie
```

Create the empty, fixed-name model credential Secret. Approvers add model tokens
later through the GUI, and PodPilot patches per-profile keys dynamically:

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
only on its exact model-credential Secret in `ai-ops`.
The PVC must be `Bound`, the Deployment `1/1 Available`, and the migration log
must end at the repository's current Alembic head.

Verify admission independently with any existing authenticated username:

```bash
oc auth can-i get service/podpilot -n ai-ops --as='<configured-group-member>'
oc get route podpilot -n ai-ops -o jsonpath='https://{.spec.host}{"\n"}'
```

Open the Route in a clean browser session. OpenShift OAuth authenticates the user;
the namespace Role admits the group; PodPilot shows the group-derived application
role in the lower-left identity area.

## 9. Configure and test a model

Sign in as a `podpilot-approvers` user. In **Model settings**, add the endpoint,
API type, model ID, token, TLS mode, and limits. Test the endpoint before
activation. Prefer system trust or a custom CA. Insecure TLS disables certificate
and hostname verification and is inappropriate for a real-workload cluster.

Start with read-only questions against a designated test namespace. Confirm
evidence scope, redaction, Pod-log access, Alertmanager freshness, and audit
attribution before widening the user group.

## 10. Rollback and removal

For application rollback, restore the previous image digest in the remote
Kustomization, run the server dry run, apply it, and wait for rollout. Alembic
migrations are forward-only operationally; take a CSI snapshot or supported
volume backup before upgrading a valuable PoC database.

Do not use `oc delete -k` casually because it includes the PVC. To stop PodPilot
while preserving state, scale the Deployment to zero. Remove cluster bindings,
monitoring RBAC, Route, Service, and Deployment explicitly only after reviewing
their exact names. Delete `podpilot-data` only after its SQLite history is no
longer required and a recoverable backup exists.
