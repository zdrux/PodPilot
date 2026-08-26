# OpenShift deployment artifacts

Use `overlays/remote-poc/` for a remote OpenShift proof of concept. It composes:

- `base/`: namespace, runtime ServiceAccount, `cluster-reader`, monitoring access,
  and explicit Alertmanager API RBAC in `openshift-monitoring`;
- `auth/group-rbac/`: namespace-local GUI admission for OpenShift's built-in
  `system:authenticated` group;
- `workload/`: SQLite PVC, runtime configuration, Deployment, OAuth proxy,
  Service, Route, NetworkPolicy, and fixed model- and cluster-credential Secret RBAC.

The remote PVC omits `storageClassName`; Kubernetes therefore uses the target
cluster's default StorageClass. No PV or StorageClass is created by the remote
overlay.

The remote overlay creates the `ai-ops/podpilot` ImageStream and deploys tag
`0.12.0` through the stable internal-registry pull spec. Change `newTag` in its
Kustomization when promoting another tag; the external registry Route is needed
only to push from a workstation. Also replace the cluster name and elevated-role
JSON arrays in `overlays/remote-poc/`. Create the OAuth cookie and empty
model- and cluster-credential Secrets out of band. Full ordered instructions are in
[`docs/remote-poc-deployment.md`](../../docs/remote-poc-deployment.md).

Directories whose names identify a local lab are intentionally excluded from the
remote overlay.
