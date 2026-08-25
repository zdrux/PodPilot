# OpenShift deployment artifacts

Use `overlays/remote-poc/` for a remote OpenShift proof of concept. It composes:

- `base/`: namespace, runtime ServiceAccount, `cluster-reader`, monitoring access,
  and explicit Alertmanager API RBAC in `openshift-monitoring`;
- `auth/group-rbac/`: namespace-local GUI admission for OpenShift's built-in
  `system:authenticated` group;
- `workload/`: SQLite PVC, runtime configuration, Deployment, OAuth proxy,
  Service, Route, NetworkPolicy, and fixed model-credential Secret RBAC.

The remote PVC omits `storageClassName`; Kubernetes therefore uses the target
cluster's default StorageClass. No PV or StorageClass is created by the remote
overlay.

Before applying, replace the example image, cluster name, and elevated-role JSON
arrays in `overlays/remote-poc/`. Create the OAuth cookie and empty
model-credential Secrets out of band. Full ordered instructions are in
[`docs/remote-poc-deployment.md`](../../docs/remote-poc-deployment.md).

Directories whose names identify a local lab are intentionally excluded from the
remote overlay.
