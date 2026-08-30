# OpenShift deployment artifacts

Use `overlays/remote-poc/` for a remote OpenShift proof of concept. It composes:

- `base/`: namespace, runtime ServiceAccount, legacy dashboard read access,
  and explicit Alertmanager API RBAC in `openshift-monitoring`;
- `auth/group-rbac/`: namespace-local GUI admission for OpenShift's built-in
  `system:authenticated` group;
- `workload/`: SQLite PVC, runtime configuration, Deployment, OAuth proxy,
  Service, Route, NetworkPolicy, fixed model-credential Secret RBAC, and the tokenless runner.

The remote PVC omits `storageClassName`; Kubernetes therefore uses the target
cluster's default StorageClass. No PV or StorageClass is created by the remote
overlay.

The remote overlay creates `ai-ops/podpilot` and `ai-ops/podpilot-oc-runner` ImageStreams and deploys tag
`0.12.0` through the stable internal-registry pull spec. Change `newTag` in its
Kustomization when promoting another tag; the external registry Route is needed
only to push from a workstation. Also replace the cluster name and elevated-role
JSON arrays in `overlays/remote-poc/`. Create the OAuth cookie and empty
model-credential Secret out of band. PodPilot does not store remote cluster tokens. Full ordered instructions are in
[`docs/remote-poc-deployment.md`](../../docs/remote-poc-deployment.md).

Directories whose names identify a local lab are intentionally excluded from the
remote overlay.

The standard remote overlay includes the shared `components/agentic-runner/` sidecar and adds no
cluster mutation RBAC. Commands receive only a random loopback broker capability; the API injects
the selected user's memory-only token. `overlays/remote-poc-agentic/` remains as a compatibility
wrapper for longer Action deadlines. TLS verification is selected per cluster entry.
