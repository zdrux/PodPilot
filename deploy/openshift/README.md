# OpenShift deployment artifacts

Use `overlays/remote-poc/` for a remote OpenShift proof of concept. It composes:

- `base/`: namespace, runtime ServiceAccount, narrow OpenShift Group lookup,
  supporting platform views, and explicit Alertmanager API RBAC in `openshift-monitoring`;
- `auth/group-rbac/`: namespace-local GUI admission for OpenShift's built-in
  `system:authenticated` group;
- `workload/`: SQLite PVC, runtime configuration, Deployment, OAuth proxy,
  Service, Route, NetworkPolicy, an empty fixed-name model-credential Secret with narrow RBAC,
  and the tokenless runner.

The remote PVC omits `storageClassName`; Kubernetes therefore uses the target
cluster's default StorageClass. No PV or StorageClass is created by the remote
overlay.

The remote overlay creates `ai-ops/podpilot` and `ai-ops/podpilot-oc-runner` ImageStreams and deploys tag
`0.12.0` through the stable internal-registry pull spec. Change `newTag` in its
Kustomization when promoting another tag; the external registry Route is needed
only to push from a workstation. Also replace the cluster name and elevated-role
JSON arrays in `overlays/remote-poc/`. Create the OAuth cookie out of band; the
workload creates the empty model-credential Secret and configuration administrators populate it
through the UI. PodPilot does not store remote cluster tokens. Full ordered instructions are in
[`docs/remote-poc-deployment.md`](../../docs/remote-poc-deployment.md).

Directories whose names identify a local lab are intentionally excluded from the
remote overlay.

The standard remote overlay includes the shared `components/agentic-runner/` sidecar and adds no
cluster mutation RBAC. Commands receive only a random loopback broker capability; the API injects
the selected user's memory-only token. `overlays/remote-poc-agentic/` remains as a compatibility
wrapper for longer Action deadlines. TLS verification is selected per cluster entry.

Upgrades from a pre-delegated manifest must remove the obsolete
`podpilot-investigator` ClusterRoleBinding after applying the current overlay; Kustomize does not
prune an object removed from its resource list. The replacement binding is
`podpilot-role-reader`, and `oc auth can-i get groups.user.openshift.io
--as=system:serviceaccount:ai-ops:podpilot-investigator` must return `yes` before rollout.
