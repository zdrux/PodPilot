# Disposable enterprise evaluation dependencies

Not included in any production overlay. Installed on the documented SNO on
2026-09-09 with explicit user authorization to add investigation dependencies.

- Red Hat Service Mesh operator 3.4.2 / Istio 1.30.4. The control plane watches only
  namespaces labeled `podpilot.io/mesh-eval=true`; injection requires the explicit
  `istio.io/rev=podpilot-eval` label. CNI is the operator-managed `default` resource.
- Red Hat Logging and Loki operators 6.6.0. LokiStack `1x.demo` is non-HA and only
  suitable for this light lab. A one-day retention limit applies.
- Collector is restricted by configuration to `podpilot-eval-*` application logs.
  Its standard application-log collection role can read node application logs;
  the configured filter is not a separate RBAC isolation boundary. No platform
  audit/infrastructure collection is enabled. Production requires separate sizing,
  storage, retention, collection policy and access review.
- SeaweedFS 4.46 is an authenticated S3 fixture, image pinned by digest. Random
  credentials live only in `openshift-logging/podpilot-eval-loki-s3`. Its HTTPS
  certificate is issued by OpenShift Service CA. No public Route exists. An ingress
  policy permits only namespace-local access to TLS port 8334. Telemetry is off.
- Loki preserves OpenShift gateway authentication and delegated-user authorization.
  PodPilot's configured application-log endpoint matches the actual gateway Service.

## Dedicated storage

The original `lvms-vg1` has only a 9 GiB thin pool. Loki's four 10 GiB claims could
not fit. A new 60 GiB dynamic VHDX was attached online to `ocp-sno`, SCSI 0:2:

`C:\ProgramData\Microsoft\Windows\Virtual Hard Disks\ocp-sno-enterprise-eval.vhdx`

Guest identity was verified as empty, unmounted 60 GiB device with WWN
`0x6002248009fad22005e448f9e0f7e39b`. The additional `enterprise-eval` device class
uses an explicit stable path, no forced wiping, 90% pool size and no
overprovisioning. It provides non-default `lvms-enterprise-eval`. The existing
device class and default StorageClass remain in place. The 5 GiB S3 PVC currently
uses `lvms-vg1`; the four Loki PVCs use the new class.

`lvm-device-class-patch.json` is a one-time append, not an idempotent apply file.
Inspect the live device classes before reuse. Never apply it to another machine.
`scripts/recreate-empty-loki-claims.py` was used once to replace only unbound Pending
claims after selecting the new class; it refuses bound claims and foreign UIDs.
It is not a populated-volume migration procedure.

Operator install plans were inspected and explicitly approved. Current manifests
passed server validation. Verify `LokiStack Ready`, `ClusterLogForwarder Ready`,
`Istio Ready`, actual retained-query results and node pressure before evaluations.
Do not delete operators or storage indiscriminately during cleanup: other users
may adopt them. Scenario cleanup removes only run-labeled, UID-matched fixtures.

References: [LokiStack demo constraints](https://github.com/grafana/loki/blob/main/operator/docs/operator/api.md),
[SeaweedFS mini](https://github.com/seaweedfs/seaweedfs/blob/4.46/README.md),
[Red Hat Service Mesh](https://docs.redhat.com/en/documentation/red_hat_openshift_service_mesh/3.3/html-single/about/about).
