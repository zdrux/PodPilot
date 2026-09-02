# Hyper-V SNO Lab

Last reviewed: 2026-09-01
Update when: the lab topology, OpenShift version, access path, or monitoring state changes.

This records non-secret orientation facts imported from the predecessor task.
Treat them as a snapshot and re-verify live state before relying on them.

## Topology Snapshot

- Purpose: local PodPilot development and OpenShift troubleshooting tests.
- Platform: single-node OpenShift on a Generation 2 Hyper-V VM.
- OpenShift version observed during setup: 4.22.9.
- VM sizing: 12 vCPUs, 32 GB fixed RAM, 250 GB VHDX.
- Hyper-V settings: Secure Boot off, checkpoints disabled, external switch.
- Planned/reserved node IP: `192.168.0.200`.
- Lab cluster name/domain: `sno.192-168-0-200.sslip.io`.
- Kubernetes API: `https://api.sno.192-168-0-200.sslip.io:6443`.
- Application wildcard: `*.apps.sno.192-168-0-200.sslip.io`.
- Application namespace and identity: `ai-ops/podpilot-investigator`, bound to the narrow
  `podpilot-role-reader` ClusterRole for OpenShift Group lookup, not `cluster-reader`.
- Both the remote and SNO workload overlays inherit this role and binding from
  `deploy/openshift/base`; a fresh overlay deployment does not depend on pre-existing runtime RBAC.
- Development/break-glass identity: `ai-ops/ai-observer`, with `cluster-admin`
  through the explicitly labeled `podpilot-poc-cluster-admin` binding.
- The unrestricted-agent simulation uses a tokenless `oc-runner`; each cluster command receives a
  delegated-user broker capability. `scripts/deploy-agentic-sno.ps1` verifies application-role
  lookup and refuses to deploy if `podpilot-investigator` can patch Deployments.

The MAC address, installer files, kubeconfig, administrator credentials, and pull
secret are intentionally omitted. They do not belong in this repository.

## Known Monitoring Behavior

- Live verification on 2026-08-22 reported OpenShift `4.22.9` Available=True and Progressing=False.
- The `monitoring` ClusterOperator reported Available=True, Degraded=False, and Progressing=False.
- OpenShift's Cluster Monitoring Operator provides Prometheus, Alertmanager, Thanos Querier, and related components.
- The predecessor task successfully exercised the authenticated Alertmanager API route.
- The Alertmanager route exposes an API, not the historical Alertmanager root UI. A browser request to `/` can show “Application is not available” even while `/api/v2/...` works.
- Use the OpenShift console for the human alerting UI.
- `Watchdog` is expected to fire continuously.
- User-workload monitoring is enabled through
  `openshift-monitoring/cluster-monitoring-config`. The live SNO runs the user-workload
  Prometheus operator, one Prometheus replica, and one Thanos Ruler replica.
- The Community Strimzi operator `0.51.0` is installed cluster-wide from the `stable` channel in
  `openshift-operators`. Its Subscription uses automatic install-plan approval.
- The `kafka-observability` namespace contains the lab-only
  `kafka-observability-cluster`: one Kafka `4.2.0` node with combined broker/controller roles,
  Strimzi JMX Prometheus Exporter rules, Kafka Exporter, and the
  `kafka-resources-metrics` PodMonitor. The `podpilot-metrics-test` topic and
  `podpilot-metrics-probe` consumer group provide a small verification signal.
- Topic-first storage-display verification also uses `podpilot-orders-small` (2 partitions,
  approximately 0.1 MiB), `podpilot-payments-medium` (3 partitions, approximately 1 MiB), and
  `podpilot-audit-large` (4 partitions, approximately 6 MiB). These one-day-retention topics make
  ranking and expandable partition placement observable without materially filling the lab disk.
- Live Thanos verification found both Kafka scrape targets healthy and returned
  `kafka_log_log_size`, per-topic broker byte/message counters, and
  `kafka_consumergroup_lag`. PodPilot's registered `kafka_topic_disk_utilization` and
  `kafka_consumer_lag` readers both returned results for this fixture. The topic-storage view
  reports the three seeded topics with complete 2/3/4-partition detail on broker Pod
  `kafka-observability-cluster-sno-0`; the 50-partition internal `__consumer_offsets` topic is
  explicitly labeled as a bounded, incomplete 20-partition detail result.

## Limitations

- Hyper-V is a proof-of-concept lab platform here, not a supported production claim.
- SNO has no control-plane or monitoring high availability.
- It cannot validate multi-node scheduling, etcd quorum, node failover, or realistic HA alert behavior.
- Keep inference remote initially so it does not compete with etcd, the API server, and monitoring.
- The cluster originally had no StorageClass. PodPilot adds the non-default
  `podpilot-local` class and one static 5 Gi Retain-policy local PV at
  `/var/mnt/podpilot` for this SNO lab only.
- The local PV survives Pod replacement but not node loss/rebuild. Its nominal
  capacity is not a filesystem quota and it is not a production storage design.
- Kafka uses a second lab-only Retain-policy local PV named
  `kafka-observability-local-pv`, backed by `/var/mnt/kafka-observability` and advertised as
  10 Gi through the non-default `kafka-observability-local` StorageClass. The directory is not a
  filesystem quota: kubelet reports the capacity of the underlying node filesystem, so PodPilot's
  Kafka topic disk-utilization percentage uses that larger observed capacity rather than the PV's
  nominal 10 Gi. The single combined broker/controller has no Kafka availability or data-durability
  redundancy and remains a telemetry fixture only.
- The current `ai-ops` UID and supplemental-group allocation begins at
  `1000740000`; `/var/mnt/podpilot` is group-owned by that ID with mode `0770`.
  Re-verify and reinitialize ownership whenever the namespace or cluster is rebuilt.
- Live check on 2026-08-22 found no Service Mesh, Istio, VirtualService, or Kiali APIs/operators installed.

## Re-Verification

```powershell
oc whoami --show-server
oc get clusterversion
oc get clusteroperators
oc -n openshift-monitoring get pods
oc -n openshift-monitoring get route thanos-querier alertmanager-main
oc auth can-i --list --as=system:serviceaccount:ai-ops:ai-observer
oc get storageclass podpilot-local
oc -n ai-ops get pvc podpilot-data
oc -n openshift-operators get subscription strimzi-kafka-operator
oc -n openshift-user-workload-monitoring get pods
oc -n kafka-observability get kafka,kafkanodepool,kafkatopic,podmonitor,pvc
oc get storageclass kafka-observability-local
oc get pv kafka-observability-local-pv
```
