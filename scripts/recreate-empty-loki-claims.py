"""One-time SNO repair after selecting the dedicated evaluation storage class.

Refuses any bound volume, non-Pending claim, or foreign controller. No stored logs
may exist. Never use this procedure to migrate a populated LokiStack.
"""
import time
from kubernetes import client, config

config.load_kube_config()
if client.Configuration.get_default_copy().host.rstrip("/") != "https://api.sno.192-168-0-200.sslip.io:6443":
    raise RuntimeError("SNO only")
core, apps, custom = client.CoreV1Api(), client.AppsV1Api(), client.CustomObjectsApi()
ns = "openshift-logging"
stack = custom.get_namespaced_custom_object("loki.grafana.com", "v1", ns, "lokistacks", "logging-loki")
assert stack["spec"]["storageClassName"] == "lvms-enterprise-eval"
names = ["logging-loki-compactor", "logging-loki-index-gateway", "logging-loki-ingester"]
sets, claims = [], []
for name in names:
    obj = apps.read_namespaced_stateful_set(name, ns)
    assert not obj.status.ready_replicas
    assert any(o.uid == stack["metadata"]["uid"] for o in obj.metadata.owner_references or [])
    sets.append(obj)
    for template in obj.spec.volume_claim_templates:
        claim = core.read_namespaced_persistent_volume_claim(template.metadata.name + "-" + name + "-0", ns)
        assert claim.status.phase == "Pending" and not claim.spec.volume_name
        claims.append(claim)
custom.patch_namespaced_custom_object("loki.grafana.com", "v1", ns, "lokistacks", "logging-loki", {"spec": {"managementState": "Unmanaged"}})
try:
    for obj in sets:
        apps.delete_namespaced_stateful_set(obj.metadata.name, ns, body=client.V1DeleteOptions(
            propagation_policy="Foreground", preconditions=client.V1Preconditions(uid=obj.metadata.uid)))
    for _ in range(60):
        if not any(p.metadata.name.startswith(tuple(names)) for p in core.list_namespaced_pod(ns).items):
            break
        time.sleep(2)
    else:
        raise RuntimeError("Pending Loki Pods did not terminate; claims retained")
    for obj in claims:
        fresh = core.read_namespaced_persistent_volume_claim(obj.metadata.name, ns)
        assert fresh.status.phase == "Pending" and not fresh.spec.volume_name
        core.delete_namespaced_persistent_volume_claim(obj.metadata.name, ns, body=client.V1DeleteOptions(
            preconditions=client.V1Preconditions(uid=obj.metadata.uid, resource_version=fresh.metadata.resource_version)))
    print("Removed only empty Pending Loki claims with identity preconditions")
finally:
    custom.patch_namespaced_custom_object("loki.grafana.com", "v1", ns, "lokistacks", "logging-loki", {"spec": {"managementState": "Managed"}})
