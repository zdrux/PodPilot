"""Run reversible, evidence-rich incident simulations against the disposable SNO.

The scenarios never alter OpenShift control-plane workloads. A temporary owned Pod
in openshift-monitoring supplies bounded logs; alerts are posted through the real
authenticated PodPilot webhook and resolved after their investigations finish.
"""
import base64
import argparse
import json
import subprocess
import time
from datetime import datetime, timezone
from uuid import uuid4

import httpx
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

from podpilot_openshift.delegated import tls_context

API_NAMESPACE = "ai-ops"
FIXTURE_NAMESPACE = "openshift-monitoring"
FIXTURE_NAME = "podpilot-incident-log-fixture"
SYSTEM_CLUSTER_ID = "00000000-0000-0000-0000-000000000001"
TERMINAL = {"completed", "partial", "failed", "budget_exhausted", "interrupted"}


def oc(*args, stdin=None):
    result = subprocess.run(["oc", *args], input=stdin, text=True,
        capture_output=True, timeout=75)
    if result.returncode:
        raise RuntimeError(f"oc operation failed: {args[0]} (output suppressed)")
    return result.stdout


def verify_target():
    expected = "https://api.sno.192-168-0-200.sslip.io:6443"
    if client.Configuration.get_default_copy().host.rstrip("/") != expected:
        raise RuntimeError("Refusing a cluster other than the documented disposable SNO.")
    if oc("whoami").strip() != "system:serviceaccount:ai-ops:ai-observer":
        raise RuntimeError("Connect with the short-lived ai-observer helper first.")


def create_log_fixture(core):
    try:
        current = core.read_namespaced_pod(FIXTURE_NAME, FIXTURE_NAMESPACE)
        if (current.metadata.labels or {}).get("app.kubernetes.io/part-of") != "podpilot":
            raise RuntimeError("Refusing to replace an unowned fixture Pod.")
        core.delete_namespaced_pod(FIXTURE_NAME, FIXTURE_NAMESPACE,
            grace_period_seconds=0)
        for _ in range(30):
            try:
                core.read_namespaced_pod(FIXTURE_NAME, FIXTURE_NAMESPACE)
                time.sleep(1)
            except ApiException as exc:
                if exc.status == 404:
                    break
                raise
    except ApiException as exc:
        if exc.status != 404:
            raise
    lines = []
    for index in range(80):
        if index % 4 == 0:
            lines.append(f"2026-09-05T16:{index % 60:02d}:00Z ERROR request {index}: dial tcp 10.0.0.1:6443: connect: connection refused")
        elif index % 4 == 1:
            lines.append(f"2026-09-05T16:{index % 60:02d}:01Z WARN request {index}: context deadline exceeded while awaiting headers")
        elif index % 4 == 2:
            lines.append(f"2026-09-05T16:{index % 60:02d}:02Z ERROR request {index}: x509: certificate has expired or is not yet valid")
        else:
            lines.append(f"2026-09-05T16:{index % 60:02d}:03Z INFO retry {index}: backoff scheduled; no mutation attempted")
    script = "import time\nprint(" + repr("\n".join(lines)) + ", flush=True)\ntime.sleep(1800)"
    pod = client.V1Pod(
        metadata=client.V1ObjectMeta(name=FIXTURE_NAME, namespace=FIXTURE_NAMESPACE,
            labels={"app.kubernetes.io/part-of":"podpilot", "app":"podpilot-incident-fixture"}),
        spec=client.V1PodSpec(restart_policy="Never", containers=[client.V1Container(
            name="platform-probe", image="registry.access.redhat.com/ubi9/python-312@sha256:f3959363d949bb0b7495ffb1c7e3caa36bdbbd665a602fcfee946c46c21f3355",
            command=["python", "-c", script],
            security_context=client.V1SecurityContext(allow_privilege_escalation=False,
                capabilities=client.V1Capabilities(drop=["ALL"])))],
            security_context=client.V1PodSecurityContext(run_as_non_root=True,
                seccomp_profile=client.V1SeccompProfile(type="RuntimeDefault"))))
    core.create_namespaced_pod(FIXTURE_NAMESPACE, pod)
    for _ in range(90):
        current = core.read_namespaced_pod(FIXTURE_NAME, FIXTURE_NAMESPACE)
        if current.status.phase == "Running":
            return
        if current.status.phase in {"Failed", "Succeeded"}:
            raise RuntimeError(f"Fixture Pod entered {current.status.phase}.")
        time.sleep(1)
    raise RuntimeError("Fixture Pod did not become Running.")


def connection(core, custom):
    query = """
from sqlalchemy import select
from sqlalchemy.orm import Session
from podpilot_api.database import build_engine
from podpilot_api.settings import get_settings
from podpilot_api.incident_models import IncidentConnection
with Session(build_engine(get_settings())) as db:
 row=db.scalar(select(IncidentConnection).where(IncidentConnection.kind=='cluster',IncidentConnection.cluster_id=='%s',IncidentConnection.enabled.is_(True)))
 print(row.id if row else '')
""" % SYSTEM_CLUSTER_ID
    source_id = oc("exec", "deployment/podpilot", "-n", API_NAMESPACE, "-c", "api",
        "--", "python", "-c", query).strip()
    if not source_id:
        raise RuntimeError("Enabled SNO incident connection is missing.")
    stored = core.read_namespaced_secret("podpilot-incident-credentials", API_NAMESPACE)
    token = base64.b64decode(stored.data[f"webhook-{source_id}"]).decode()
    ca = base64.b64decode(core.read_namespaced_secret("router-ca",
        "openshift-ingress-operator").data["tls.crt"]).decode()
    host = custom.get_namespaced_custom_object("route.openshift.io", "v1",
        API_NAMESPACE, "routes", "podpilot")["spec"]["host"]
    return f"https://{host}/api/v1/incident-webhooks/{source_id}", token, ca


def scenario(name, alerts):
    started = datetime.now(timezone.utc).isoformat()
    rendered = []
    for index, value in enumerate(alerts):
        labels = {"severity":"critical", "podpilot_simulation":"true",
            "podpilot_scenario":name, **value.get("labels", {})}
        rendered.append({"status":"firing", "labels":labels,
            "annotations":{"summary":value["summary"],
                "description":"Controlled PodPilot investigation simulation. Alert claims are premises, not verified cluster facts."},
            "startsAt":started, "fingerprint":f"{name}-{index}-{uuid4().hex}"})
    return {"groupKey":f"podpilot-simulation/{name}/{uuid4().hex}",
        "status":"firing", "alerts":rendered}


def scenarios():
    return [
        scenario("api-log-chain", [{"labels":{"alertname":"KubeAPIDown",
            "namespace":FIXTURE_NAMESPACE,"pod":FIXTURE_NAME,"job":"apiserver"},
            "summary":"API requests appear to fail with transport and certificate errors; inspect the named platform probe logs."}]),
        scenario("conflicting-control-plane", [
            {"labels":{"alertname":"etcdNoLeader","name":"etcd"},
             "summary":"The simulation claims etcd has no leader; corroborate against operators, metrics and Pods."},
            {"labels":{"alertname":"KubeletDown","node":"sno"},
             "summary":"The simulation claims the SNO kubelet is down; reconcile this with current node readiness."}]),
        scenario("rollout-regression", [{"labels":{"alertname":"ClusterOperatorDown",
            "namespace":FIXTURE_NAMESPACE,"name":"monitoring","job":"cluster-version-operator"},
            "summary":"A platform operator alert follows a supposed monitoring rollout; inspect rollout, event and version evidence."}]),
        scenario("api-error-fanout", [{"labels":{"alertname":"KubeAPIErrorBudgetBurn",
            "instance":f"synthetic-apiserver-{index}"},
            "summary":"Many API error-budget series are firing concurrently; determine whether cluster evidence corroborates broad impact. " + "bounded-pressure " * 20}
            for index in range(20)]),
    ]


def run_status(ids):
    code = """
import json,sys
from sqlalchemy import select
from sqlalchemy.orm import Session
from podpilot_api.database import build_engine
from podpilot_api.settings import get_settings
from podpilot_api.incident_models import FleetIncident,IncidentRun
ids=json.load(sys.stdin)
with Session(build_engine(get_settings())) as db:
 out=[]
 for iid in ids:
  incident=db.get(FleetIncident,iid); run=db.scalar(select(IncidentRun).where(IncidentRun.incident_id==iid).order_by(IncidentRun.created_at.desc()))
  evidence=json.loads(run.evidence_json) if run else []
  briefing=json.loads(run.briefing_json) if run else {}
  out.append({'id':iid,'title':incident.title,'alert_state':incident.alert_state,
   'status':run.status if run else 'missing','evidence_sources':[e.get('source') for e in evidence],
   'summary':briefing.get('summary',''),'limitations':briefing.get('limitations',[])})
 print(json.dumps(out))
"""
    return json.loads(oc("exec", "-i", "deployment/podpilot", "-n", API_NAMESPACE,
        "-c", "api", "--", "python", "-c", code, stdin=json.dumps(ids)))


def close_orphaned_simulations():
    code = """
import json
from sqlalchemy import select
from sqlalchemy.orm import Session
from podpilot_api.database import build_engine
from podpilot_api.settings import get_settings
from podpilot_api.incidents import IncidentService,utcnow
from podpilot_api.incident_models import FleetIncident
with Session(build_engine(get_settings())) as db:
 count=0; service=IncidentService(get_settings(),None,None,None)
 for incident in db.scalars(select(FleetIncident).where(FleetIncident.title.like('[SIMULATION]%'),FleetIncident.alert_state=='firing')):
  alerts=json.loads(incident.alerts_json)
  for alert in alerts.values():
   alert['status']='resolved'; alert['endsAt']=utcnow().isoformat()
  incident.alerts_json=json.dumps(alerts); incident.alert_state='resolved'; incident.updated_at=utcnow(); count+=1
 service.audit(db,'system:sno-stress-cleanup','simulation_cleanup',incident_count=count)
 db.commit(); print(count)
"""
    return int(oc("exec", "deployment/podpilot", "-n", API_NAMESPACE,
        "-c", "api", "--", "python", "-c", code).strip())


def resolve(http, endpoint, token, payloads):
    for payload in payloads:
        resolved = json.loads(json.dumps(payload))
        resolved["status"] = "resolved"
        for alert in resolved["alerts"]:
            alert["status"] = "resolved"
            alert["endsAt"] = datetime.now(timezone.utc).isoformat()
        response = http.post(endpoint, headers={"Authorization":f"Bearer {token}"}, json=resolved)
        if response.status_code != 202:
            raise RuntimeError("Scenario resolution webhook failed.")


def main(resolve_only=False):
    config.load_kube_config()
    verify_target()
    core, custom = client.CoreV1Api(), client.CustomObjectsApi()
    endpoint, token, ca = connection(core, custom)
    if resolve_only:
        count = close_orphaned_simulations()
        print(json.dumps({"closed_orphaned_simulations":count}))
        return
    create_log_fixture(core)
    payloads, incident_ids = scenarios(), []
    http = httpx.Client(verify=tls_context(ca), timeout=30, follow_redirects=False)
    try:
        for payload in payloads:
            response = http.post(endpoint, headers={"Authorization":f"Bearer {token}"}, json=payload)
            if response.status_code != 202 or response.json().get("accepted", 0) < 1:
                raise RuntimeError(f"Scenario webhook was rejected (HTTP {response.status_code}).")
            incident_ids.append(response.json()["incident_id"])
        print(json.dumps({"queued_incidents":incident_ids}), flush=True)
        deadline = time.monotonic() + 3600
        previous = None
        while time.monotonic() < deadline:
            rows = run_status(incident_ids)
            state = [row["status"] for row in rows]
            if state != previous:
                print(json.dumps({"run_statuses":state}), flush=True)
                previous = state
            if all(value in TERMINAL for value in state):
                break
            time.sleep(15)
        else:
            raise RuntimeError("Stress investigations did not finish within 60 minutes.")
        rows = run_status(incident_ids)
        print(json.dumps({"results":rows}, indent=2), flush=True)
    finally:
        try:
            resolve(http, endpoint, token, payloads[:len(incident_ids)])
        finally:
            http.close()
        try:
            pod = core.read_namespaced_pod(FIXTURE_NAME, FIXTURE_NAMESPACE)
            if (pod.metadata.labels or {}).get("app.kubernetes.io/part-of") == "podpilot":
                core.delete_namespaced_pod(FIXTURE_NAME, FIXTURE_NAMESPACE,
                    grace_period_seconds=0)
                print("Owned log fixture cleanup requested.", flush=True)
        except ApiException as exc:
            if exc.status != 404:
                raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--resolve-open", action="store_true")
    args = parser.parse_args()
    try:
        main(resolve_only=args.resolve_open)
    except Exception as exc:
        print(f"Stress run failed ({type(exc).__name__}); credentials and response bodies suppressed.")
        if isinstance(exc, RuntimeError):
            print(str(exc))
        raise SystemExit(1)
