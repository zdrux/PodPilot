"""Read-only model-backed SNO evaluations; run after connect-sno.ps1.

Uses the existing delegated-login harness. Keeps credentials in memory and writes
only redacted answers, tool evidence, and synthetic/operational ground truth.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import time

from podpilot_diagnostics.redaction import redact_text

spec = importlib.util.spec_from_file_location("enterprise_eval", Path(__file__).resolve().parents[3] / "scripts" / "enterprise-eval-sno.py")
harness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harness)

CASES = {
    "fixture-diagnosis": "Investigate every failing or unhealthy workload in podpilot-test, including network-client and web-a through web-d. Identify each distinct cause using current object state, Events and logs as appropriate. Present a complete table of workloads, evidence, cause, and a precise proposed fix. Do not change anything.",
    "pod-inventory": "List every Pod and Deployment in podpilot-test, including healthy ones. Use oc get to present exact names, Pod phase and container waiting reasons, and Deployment desired/ready/available replicas. Do not confuse Pod phase with container readiness or omit rows. Do not change anything.",
    "kafka": "Is Kafka installed in this cluster? Discover its APIs and inspect the actual Kafka clusters and supporting node pools, topics and Pods if available. Report namespaces, names, readiness, broker topology and any observed problems. Explain what you verified and any gaps. Do not change anything.",
    "utilization": "Use oc adm top to show current node CPU/memory usage and per-Pod CPU/memory usage in kafka-observability. Present the observed values, timestamps and limitations; distinguish current usage from requests, limits and historical utilization. Do not change anything.",
    "schema": "Use oc explain to inspect the Deployment API schema for spec.template.spec.containers.resources and spec.template.spec.nodeSelector. Explain how these fields relate to the observed scheduling failures of web-a and web-c in podpilot-test. Verify their actual specifications. Do not change anything.",
    "permissions": "Use oc auth can-i to check whether my current delegated identity can get pods, list deployments and patch deployments in podpilot-test, and list nodes cluster-wide. Present the permission results. These are permission checks only; do not perform any write.",
    "other-kinds": "Inspect Services, EndpointSlices, NetworkPolicies, StatefulSets and DaemonSets in kafka-observability and podpilot-test2. Show the exact objects present and their relevant health or relationships, including service-to-endpoint matching. Report absent kinds explicitly and any coverage limitations. Do not change anything.",
    "network": "Diagnose why network-client in podpilot-test cannot reach network-target in podpilot-test2. Inspect the client logs, Service, endpoints, target readiness and NetworkPolicy. Use http_probe for http://network-target.podpilot-test2.svc.cluster.local:8080/ as an additional check, identifying the probe origin. Give an evidence-based explanation and proposed fix; do not change anything.",
    "api-discovery": "Use oc api-resources to discover the APIs installed for Kafka, Argo CD and service mesh. Report resource names, API groups/versions and namespaced scope. Distinguish an installed API from a deployed or healthy application. Do not change anything.",
}

RESULT_CODE = """cid=json.load(sys.stdin)
c=db.get(AdHocConversation,cid)
m=db.scalar(select(AdHocMessage).where(AdHocMessage.conversation_id==cid,AdHocMessage.role=='assistant').order_by(AdHocMessage.created_at.desc()))
print(json.dumps({'answer':m.content if m else None,'activity':json.loads(m.tool_activity_json) if m else {}}))"""


def run_case(http, name, question, output, reasoning_effort="low"):
    report = {"scenario": name, "question": question, "reasoning_effort": reasoning_effort, "started_at": datetime.now(timezone.utc).isoformat()}
    active_run = None
    try:
        response = http.post("/api/v1/adhoc-conversations", data={"message": question,
            "execution_mode": "read_only", "cluster_ids": json.dumps([harness.CLUSTER_ID]),
            "reasoning_effort": reasoning_effort}, follow_redirects=False)
        if response.status_code != 303:
            raise RuntimeError(f"Conversation creation returned HTTP {response.status_code}")
        cid = response.headers["location"].rsplit("/", 1)[-1]
        report["conversation_id"] = cid
        run = harness.db_read("cid=json.load(sys.stdin)\nr=db.scalar(select(AdHocRun).where(AdHocRun.conversation_id==cid).order_by(AdHocRun.created_at.desc()))\nprint(json.dumps({'id':r.id,'status':r.status}))", cid)
        active_run = run["id"]
        print(json.dumps({"scenario":name,"phase":"started","conversation_id":cid}),flush=True)
        deadline = time.monotonic() + 1000
        while time.monotonic() < deadline:
            response = http.get(f"/api/v1/adhoc-runs/{active_run}")
            response.raise_for_status()
            status = response.json().get("status")
            if status not in {"queued", "running"}:
                report["run_status"] = status
                break
            time.sleep(5)
        else:
            raise RuntimeError("Investigation exceeded 1000 seconds")
        report["result"] = harness.db_read(RESULT_CODE, cid)
        page = http.get(f"/ask/{cid}")
        report["render_status"] = page.status_code
        ledger = report["result"]["activity"].get("evidence_ledger", [])
        report["tools"] = sorted({item.get("tool", "") for item in ledger})
        report["shell_calls"] = sum(item.get("tool") == "execute_shell" for item in ledger)
        report["failed_operations"] = [{"tool": item.get("tool"), "status": item.get("status"),
            "error": item.get("error"), "stderr": item.get("stderr_excerpt")} for item in ledger
            if item.get("status") not in {"completed", "succeeded"}]
    except Exception as exc:
        report["error_type"] = type(exc).__name__
        report["error"] = str(exc)[:500]
    finally:
        if active_run and report.get("run_status") not in {"succeeded", "completed", "failed", "cancelled"}:
            http.post(f"/api/v1/adhoc-runs/{active_run}/cancel")
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        output.mkdir(parents=True, exist_ok=True)
        (output / f"{name}.json").write_text(redact_text(json.dumps(report,indent=2)),encoding="utf-8")
        print(json.dumps({"scenario":name,"phase":"finished","status":report.get("run_status"),
            "tools":report.get("tools"),"errors":report.get("failed_operations"),"error":report.get("error")}),flush=True)
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", nargs="+", choices=list(CASES), default=list(CASES))
    parser.add_argument("--output", type=Path, default=Path("evals/results/oc-tools"))
    parser.add_argument("--reasoning-effort", choices=["low", "medium", "high"], default="low")
    args = parser.parse_args()
    with harness.api_session() as http:
        # Avoid stale keep-alive reuse across the oc port-forward polling interval.
        http.headers["Connection"] = "close"
        print(json.dumps({"health_ready":http.get("/health/ready").status_code,
            "health_live":http.get("/health/live").status_code,
            "model_settings":http.get("/settings/model").status_code}),flush=True)
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(run_case,http,name,CASES[name],args.output,args.reasoning_effort) for name in args.cases]
            for future in as_completed(futures):
                future.result()


if __name__ == "__main__":
    main()
