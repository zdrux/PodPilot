"""Owned live fixtures for identity replacement and real GitOps transitions.

The Git server contains only generated public test manifests, has no credentials,
and is a namespace-local ClusterIP. No external repository is modified.
"""
import base64
import copy
import io
import json
import subprocess
import tarfile
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path


def wait_for(check, *, attempts=90, delay=2):
    for _ in range(attempts):
        value = check()
        if value:
            return value
        time.sleep(delay)
    raise RuntimeError("Owned fixture did not reach its required observed state")


def source_documents(base, namespace, run_id):
    manifests = base.fixture_documents("contradictory-alert", namespace, run_id)
    workload = copy.deepcopy(manifests[0])
    # Argo owns destination identity; the source has no namespace interpolation.
    workload["metadata"].pop("namespace")
    with tempfile.TemporaryDirectory(prefix="podpilot-eval-git-") as directory:
        root = Path(directory)
        def git(*args):
            result = subprocess.run(["git", "-c", "user.name=PodPilot synthetic eval", "-c", "user.email=eval@example.invalid", *args], cwd=root, capture_output=True, text=True, check=True)
            return result.stdout.strip()
        git("init", "--initial-branch=main")
        (root / "manifests").mkdir()
        target = root / "manifests/subject.json"
        target.write_text(json.dumps(workload), encoding="utf-8")
        git("add", "manifests"); git("commit", "-m", "Healthy synthetic HTTP worker")
        good = git("rev-parse", "HEAD")
        workload["spec"]["template"]["spec"]["containers"][0]["image"] = "registry.access.redhat.com/ubi9/python-312:podpilot-eval-nonexistent"
        target.write_text(json.dumps(workload), encoding="utf-8")
        git("add", "manifests"); git("commit", "-m", "Synthetic missing image regression")
        bad = git("rev-parse", "HEAD")
        git("clone", "--bare", ".", "repo.git")
        git("--git-dir=repo.git", "update-server-info")
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w:gz") as tar:
            tar.add(root / "repo.git", arcname="repo.git")
    labels = {"app": "source", "podpilot.io/eval-run": run_id}
    server = copy.deepcopy(manifests[0])
    server["metadata"].update(name="source", labels=labels)
    server["spec"]["selector"]["matchLabels"] = {"app": "source"}
    server["spec"]["template"]["metadata"]["labels"] = labels
    pod = server["spec"]["template"]["spec"]
    pod["volumes"] = [{"name": "archive", "configMap": {"name": "source"}}]
    container = pod["containers"][0]
    container["volumeMounts"] = [{"name": "archive", "mountPath": "/source", "readOnly": True}]
    container["command"] = ["python", "-u", "-c", "import os,tarfile,http.server; os.mkdir('/tmp/repo'); tarfile.open('/source/repo.tgz').extractall('/tmp/repo',filter='data'); os.chdir('/tmp/repo'); http.server.test(HandlerClass=http.server.SimpleHTTPRequestHandler,port=8000)"]
    objects = [
        {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "source", "namespace": namespace, "labels": labels}, "binaryData": {"repo.tgz": base64.b64encode(archive.getvalue()).decode()}},
        server,
        {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "source", "namespace": namespace, "labels": labels}, "spec": {"selector": {"app": "source"}, "ports": [{"port": 8000, "targetPort": 8000}]}}
    ]
    return objects, good, bad


def install_git_transition(base, core, custom, namespace, run_id, case, foreign_resources, report):
    documents, good, bad = source_documents(base, namespace, run_id)
    payload = json.dumps({"apiVersion": "v1", "kind": "List", "items": documents})
    base.oc("apply", "--dry-run=server", "-f", "-", stdin=payload)
    base.oc("apply", "-f", "-", stdin=payload)
    wait_for(lambda: any(c.type == "Ready" and c.status == "True" for p in core.list_namespaced_pod(namespace, label_selector="app=source").items for c in p.status.conditions or []))
    project, app = base.fixture_documents("argocd-path", namespace, run_id)
    repo = f"http://source.{namespace}.svc:8000/repo.git"
    project["spec"]["sourceRepos"] = [repo]
    app["spec"]["source"].update(repoURL=repo, path="manifests", targetRevision=good)
    for obj in (project, app):
        plural = "applications" if obj["kind"] == "Application" else "appprojects"
        result = custom.create_namespaced_custom_object("argoproj.io", "v1alpha1", "openshift-gitops", plural, obj)
        foreign_resources.append((plural, namespace, result["metadata"]["uid"]))
    def read():
        return custom.get_namespaced_custom_object("argoproj.io", "v1alpha1", "openshift-gitops", "applications", namespace)
    def patch(value):
        return custom.patch_namespaced_custom_object("argoproj.io", "v1alpha1", "openshift-gitops", "applications", namespace, value)
    patch({"operation": {"sync": {"revision": good}}})
    wait_for(lambda: read().get("status", {}).get("operationState", {}).get("phase") == "Succeeded", attempts=120)
    wait_for(lambda: any(c.type == "Ready" and c.status == "True" for p in core.list_namespaced_pod(namespace, label_selector="app=subject").items for c in p.status.conditions or []))
    report["healthy_baseline"] = read()
    report["healthy_baseline_at"] = datetime.now(timezone.utc).isoformat()
    report["source_revisions"] = {"good": good, "bad": bad, "repository": repo, "transport": "isolated credential-free HTTP synthetic Git source"}
    if case == "argocd-image-regression":
        patch({"spec": {"source": {"targetRevision": bad}}, "operation": {"sync": {"revision": bad}}})
        wait_for(lambda: read().get("status", {}).get("operationState", {}).get("syncResult", {}).get("revision") == bad)
        wait_for(lambda: any(s.state.waiting and s.state.waiting.reason in {"ErrImagePull", "ImagePullBackOff"} for p in core.list_namespaced_pod(namespace, label_selector="app=subject").items for s in p.status.container_statuses or []))
    else:
        # An explicit scoped fixture mutation; auto-sync remains off.
        base.oc("scale", "deployment/subject", "-n", namespace, "--replicas=2")
        patch({"metadata": {"annotations": {"argocd.argoproj.io/refresh": "hard"}}})
        wait_for(lambda: read().get("status", {}).get("sync", {}).get("status") == "OutOfSync")
    report["fault_injected_at"] = datetime.now(timezone.utc).isoformat()
    report["application_ground_truth"] = read()


def install_name_reuse(base, core, namespace, run_id, report):
    deployment = base.fixture_documents("pod-crash-exit", namespace, run_id)[0]
    pod = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "subject", "namespace": namespace, "labels": deployment["metadata"]["labels"]}, "spec": deployment["spec"]["template"]["spec"]}
    pod["spec"]["restartPolicy"] = "Never"
    old = core.create_namespaced_pod(namespace, pod)
    wait_for(lambda: core.read_namespaced_pod("subject", namespace).status.phase == "Failed")
    old = core.read_namespaced_pod("subject", namespace)
    report["previous_pod"] = core.api_client.sanitize_for_serialization(old)
    core.delete_namespaced_pod("subject", namespace, body={"preconditions": {"uid": old.metadata.uid}})
    def gone():
        try: core.read_namespaced_pod("subject", namespace)
        except base.client.ApiException as exc:
            if exc.status == 404: return True
            raise
        return False
    wait_for(gone)
    pod["spec"]["containers"][0]["command"] = ["python", "-u", "-m", "http.server", "8000"]
    new = core.create_namespaced_pod(namespace, pod)
    assert new.metadata.uid != old.metadata.uid
    wait_for(lambda: any(c.type == "Ready" and c.status == "True" for c in core.read_namespaced_pod("subject", namespace).status.conditions or []))
    report["replacement_pod_uid"] = new.metadata.uid
    report["old_uid_events"] = core.api_client.sanitize_for_serialization(core.list_namespaced_event(namespace, field_selector=f"involvedObject.uid={old.metadata.uid}"))


def verify_git_recovery(base, core, custom, namespace, run_id, report):
    """Independent fixture recovery, after the read-only model has finished."""
    apps = base.client.AppsV1Api()
    current = custom.get_namespaced_custom_object("argoproj.io", "v1alpha1", "openshift-gitops", "applications", namespace)
    assert current["metadata"]["labels"]["podpilot.io/eval-run"] == run_id
    assert current["metadata"]["uid"] == report["application_ground_truth"]["metadata"]["uid"]
    good = report["source_revisions"]["good"]
    before_uids = [p.metadata.uid for p in core.list_namespaced_pod(namespace, label_selector="app=subject").items if any(c.type == "Ready" and c.status == "True" for c in p.status.conditions or [])]
    custom.patch_namespaced_custom_object("argoproj.io", "v1alpha1", "openshift-gitops", "applications", namespace,
        {"metadata": {"resourceVersion": current["metadata"]["resourceVersion"]}, "spec": {"source": {"targetRevision": good}}, "operation": {"sync": {"revision": good}}})
    def recovered():
        app = custom.get_namespaced_custom_object("argoproj.io", "v1alpha1", "openshift-gitops", "applications", namespace)
        d = apps.read_namespaced_deployment("subject", namespace)
        pods = [p for p in core.list_namespaced_pod(namespace, label_selector="app=subject").items if not p.metadata.deletion_timestamp]
        if (not app.get("operation") and app.get("status", {}).get("sync", {}).get("status") == "Synced"
            and app.get("status", {}).get("sync", {}).get("revision") == good
            and app.get("status", {}).get("health", {}).get("status") == "Healthy"
            and d.spec.replicas == d.status.available_replicas == d.status.updated_replicas == 1
            and d.spec.template.spec.containers[0].image == base.IMAGE
            and d.metadata.generation == d.status.observed_generation and len(pods) == 1):
            return {"source_revision": good, "available_replicas": 1, "template_image": d.spec.template.spec.containers[0].image,
                    "serving_pod_uids": [p.metadata.uid for p in pods], "reused_healthy_pod": pods[0].metadata.uid in before_uids,
                    "performed_by": "independent fixture harness after read-only investigation", "verified_at": datetime.now(timezone.utc).isoformat()}
        return None
    report["independent_recovery"] = wait_for(recovered, attempts=120)
    pod = next(p for p in core.list_namespaced_pod(namespace, label_selector="app=subject").items if p.metadata.uid in report["independent_recovery"]["serving_pod_uids"])
    import ipaddress
    address = ipaddress.ip_address(pod.status.pod_ip)
    host = f"[{address}]" if address.version == 6 else str(address)
    code = "import urllib.request; print(urllib.request.urlopen(" + repr(f"http://{host}:8000/") + ",timeout=5).status)"
    assert base.oc("exec", "deployment/podpilot", "-n", "ai-ops", "-c", "api", "--", "python", "-c", code).strip() == "200"
    report["independent_recovery"]["functional_probe"] = {"http_status": 200, "origin": "PodPilot application Pod", "target_pod_uid": pod.metadata.uid}
