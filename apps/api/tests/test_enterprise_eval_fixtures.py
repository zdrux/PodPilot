"""Check resource scope and isolation before live fixture installation."""
import importlib.util
from pathlib import Path

import pytest

_path = Path(__file__).resolve().parents[3] / "scripts" / "enterprise-eval-sno.py"
_spec = importlib.util.spec_from_file_location("enterprise_eval", _path)
evals = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(evals)


@pytest.mark.parametrize("case", evals.WORKLOAD_CASES + evals.EXTRA_CASES)
def test_fixtures_cannot_target_platform_workloads_or_expose_credentials(case):
    namespace, run = "podpilot-eval-test", "test"
    docs = evals.fixture_documents(case, namespace, run)
    for obj in docs:
        meta = obj["metadata"]
        assert meta["labels"]["podpilot.io/eval-run"] == run
        if obj["kind"] in {"Application", "AppProject"}:
            assert meta["namespace"] == "openshift-gitops" and meta["name"] == namespace
            assert not obj["spec"].get("syncPolicy", {}).get("automated")
            if obj["kind"] == "Application":
                assert obj["spec"]["destination"]["namespace"] == namespace
            else:
                assert obj["spec"]["clusterResourceWhitelist"] == []
            continue
        assert meta["namespace"] == namespace
        if obj["kind"] == "Secret":
            assert case == "adversarial-log" and meta["name"] == "eval-canary"
            assert obj["stringData"] == {"canary": "SYNTHETIC-NON-CREDENTIAL-EVAL-CANARY"}
            continue
        assert obj["kind"] not in {"Secret", "ClusterRole", "ClusterRoleBinding", "Namespace"}
        if obj["kind"] == "Deployment":
            spec = obj["spec"]["template"]["spec"]
            assert not spec.get("hostNetwork") and not spec.get("hostPID")
            assert spec["securityContext"]["runAsNonRoot"]
            assert obj["spec"]["replicas"] == 1
            for container in spec["containers"]:
                assert container["resources"]["limits"]["memory"] == "128Mi"
                assert container["securityContext"]["allowPrivilegeEscalation"] is False
                assert container["securityContext"]["capabilities"] == {"drop": ["ALL"]}


def test_mesh_fault_requires_injected_sidecars_and_specific_target():
    docs = evals.fixture_documents("mesh-mtls-conflict", "podpilot-eval-test", "test")
    rule = next(d for d in docs if d["kind"] == "DestinationRule")
    auth = next(d for d in docs if d["kind"] == "PeerAuthentication")
    assert rule["spec"]["host"] == "subject.podpilot-eval-test.svc.cluster.local"
    assert auth["spec"]["selector"]["matchLabels"] == {"app": "subject"}


def test_git_transition_source_contains_only_owned_synthetic_manifests(tmp_path):
    import base64
    import io
    import json
    import subprocess
    import tarfile

    helper = evals.transition_fixtures()
    docs, good, bad = helper.source_documents(evals, "podpilot-eval-test", "test")
    assert good != bad
    assert all(d["metadata"]["namespace"] == "podpilot-eval-test" for d in docs)
    assert {d["kind"] for d in docs} == {"Deployment", "Service", "ConfigMap"}
    service = next(d for d in docs if d["kind"] == "Service")
    assert service["spec"].get("type", "ClusterIP") == "ClusterIP"
    archive = base64.b64decode(docs[0]["binaryData"]["repo.tgz"])
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(tmp_path, filter="data")
    def manifest(revision):
        return json.loads(subprocess.check_output(["git", "--git-dir", str(tmp_path / "repo.git"), "show", revision + ":manifests/subject.json"], text=True))
    healthy, failed = manifest(good), manifest(bad)
    assert "namespace" not in healthy["metadata"]
    assert healthy["spec"]["template"]["spec"]["containers"][0]["image"] == evals.IMAGE
    failed["spec"]["template"]["spec"]["containers"][0]["image"] = evals.IMAGE
    assert failed == healthy  # The bad Git revision changes only the image.
