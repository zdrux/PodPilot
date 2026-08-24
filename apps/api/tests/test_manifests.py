from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[3]


def test_alertmanager_binding_uses_the_namespaced_platform_role() -> None:
    documents = list(yaml.safe_load_all((ROOT / "deploy" / "openshift" / "rbac.yaml").read_text()))
    binding = next(
        item for item in documents
        if item["kind"] == "RoleBinding"
        and item["metadata"]["name"] == "podpilot-alertmanager-api-view"
    )
    assert binding["metadata"]["namespace"] == "openshift-monitoring"
    assert binding["roleRef"] == {
        "apiGroup": "rbac.authorization.k8s.io",
        "kind": "Role",
        "name": "monitoring-alertmanager-view",
    }
    assert binding["subjects"] == [{
        "kind": "ServiceAccount",
        "name": "podpilot-investigator",
        "namespace": "ai-ops",
    }]
