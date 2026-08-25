from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[3]


def test_alertmanager_access_uses_an_explicit_namespaced_role() -> None:
    documents = list(yaml.safe_load_all(
        (ROOT / "deploy" / "openshift" / "base" / "rbac.yaml").read_text()
    ))
    role = next(
        item for item in documents
        if item["kind"] == "Role"
        and item["metadata"]["name"] == "podpilot-alertmanager-api-view"
    )
    assert role["metadata"]["namespace"] == "openshift-monitoring"
    assert role["rules"] == [{
        "apiGroups": ["monitoring.coreos.com"],
        "resources": ["alertmanagers/api"],
        "resourceNames": ["main"],
        "verbs": ["get", "list"],
    }]
    binding = next(
        item for item in documents
        if item["kind"] == "RoleBinding"
        and item["metadata"]["name"] == "podpilot-alertmanager-api-access"
    )
    assert binding["metadata"]["namespace"] == "openshift-monitoring"
    assert binding["roleRef"] == {
        "apiGroup": "rbac.authorization.k8s.io",
        "kind": "Role",
        "name": "podpilot-alertmanager-api-view",
    }
    assert binding["subjects"] == [{
        "kind": "ServiceAccount",
        "name": "podpilot-investigator",
        "namespace": "ai-ops",
    }]


def test_remote_pvc_requests_the_default_storage_class() -> None:
    pvc = yaml.safe_load(
        (ROOT / "deploy" / "openshift" / "workload" / "persistentvolumeclaim.yaml").read_text()
    )
    assert pvc["metadata"]["name"] == "podpilot-data"
    assert "storageClassName" not in pvc["spec"]
    assert pvc["spec"]["accessModes"] == ["ReadWriteOnce"]
    assert pvc["spec"]["resources"]["requests"]["storage"] == "5Gi"


def test_inventory_ceiling_is_exposed_through_runtime_config() -> None:
    workload = ROOT / "deploy" / "openshift" / "workload"
    runtime = yaml.safe_load((workload / "runtime-config.yaml").read_text())
    deployment = yaml.safe_load((workload / "deployment.yaml").read_text())
    env = deployment["spec"]["template"]["spec"]["initContainers"][0]["env"]

    assert runtime["data"]["adhoc_inventory_max_objects"] == "250"
    configured = next(item for item in env if item["name"] == "PODPILOT_ADHOC_INVENTORY_MAX_OBJECTS")
    assert configured["valueFrom"]["configMapKeyRef"] == {
        "name": "podpilot-runtime",
        "key": "adhoc_inventory_max_objects",
    }


def test_remote_overlay_uses_versioned_internal_registry_imagestream_tag() -> None:
    overlay = ROOT / "deploy" / "openshift" / "overlays" / "remote-poc"
    kustomization = yaml.safe_load((overlay / "kustomization.yaml").read_text())
    image_stream = yaml.safe_load((overlay / "image-stream.yaml").read_text())

    assert "image-stream.yaml" in kustomization["resources"]
    assert kustomization["images"] == [{
        "name": "podpilot",
        "newName": "image-registry.openshift-image-registry.svc:5000/ai-ops/podpilot",
        "newTag": "0.11.0",
    }]
    assert image_stream["kind"] == "ImageStream"
    assert image_stream["metadata"]["namespace"] == "ai-ops"
    assert image_stream["metadata"]["name"] == "podpilot"


def test_remote_gui_access_is_local_and_allows_authenticated_users() -> None:
    documents = list(yaml.safe_load_all(
        (ROOT / "deploy" / "openshift" / "auth" / "group-rbac" / "ui-access-rbac.yaml").read_text()
    ))
    role = next(item for item in documents if item["kind"] == "Role")
    binding = next(item for item in documents if item["kind"] == "RoleBinding")
    assert role["metadata"]["namespace"] == "ai-ops"
    assert role["rules"] == [{
        "apiGroups": [""],
        "resources": ["services"],
        "resourceNames": ["podpilot"],
        "verbs": ["get"],
    }]
    assert binding["subjects"] == [{
        "kind": "Group",
        "apiGroup": "rbac.authorization.k8s.io",
        "name": "system:authenticated",
    }]


def test_poc_gui_access_uses_same_authenticated_user_boundary() -> None:
    auth_dir = ROOT / "deploy" / "openshift" / "auth" / "poc-htpasswd"
    documents = list(yaml.safe_load_all((auth_dir / "ui-access-rbac.yaml").read_text()))
    binding = next(item for item in documents if item["kind"] == "RoleBinding")
    groups = list(yaml.safe_load_all((auth_dir / "groups.yaml").read_text()))

    assert binding["subjects"] == [{
        "kind": "Group",
        "apiGroup": "rbac.authorization.k8s.io",
        "name": "system:authenticated",
    }]
    assert {group["metadata"]["name"] for group in groups} == {
        "podpilot-investigators",
        "podpilot-approvers",
        "podpilot-breakglass",
    }


def test_remote_ldap_group_config_only_maps_elevated_roles() -> None:
    overlay = ROOT / "deploy" / "openshift" / "overlays" / "remote-poc"
    runtime = yaml.safe_load((overlay / "runtime-config-patch.yaml").read_text())
    assert "role_viewer_groups" not in runtime["data"]
    assert {
        key for key in runtime["data"]
        if key.startswith("role_") and key.endswith("_groups")
    } == {
        "role_investigator_groups",
        "role_approver_groups",
        "role_breakglass_groups",
    }
