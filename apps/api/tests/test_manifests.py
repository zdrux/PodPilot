from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[3]


def test_investigator_has_monitoring_and_logging_view_bindings() -> None:
    documents = list(yaml.safe_load_all(
        (ROOT / "deploy" / "openshift" / "base" / "rbac.yaml").read_text()
    ))
    bindings = {
        item["roleRef"]["name"]: item
        for item in documents
        if item.get("kind") == "ClusterRoleBinding"
    }
    expected_roles = {
        "cluster-monitoring-view",
        "cluster-logging-application-view",
        "cluster-logging-infrastructure-view",
        "cluster-logging-audit-view",
    }

    assert expected_roles <= set(bindings)
    for role_name in expected_roles:
        assert bindings[role_name]["subjects"] == [{
            "kind": "ServiceAccount",
            "name": "podpilot-investigator",
            "namespace": "ai-ops",
        }]


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


def test_cluster_credentials_use_one_fixed_resource_named_secret() -> None:
    workload = ROOT / "deploy" / "openshift" / "workload"
    documents = list(yaml.safe_load_all((workload / "cluster-credentials-rbac.yaml").read_text()))
    role = next(item for item in documents if item["kind"] == "Role")
    assert role["rules"] == [{
        "apiGroups": [""],
        "resources": ["secrets"],
        "resourceNames": ["podpilot-cluster-credentials"],
        "verbs": ["get", "patch", "update"],
    }]
    deployment = yaml.safe_load((workload / "deployment.yaml").read_text())
    env = deployment["spec"]["template"]["spec"]["initContainers"][0]["env"]
    assert next(
        item for item in env if item["name"] == "PODPILOT_CLUSTER_CREDENTIAL_STORE"
    )["value"] == "kubernetes"


def test_inventory_ceiling_is_exposed_through_runtime_config() -> None:
    workload = ROOT / "deploy" / "openshift" / "workload"
    runtime = yaml.safe_load((workload / "runtime-config.yaml").read_text())
    deployment = yaml.safe_load((workload / "deployment.yaml").read_text())
    env = deployment["spec"]["template"]["spec"]["initContainers"][0]["env"]

    assert runtime["data"]["adhoc_inventory_max_objects"] == "500"
    assert runtime["data"]["adhoc_search_max_scan_objects"] == "2000"
    assert runtime["data"]["adhoc_metrics_max_range_seconds"] == "2592000"
    assert runtime["data"]["adhoc_metrics_max_points_per_series"] == "300"
    assert runtime["data"]["adhoc_metrics_max_response_bytes"] == "1048576"
    assert runtime["data"]["loki_timeout_seconds"] == "30"
    assert runtime["data"]["adhoc_audit_initial_range_seconds"] == "3600"
    assert runtime["data"]["adhoc_audit_max_range_seconds"] == "86400"
    assert runtime["data"]["adhoc_audit_default_limit"] == "20"
    assert runtime["data"]["adhoc_audit_max_response_bytes"] == "1048576"
    configured = next(item for item in env if item["name"] == "PODPILOT_ADHOC_INVENTORY_MAX_OBJECTS")
    assert configured["valueFrom"]["configMapKeyRef"] == {
        "name": "podpilot-runtime",
        "key": "adhoc_inventory_max_objects",
    }
    search = next(item for item in env if item["name"] == "PODPILOT_ADHOC_SEARCH_MAX_SCAN_OBJECTS")
    assert search["valueFrom"]["configMapKeyRef"] == {
        "name": "podpilot-runtime",
        "key": "adhoc_search_max_scan_objects",
    }
    audit_limit = next(
        item for item in env if item["name"] == "PODPILOT_ADHOC_AUDIT_DEFAULT_LIMIT"
    )
    assert audit_limit["valueFrom"]["configMapKeyRef"] == {
        "name": "podpilot-runtime",
        "key": "adhoc_audit_default_limit",
    }
    audit_bytes = next(
        item for item in env if item["name"] == "PODPILOT_ADHOC_AUDIT_MAX_RESPONSE_BYTES"
    )
    assert audit_bytes["valueFrom"]["configMapKeyRef"] == {
        "name": "podpilot-runtime",
        "key": "adhoc_audit_max_response_bytes",
    }
    metric_range = next(
        item for item in env if item["name"] == "PODPILOT_ADHOC_METRICS_MAX_RANGE_SECONDS"
    )
    assert metric_range["valueFrom"]["configMapKeyRef"]["key"] == "adhoc_metrics_max_range_seconds"
    metric_points = next(
        item for item in env if item["name"] == "PODPILOT_ADHOC_METRICS_MAX_POINTS_PER_SERIES"
    )
    assert metric_points["valueFrom"]["configMapKeyRef"]["key"] == "adhoc_metrics_max_points_per_series"
    metric_bytes = next(
        item for item in env if item["name"] == "PODPILOT_ADHOC_METRICS_MAX_RESPONSE_BYTES"
    )
    assert metric_bytes["valueFrom"]["configMapKeyRef"] == {
        "name": "podpilot-runtime",
        "key": "adhoc_metrics_max_response_bytes",
    }
    assert runtime["data"]["adhoc_run_timeout_seconds"] == "300"
    assert runtime["data"]["agent_mode"] == "guarded"
    assert runtime["data"]["agent_runner_url"] == "http://127.0.0.1:8090"
    assert runtime["data"]["agent_command_timeout_seconds"] == "300"
    assert runtime["data"]["agent_heartbeat_seconds"] == "10"
    timeout = next(item for item in env if item["name"] == "PODPILOT_ADHOC_RUN_TIMEOUT_SECONDS")
    assert timeout["valueFrom"]["configMapKeyRef"] == {
        "name": "podpilot-runtime",
        "key": "adhoc_run_timeout_seconds",
    }
    assert runtime["data"]["model_timeout_max_seconds"] == "240"
    model_timeout = next(
        item for item in env if item["name"] == "PODPILOT_MODEL_TIMEOUT_MAX_SECONDS"
    )
    assert model_timeout["valueFrom"]["configMapKeyRef"] == {
        "name": "podpilot-runtime",
        "key": "model_timeout_max_seconds",
    }
    assert runtime["data"]["adhoc_max_rounds"] == "10"
    assert runtime["data"]["adhoc_max_reads_per_turn"] == "25"
    assert runtime["data"]["adhoc_followup_reserve_units"] == "0"
    reserve = next(
        item for item in env if item["name"] == "PODPILOT_ADHOC_FOLLOWUP_RESERVE_UNITS"
    )
    assert reserve["valueFrom"]["configMapKeyRef"] == {
        "name": "podpilot-runtime",
        "key": "adhoc_followup_reserve_units",
    }
    assert runtime["data"]["adhoc_worker_concurrency"] == "3"
    assert runtime["data"]["adhoc_max_concurrent_runs_per_user"] == "2"
    worker_concurrency = next(
        item for item in env if item["name"] == "PODPILOT_ADHOC_WORKER_CONCURRENCY"
    )
    per_user_concurrency = next(
        item for item in env
        if item["name"] == "PODPILOT_ADHOC_MAX_CONCURRENT_RUNS_PER_USER"
    )
    assert worker_concurrency["valueFrom"]["configMapKeyRef"]["key"] == (
        "adhoc_worker_concurrency"
    )
    assert per_user_concurrency["valueFrom"]["configMapKeyRef"]["key"] == (
        "adhoc_max_concurrent_runs_per_user"
    )
    assert runtime["data"]["adhoc_http_probe_timeout_seconds"] == "8"
    assert runtime["data"]["adhoc_http_probe_max_bytes"] == "16384"
    oauth_proxy = next(
        container for container in deployment["spec"]["template"]["spec"]["containers"]
        if container["name"] == "oauth-proxy"
    )
    api = next(
        container for container in deployment["spec"]["template"]["spec"]["containers"]
        if container["name"] == "api"
    )
    assert api["resources"]["requests"] == {"cpu": "250m", "memory": "384Mi"}
    assert api["resources"]["limits"] == {"cpu": "1500m", "memory": "1Gi"}
    assert "--upstream-timeout=300s" in oauth_proxy["args"]
    route = yaml.safe_load((workload / "route.yaml").read_text())
    assert route["metadata"]["annotations"]["haproxy.router.openshift.io/timeout"] == "300s"


def test_sno_agentic_runner_uses_read_only_runtime_service_account() -> None:
    root = ROOT / "deploy" / "openshift"
    overlay = root / "overlays" / "sno-milestone-one"
    kustomization = yaml.safe_load((overlay / "kustomization.yaml").read_text())
    runtime = yaml.safe_load((overlay / "runtime-config-patch.yaml").read_text())
    runner_patch = yaml.safe_load(
        (root / "components" / "agentic-runner" / "deployment-patch.yaml").read_text()
    )
    deployment = yaml.safe_load((root / "workload" / "deployment.yaml").read_text())
    rbac_documents = list(yaml.safe_load_all((root / "base" / "rbac.yaml").read_text()))

    assert runtime["data"]["agent_mode"] == "unrestricted"
    assert runtime["data"]["adhoc_run_timeout_seconds"] == "900"
    assert "../../../overlays/poc-cluster-admin" not in kustomization["resources"]
    assert kustomization["components"] == ["../../components/agentic-runner"]
    assert deployment["spec"]["template"]["spec"]["serviceAccountName"] == (
        "podpilot-investigator"
    )
    runner = runner_patch["spec"]["template"]["spec"]["containers"][0]
    assert runner["name"] == "oc-runner"
    assert runner["image"] == "podpilot-oc-runner:latest"
    assert all(
        document.get("roleRef", {}).get("name") != "cluster-admin"
        for document in rbac_documents
    )


def test_remote_agentic_overlay_adds_versioned_runner_without_cluster_admin() -> None:
    root = ROOT / "deploy" / "openshift"
    overlay = root / "overlays" / "remote-poc-agentic"
    kustomization = yaml.safe_load((overlay / "kustomization.yaml").read_text())
    runtime = yaml.safe_load((overlay / "runtime-config-patch.yaml").read_text())
    image_stream = yaml.safe_load((overlay / "image-stream.yaml").read_text())
    runner_patch = yaml.safe_load(
        (root / "components" / "agentic-runner" / "deployment-patch.yaml").read_text()
    )
    rbac_documents = list(yaml.safe_load_all((root / "base" / "rbac.yaml").read_text()))

    assert kustomization["resources"] == ["../remote-poc", "image-stream.yaml"]
    assert kustomization["images"] == [{
        "name": "podpilot-oc-runner",
        "newName": (
            "image-registry.openshift-image-registry.svc:5000/"
            "ai-ops/podpilot-oc-runner"
        ),
        "newTag": "0.12.0",
    }]
    assert kustomization["components"] == ["../../components/agentic-runner"]
    assert runtime["data"] == {
        "agent_mode": "unrestricted",
        "adhoc_run_timeout_seconds": "900",
        "remote_cluster_tls_verify": "false",
    }
    assert image_stream["metadata"]["name"] == "podpilot-oc-runner"
    runner = runner_patch["spec"]["template"]["spec"]["containers"][0]
    assert runner["name"] == "oc-runner"
    assert {item["name"] for item in runner["env"]} == {
        "PODPILOT_AGENT_COMMAND_TIMEOUT_SECONDS",
        "PODPILOT_AGENT_HEARTBEAT_SECONDS",
    }
    assert all(
        document.get("roleRef", {}).get("name") != "cluster-admin"
        for document in rbac_documents
    )


def test_oc_runner_build_pins_cli_image_and_uses_separate_image_stream() -> None:
    root = ROOT
    dockerfile = (root / "Dockerfile.oc-runner").read_text()
    build = yaml.safe_load(
        (root / "deploy" / "openshift" / "build" / "sno-binary" /
         "oc-runner-build-config.yaml").read_text()
    )
    assert "quay.io/openshift/origin-cli@sha256:" in dockerfile
    assert "COPY --from=cli /usr/bin/oc" in dockerfile
    assert build["spec"]["strategy"]["dockerStrategy"]["dockerfilePath"] == (
        "Dockerfile.oc-runner"
    )
    assert build["spec"]["output"]["to"]["name"] == "podpilot-oc-runner:latest"


def test_agentic_deploy_restarts_latest_tag_workload_after_build() -> None:
    script = (ROOT / "scripts" / "deploy-agentic-sno.ps1").read_text()

    assert "--from-archive=$buildArchive" in script
    assert "oc rollout restart deployment/podpilot -n ai-ops" in script
    assert "oc rollout status deployment/podpilot -n ai-ops --timeout=600s" in script


def test_remote_overlay_uses_versioned_internal_registry_imagestream_tag() -> None:
    overlay = ROOT / "deploy" / "openshift" / "overlays" / "remote-poc"
    kustomization = yaml.safe_load((overlay / "kustomization.yaml").read_text())
    image_stream = yaml.safe_load((overlay / "image-stream.yaml").read_text())

    assert "image-stream.yaml" in kustomization["resources"]
    assert kustomization["images"] == [{
        "name": "podpilot",
        "newName": "image-registry.openshift-image-registry.svc:5000/ai-ops/podpilot",
        "newTag": "0.12.0",
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
