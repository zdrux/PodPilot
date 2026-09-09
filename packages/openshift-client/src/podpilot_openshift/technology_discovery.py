"""Bounded inventory through a caller-provided, delegated Kubernetes client.

Endpoints are observations, never permission to send credentials to those URLs.
No Secrets, ConfigMap contents, workload env, or arbitrary annotations are read.
"""
from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit


TECHNOLOGIES = {
    "argocd": ("Argo CD", r"argocd|argoproj"),
    "flux": ("Flux", r"fluxcd|flux-system"),
    "tekton": ("Tekton", r"tekton"),
    "istio": ("Istio / OpenShift Service Mesh", r"istio|maistra|servicemesh"),
    "linkerd": ("Linkerd", r"linkerd"),
    "prometheus": ("Prometheus", r"prometheus"),
    "thanos": ("Thanos", r"thanos"),
    "loki": ("Loki", r"loki"),
    "grafana": ("Grafana", r"grafana/grafana(?::|@|$)|(?:^|\s)grafana(?:[-\s]|$)|grafana\.integreatly\.org"),
    "datadog": ("Datadog", r"datadog"),
    "dynatrace": ("Dynatrace", r"dynatrace|dynakube"),
    "cert-manager": ("cert-manager", r"cert-manager"),
    "opentelemetry": ("OpenTelemetry", r"opentelemetry|otel-collector"),
    "elastic": ("Elasticsearch", r"elasticsearch|elastic\.co"),
    "splunk": ("Splunk", r"splunk"),
    "cilium": ("Cilium", r"cilium"),
    "kafka": ("Kafka / Strimzi", r"strimzi|kafka"),
    "vault": ("Vault", r"hashicorp/vault|vault.hashicorp"),
    "seaweedfs": ("SeaweedFS", r"seaweedfs"),
    "lvms": ("LVM Storage", r"topolvm|lvm-operator"),
}

# Each list is independently authorized by Kubernetes. Optional APIs that do
# not exist are recorded as unavailable, not silently treated as an empty list.
RESOURCES = (
    ("apiextensions.k8s.io/v1", "CustomResourceDefinition"),
    ("apps/v1", "Deployment"), ("apps/v1", "StatefulSet"), ("apps/v1", "DaemonSet"),
    ("v1", "Service"), ("route.openshift.io/v1", "Route"),
    ("networking.k8s.io/v1", "Ingress"),
    ("argoproj.io/v1alpha1", "Application"),
    ("source.toolkit.fluxcd.io/v1", "GitRepository"),
    ("tekton.dev/v1", "PipelineRun"),
    ("build.openshift.io/v1", "BuildConfig"),
)


def repository_url(value: object) -> str | None:
    """Canonical display identity only. Never contact this origin here."""
    if not isinstance(value, str) or len(value) > 2048 or re.search(r"[\s\x00-\x1f]", value):
        return None
    if value.startswith("git@") and ":" in value:
        host, path = value[4:].split(":", 1)
        value = f"https://{host}/{path}"
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"https", "ssh"} or not parsed.hostname:
            return None
        if parsed.password or parsed.query or parsed.fragment:
            return None
        if parsed.username and not (parsed.scheme == "ssh" and parsed.username == "git"):
            return None
        if parsed.port not in {None, 22, 443}:
            return None
        path = parsed.path.rstrip("/").removesuffix(".git")
        if not re.fullmatch(r"/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+", path):
            return None
        if any(part in {".", ".."} for part in path.split("/")):
            return None
        return f"https://{parsed.hostname.lower()}{path}"
    except ValueError:
        return None


def _project(kind: str, raw: dict) -> dict:
    metadata = raw.get("metadata") or {}
    spec = raw.get("spec") or {}
    result = {
        "kind": kind, "namespace": str(metadata.get("namespace") or "")[:253],
        "name": str(metadata.get("name") or "")[:253],
        "uid": str(metadata.get("uid") or "")[:80],
    }
    if kind in {"Deployment", "StatefulSet", "DaemonSet"}:
        pod_spec = (spec.get("template") or {}).get("spec") or {}
        result["images"] = [str(c.get("image") or "")[:512] for c in pod_spec.get("containers", [])[:10]]
    if kind == "Service":
        result["ports"] = [{"name": str(p.get("name") or "")[:64], "port": p.get("port")}
                           for p in spec.get("ports", [])[:10]]
    elif kind == "Route":
        result["host"] = str(spec.get("host") or "")[:253]
        result["https"] = bool(spec.get("tls"))
        result["service"] = str((spec.get("to") or {}).get("name") or "")[:253]
    elif kind == "Ingress":
        result["hosts"] = [str(r.get("host") or "")[:253] for r in spec.get("rules", [])[:10]]
    repos = []
    if kind == "Application":
        sources = [spec.get("source") or {}, *spec.get("sources", [])[:20]]
        repos = [s.get("repoURL") for s in sources]
    elif kind == "GitRepository":
        repos = [spec.get("url")]
    elif kind == "PipelineRun":
        repos = [p.get("value") for p in spec.get("params", [])[:50]
                 if str(p.get("name") or "").lower() in {"git-url", "git_url", "repo-url", "repository-url"}]
    elif kind == "BuildConfig":
        repos = [((spec.get("source") or {}).get("git") or {}).get("uri")]
    result["repositories"] = sorted({url for value in repos if (url := repository_url(value))})
    return result


def discover_technologies(dynamic_client, *, max_objects: int = 200, timeout_seconds: float = 45) -> dict:
    started = time.monotonic()
    observations, checks = [], []
    max_objects = min(max(max_objects, 1), 500)
    for api_version, kind in RESOURCES:
        check = {"kind": kind, "api_version": api_version, "verb": "list"}
        if time.monotonic() - started >= timeout_seconds:
            checks.append({**check, "status": "time_limit"})
            continue
        count, token = 0, None
        timed_out = False
        try:
            resource = dynamic_client.resources.get(api_version=api_version, kind=kind)
            check.update(resource=getattr(resource, "name", kind),
                         scope="all_namespaces" if getattr(resource, "namespaced", False) else "cluster")
            while count < max_objects:
                remaining = timeout_seconds - (time.monotonic() - started)
                if remaining <= 0:
                    timed_out = True
                    break
                kwargs = {"limit": min(50, max_objects - count), "_request_timeout": min(5, remaining)}
                if token:
                    kwargs["_continue"] = token
                response = resource.get(**kwargs)
                raw_response = response.to_dict() if hasattr(response, "to_dict") else response
                items = raw_response.get("items") or []
                for raw in items[:max_objects - count]:
                    observations.append(_project(kind, raw))
                count += len(items)
                next_token = (raw_response.get("metadata") or {}).get("continue")
                if not next_token:
                    token = None
                    break
                if next_token == token:
                    break
                token = next_token
            checks.append({**check, "status": "time_limit" if timed_out else "partial" if token else "read", "count": count})
        except Exception as exc:
            status = getattr(exc, "status", None)
            checks.append({**check, "status": "denied" if status in {401, 403} else "unavailable", "http_status": status,
                           "error_type": type(exc).__name__})
    technologies, endpoints, repositories = {}, [], {}
    for item in observations:
        signature = " ".join([item["name"], item["namespace"], item.get("service", ""), *item.get("images", [])]).lower()
        matches = [key for key, (_, pattern) in TECHNOLOGIES.items() if re.search(pattern, signature)]
        for key in matches:
            technology = technologies.setdefault(key, {"id": key, "name": TECHNOLOGIES[key][0], "evidence": []})
            if len(technology["evidence"]) < 20:
                technology["evidence"].append({k: item[k] for k in ("kind", "namespace", "name", "uid")})
        if matches and item["kind"] == "Service":
            for port in item.get("ports", []):
                number = port.get("port")
                if not isinstance(number, int) or not 1 <= number <= 65535:
                    continue
                scheme = "https" if "https" in port["name"] or number == 443 else "http"
                endpoints.append({"url": f"{scheme}://{item['name']}.{item['namespace']}.svc:{number}",
                                  "technologies": matches, "verified": False, "source": item["uid"],
                                  "limitation": "Service candidate; protocol, API path and access not verified."})
        if matches and item["kind"] == "Route" and re.fullmatch(r"[A-Za-z0-9.-]+", item.get("host", "")):
            endpoints.append({"url": f"{'https' if item['https'] else 'http'}://{item['host']}",
                              "technologies": matches, "verified": False, "source": item["uid"],
                              "limitation": "Observed Route; API path and access not verified."})
        for url in item["repositories"]:
            repository = repositories.setdefault(url, {"url": url, "references": []})
            if len(repository["references"]) < 20:
                repository["references"].append({k: item[k] for k in ("kind", "namespace", "name", "uid")})
    return {
        "schema_version": 1, "observed_at": datetime.now(timezone.utc).isoformat(),
        "status": "partial" if any(c["status"] != "read" for c in checks) else "complete",
        "technologies": list(technologies.values()), "endpoints": endpoints[:200],
        "repositories": list(repositories.values())[:200], "checks": checks,
        "api_extensions": [item["name"] for item in observations if item["kind"] == "CustomResourceDefinition"],
        "limitations": ["Identity-scoped inventory. Name/image matches are candidates; CRDs alone do not prove a running instance.",
                        "Discovered URLs are metadata, not authorized credential destinations."],
    }
