"""Bounded GET-only transports for unattended platform investigation."""
import json
import re
import time
import hashlib
from datetime import datetime, timezone, timedelta
from urllib.parse import urlsplit, quote

import httpx

from podpilot_openshift.delegated import tls_context
from podpilot_diagnostics.incidents import PLATFORM_NAMESPACES
from podpilot_diagnostics.redaction import redact_text


def https_origin(value):
    p = urlsplit(value)
    if p.scheme != "https" or not p.hostname or p.username or p.password or p.query or p.fragment or p.path not in ("", "/"):
        raise ValueError("An HTTPS origin without credentials, path, query or fragment is required.")
    return value.rstrip("/")


class IncidentReader:
    def __init__(self, origin, token, ca=None, verify=True, transport=None):
        self.origin = https_origin(origin)
        if not token:
            raise ValueError("Investigation credential is missing.")
        self.token = token
        self.log_targets = {}
        self.monitor = None
        self.client = httpx.Client(verify=tls_context(ca) if verify else False,
            timeout=8, follow_redirects=False, transport=transport,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})

    def close(self):
        self.client.close()
        if self.monitor:
            self.monitor.close()

    def get(self, path, params=None):
        # Paths are owned by this module, never arbitrary model/webhook URLs.
        started = time.monotonic()
        with self.client.stream("GET", self.origin + path, params=params) as response:
            if response.status_code != 200:
                raise ValueError(f"Read unavailable (HTTP {response.status_code}).")
            data = bytearray()
            for chunk in response.iter_bytes():
                if time.monotonic() - started > 15:
                    raise ValueError("Response exceeded the read time budget.")
                data.extend(chunk)
                if len(data) > 524288:
                    raise ValueError("Response exceeded the 512 KiB evidence limit.")
        return json.loads(data)

    def catalog(self):
        return {
            "operators": "Cluster operator availability and degraded conditions",
            "version": "OpenShift upgrade history and current version",
            "nodes": "Node conditions and capacity (no workload enumeration)",
            "machine-pools": "MachineConfigPool rollout and degraded conditions",
            **{f"pods:{ns}": f"Platform Pod status and images in {ns}" for ns in PLATFORM_NAMESPACES},
            **{f"events:{ns}": f"Recent warning events in {ns}" for ns in PLATFORM_NAMESPACES},
            **{f"rollouts:{ns}": f"Platform Deployment rollout state in {ns}" for ns in PLATFORM_NAMESPACES},
            **{key: f"Bounded recent logs for observed platform container {ns}/{pod}/{container}"
               for key, (ns, pod, container) in self.log_targets.items()},
            **({"platform-metrics": "Recent API/etcd/cluster-operator availability metrics"} if self.monitor else {}),
        }

    def collect(self, key):
        if key not in self.catalog():
            raise ValueError("Collector is outside the platform allowlist.")
        if key in self.log_targets:
            ns, pod, container = self.log_targets[key]
            started = time.monotonic()
            with self.client.stream("GET", self.origin + f"/api/v1/namespaces/{ns}/pods/{pod}/log",
                    params={"container": container, "tailLines": 100, "limitBytes": 16384, "sinceSeconds": 1800, "timestamps": "true"}) as response:
                if response.status_code != 200:
                    raise ValueError(f"Pod logs unavailable (HTTP {response.status_code}).")
                body = bytearray()
                for chunk in response.iter_bytes():
                    if time.monotonic() - started > 15:
                        raise ValueError("Log response exceeded the read time budget.")
                    body.extend(chunk)
                    if len(body) > 16384:
                        break
            return {"namespace": ns, "pod": pod, "container": container,
                    "logs": body[:16384].decode('utf-8', errors='replace'),
                    "limitations": ["At most 100 lines / 16 KiB from the last 30 minutes; not complete log history."]}
        if key == "platform-metrics":
            result = self.monitor.get("/api/v1/query_range", {
                "query": 'up{job=~"apiserver|etcd"} or cluster_operator_up{job="cluster-version-operator"}',
                "start": int(time.time())-1800, "end": int(time.time()), "step": 60})
            if result.get("status") != "success":
                raise ValueError("Monitoring query failed.")
            series = result.get("data", {}).get("result", [])
            return {"series": series[:12], "partial": len(series)>12,
                    "limitations": ["Last 30 minutes, 60-second resolution, at most 12 platform availability series."]}
        paths = {"operators": "/apis/config.openshift.io/v1/clusteroperators",
                 "version": "/apis/config.openshift.io/v1/clusterversions",
                 "nodes": "/api/v1/nodes",
                 "machine-pools": "/apis/machineconfiguration.openshift.io/v1/machineconfigpools"}
        params = {"limit": 60}
        kind, _, ns = key.partition(":")
        if kind in ("pods", "events", "rollouts"):
            prefix = "/apis/apps/v1" if kind == "rollouts" else "/api/v1"
            resource = "deployments" if kind == "rollouts" else kind
            path = f"{prefix}/namespaces/{ns}/{resource}"
            if kind == "events":
                params["fieldSelector"] = "type=Warning"
        else:
            path = paths[key]
        payload = self.get(path, params)
        rows = []
        for item in payload.get("items", [])[:60]:
            meta, spec, status = item.get("metadata", {}), item.get("spec", {}), item.get("status", {})
            row = {"name": meta.get("name"), "namespace": meta.get("namespace"),
                   "uid": meta.get("uid"), "created_at": meta.get("creationTimestamp")}
            if kind == "events":
                stamp = item.get("lastTimestamp") or item.get("eventTime") or meta.get("creationTimestamp")
                if stamp and datetime.fromisoformat(stamp.replace("Z", "+00:00")) < datetime.now(timezone.utc) - timedelta(hours=2):
                    continue
                row.update(reason=item.get("reason"), message=item.get("message", "")[:2000],
                           last_seen=stamp, involved_object=item.get("involvedObject"))
            else:
                # Never send arbitrary annotations, environment values, or full specs.
                row["conditions"] = status.get("conditions", [])
                if kind == "pods":
                    row.update(phase=status.get("phase"), containers=status.get("containerStatuses", []),
                        images=[c.get("image") for c in spec.get("containers", [])])
                    # Only exact names read from allowed platform namespaces become log capabilities.
                    for c in spec.get("containers", [])[:4]:
                        pod_name, container_name = meta.get("name", ""), c.get("name", "")
                        if all(re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", x) for x in (pod_name, container_name)):
                            target_id = "logs:" + hashlib.sha256(f"{ns}/{pod_name}/{container_name}".encode()).hexdigest()[:20]
                            if len(self.log_targets) < 30:
                                self.log_targets[target_id] = (ns, pod_name, container_name)
                elif kind == "rollouts":
                    row.update(generation=meta.get("generation"), observed_generation=status.get("observedGeneration"),
                        replicas=spec.get("replicas"), available=status.get("availableReplicas"),
                        images=[c.get("image") for c in spec.get("template", {}).get("spec", {}).get("containers", [])])
                elif kind == "version":
                    row.update(history=status.get("history", [])[:10], desired=status.get("desired"))
                elif kind == "nodes":
                    row.update(capacity=status.get("capacity", {}), allocatable=status.get("allocatable", {}),
                        roles=[k.removeprefix('node-role.kubernetes.io/') for k in meta.get('labels', {}) if k.startswith('node-role.kubernetes.io/')])
                elif kind == "operators":
                    row["versions"] = status.get("versions", [])
                elif kind == "machine-pools":
                    row.update(machine_count=status.get("machineCount"), ready=status.get("readyMachineCount"),
                               updated=status.get("updatedMachineCount"), degraded=status.get("degradedMachineCount"))
            rows.append(row)
        return {"rows": rows, "partial": bool(payload.get("metadata", {}).get("continue")),
                "scope": key, "limitations": ["Bounded current-state snapshot; historical coverage is not guaranteed."]}

    def argocd(self, namespace, projects, target_servers, target_names, since):
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", namespace):
            raise ValueError("Invalid Argo CD namespace.")
        payload = self.get(f"/apis/argoproj.io/v1alpha1/namespaces/{namespace}/applications", {"limit": 60})
        rows = []
        for app in payload.get("items", [])[:60]:
            spec, status = app.get("spec", {}), app.get("status", {})
            dest = spec.get("destination", {})
            if spec.get("project", "default") not in projects:
                continue
            if dest.get("server", "").rstrip("/") not in target_servers and dest.get("name") not in target_names:
                continue
            for history in status.get("history", [])[-10:]:
                stamp = history.get("deployedAt")
                if not stamp or datetime.fromisoformat(stamp.replace("Z", "+00:00")) < since:
                    continue
                sources = history.get("sources") or [history.get("source", {})]
                revisions = history.get("revisions") or [history.get("revision")]
                for source, revision in zip(sources, revisions):
                    rows.append({"application": app["metadata"]["name"], "project": spec.get("project"),
                        "deployed_at": stamp, "revision": revision, "repository": source.get("repoURL"),
                        "health": status.get("health", {}).get("status"), "sync": status.get("sync", {}).get("status")})
        return {"changes": rows[:30], "partial": bool(payload.get("metadata", {}).get("continue")) or len(rows)>30,
                "limitations": ["Retained Argo CD history only. A nearby deployment does not establish causation."]}

    def github(self, repository, revision, api_prefix):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) or not re.fullmatch(r"[a-fA-F0-9]{40,64}", revision or ""):
            raise ValueError("GitHub metadata requires an allowed owner/repository and exact commit SHA.")
        prefix = "/api/v3" if api_prefix == "/api/v3" else ""
        # Git commit endpoint omits file diffs, unlike REST /commits/{sha}.
        commit = self.get(f"{prefix}/repos/{repository}/git/commits/{revision}")
        prs = self.get(f"{prefix}/repos/{repository}/commits/{revision}/pulls", {"per_page": 5})
        return {"repository": repository, "revision": revision,
            "commit_title": commit.get("message", "").split("\n")[0][:500],
            "author": commit.get("author", {}).get("name"),
            "committed_at": commit.get("committer", {}).get("date"),
            "pull_requests": [{"number": p.get("number"), "title": p.get("title"),
                "author": p.get("user", {}).get("login"), "merged_at": p.get("merged_at"),
                "url": f"{self.origin}/{'/'.join(quote(x, safe='') for x in repository.split('/'))}/pull/{int(p['number'])}"}
                for p in prs[:5]], "partial": len(prs) >= 5}


def clean_evidence(value, secrets=()):
    if isinstance(value, dict):
        return {str(k): "[REDACTED]" if re.search(r"(?i)password|token|secret|authorization|api.?key", str(k))
                else clean_evidence(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [clean_evidence(v, secrets) for v in value]
    if not isinstance(value, str):
        return value
    for secret in secrets:
        if secret:
            value = value.replace(secret, "[REDACTED]")
    value = re.sub(r"\b(?:gh[pousr]_[A-Za-z0-9_]{15,}|github_pat_[A-Za-z0-9_]{15,})\b", "[REDACTED]", value)
    return redact_text(value)
