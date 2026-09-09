"""Bounded GET-only transports for unattended incident investigation."""
import json
import re
import time
import hashlib
from datetime import datetime, timezone, timedelta
from urllib.parse import urlsplit, quote

import httpx

from podpilot_openshift.delegated import tls_context
from podpilot_diagnostics.redaction import redact_text
from podpilot_diagnostics.incident_policy import IncidentPolicy


def https_origin(value):
    p = urlsplit(value)
    if p.scheme != "https" or not p.hostname or p.username or p.password or p.query or p.fragment or p.path not in ("", "/"):
        raise ValueError("An HTTPS origin without credentials, path, query or fragment is required.")
    return value.rstrip("/")


class IncidentReadError(ValueError):
    """A sanitized collector failure that is safe to retain as operator evidence."""


class IncidentReader:
    def __init__(self, origin, token, ca=None, verify=True, transport=None,
            log_tail_lines=None, max_log_bytes=None, log_range_seconds=None,
            loki_log_limit=None, loki_range_seconds=None,
            namespaces=(), policy=None):
        self.policy = policy or IncidentPolicy()
        self.deadline = time.monotonic() + self.policy.run_timeout_seconds
        self.namespace_limit_reached = False
        self.origin = https_origin(origin)
        if not token:
            raise ValueError("Investigation credential is missing.")
        self.token = token
        self.log_targets = {}
        self.monitor = None
        self.loki = None
        overrides = {key: value for key, value in {
            "log_tail_lines": log_tail_lines, "log_max_bytes": max_log_bytes,
            "log_range_seconds": log_range_seconds, "loki_log_limit": loki_log_limit,
            "loki_range_seconds": loki_range_seconds,
        }.items() if value is not None}
        self.policy = IncidentPolicy.model_validate({**self.policy.model_dump(), **overrides})
        initial_namespaces = tuple(dict.fromkeys(str(namespace).strip() for namespace in namespaces))
        if any(not self._valid_namespace(namespace)
                for namespace in initial_namespaces):
            raise ValueError("Incident namespaces must be valid Kubernetes namespace names ")
        self.namespaces = initial_namespaces
        self.log_window_start = None
        self.log_window_end = None
        self.client = httpx.Client(verify=tls_context(ca) if verify else False,
            timeout=8, follow_redirects=False, transport=transport,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
        self.configure(self.policy)

    def close(self):
        self.client.close()
        if self.monitor:
            self.monitor.close()

    def set_log_window(self, alert_onset):
        """Anchor optional Loki history around the alert rather than wall-clock time."""

        self.log_window_start = alert_onset - timedelta(seconds=self.policy.history_lead_seconds)
        self.log_window_end = min(
            datetime.now(timezone.utc),
            self.log_window_start + timedelta(seconds=self.loki_range_seconds),
        )

    @staticmethod
    def _valid_namespace(namespace):
        return bool(re.fullmatch(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?", namespace))

    def _extend_namespaces(self, namespaces):
        """Expose exact namespaced capabilities discovered by server-owned collectors."""

        expanded = list(self.namespaces)
        for namespace in namespaces:
            namespace = str(namespace or "").strip()
            if not self._valid_namespace(namespace) or namespace in expanded:
                continue
            if self.policy.max_namespaces and len(expanded) >= self.policy.max_namespaces:
                self.namespace_limit_reached = True
                break
            expanded.append(namespace)
        self.namespaces = tuple(expanded)

    def get(self, path, params=None):
        # Paths are owned by this module, never arbitrary model/webhook URLs.
        started = time.monotonic()
        if started >= self.deadline:
            raise IncidentReadError("Incident collection deadline reached.")
        try:
            with self.client.stream("GET", self.origin + path, params=params) as response:
                if response.status_code != 200:
                    raise IncidentReadError(f"Kubernetes API returned HTTP {response.status_code}.")
                data = bytearray()
                for chunk in response.iter_bytes():
                    if time.monotonic() - started > self.policy.read_timeout_seconds or time.monotonic() >= self.deadline:
                        raise IncidentReadError(f"Kubernetes API read exceeded the {self.policy.read_timeout_seconds}-second read or investigation deadline.")
                    data.extend(chunk)
                    if len(data) > self.policy.max_response_bytes:
                        raise IncidentReadError(f"Kubernetes API response exceeded the {self.policy.max_response_bytes // 1024} KiB response limit.")
        except httpx.TimeoutException as exc:
            raise IncidentReadError("Kubernetes API request timed out.") from exc
        except httpx.RequestError as exc:
            raise IncidentReadError("Kubernetes API connection failed.") from exc
        try:
            return json.loads(data)
        except (TypeError, ValueError) as exc:
            raise IncidentReadError("Kubernetes API returned an invalid JSON response.") from exc

    def configure(self, policy, deadline=None):
        self.policy = policy
        self.deadline = deadline if deadline is not None else time.monotonic() + policy.run_timeout_seconds
        self.log_tail_lines = policy.log_tail_lines
        self.max_log_bytes = policy.log_max_bytes
        self.log_range_seconds = policy.log_range_seconds
        self.loki_log_limit = policy.loki_log_limit
        self.loki_range_seconds = policy.loki_range_seconds
        self.client.timeout = httpx.Timeout(policy.read_timeout_seconds)

    def _items(self, path, params, limitations):
        """Follow Kubernetes continuations without accepting paths from responses."""
        params = dict(params or {})
        seen = set()
        while True:
            try:
                if time.monotonic() >= self.deadline:
                    raise IncidentReadError("Incident collection deadline reached.")
                payload = self.get(path, params)
                items = payload.get("items", [])
                if not isinstance(items, list):
                    raise IncidentReadError("API response did not contain an object list.")
                yield from items
                token = str(payload.get("metadata", {}).get("continue") or "")
                if not token:
                    return
                if token in seen:
                    raise IncidentReadError("API repeated a continuation token.")
                seen.add(token)
                params["continue"] = token
            except IncidentReadError as exc:
                limitations.append(str(exc))
                return

    def discover_argocd(self):
        """Inventory installations and applications without fetching discovered URLs."""
        limitations, coverage = [], []

        def listing(path, **params):
            errors, rows = [], []
            for item in self._items(path, {"limit": self.policy.page_size, **params}, errors):
                if len(rows) >= 500:
                    errors.append("Inventory capped at 500 objects for this resource.")
                    break
                if isinstance(item, dict):
                    rows.append(item)
            unavailable = bool(errors)
            # An absent optional API is not a permission failure or an empty success.
            absent = bool(errors) and all("HTTP 404" in error for error in errors)
            coverage.append({"resource": path, "status": "not_installed" if absent else
                ("partial" if unavailable else "read"), "count": len(rows)})
            limitations.extend(f"{path}: {error}" for error in errors if not absent)
            return rows

        instances = []
        custom_resources = listing("/apis/argoproj.io/v1beta1/argocds")
        if coverage[-1]["status"] == "not_installed":
            custom_resources = listing("/apis/argoproj.io/v1alpha1/argocds")
        for item in custom_resources:
            meta = item.get("metadata", {})
            instances.append({"name": meta.get("name"), "namespace": meta.get("namespace"),
                "uid": meta.get("uid"), "evidence": "ArgoCD custom resource"})
        for item in listing("/apis/apps/v1/deployments", labelSelector="app.kubernetes.io/component=server,app.kubernetes.io/part-of=argocd"):
            meta = item.get("metadata", {})
            owners = meta.get("ownerReferences", [])
            if any(owner.get("uid") == instance["uid"] for owner in owners for instance in instances):
                continue
            instances.append({"name": meta.get("name"), "namespace": meta.get("namespace"),
                "uid": meta.get("uid"), "evidence": "Argo CD server Deployment (candidate)"})
        applications = []
        for item in listing("/apis/argoproj.io/v1alpha1/applications"):
            meta, spec, status = item.get("metadata", {}), item.get("spec", {}), item.get("status", {})
            sources = []
            for source in ([spec["source"]] if isinstance(spec.get("source"), dict) else []) + (spec.get("sources") or []):
                repository = str(source.get("repoURL", ""))
                parsed = urlsplit(repository)
                if parsed.scheme in {"http", "https", "ssh"}:
                    repository = parsed._replace(netloc=parsed.netloc.rsplit("@", 1)[-1], query="", fragment="").geturl()
                sources.append({"repository": repository, "path": source.get("path"),
                    "revision": source.get("targetRevision")})
            applications.append({"application": meta.get("name"), "namespace": meta.get("namespace"),
                "uid": meta.get("uid"), "project": spec.get("project", "default"),
                "destination": spec.get("destination", {}), "sources": sources,
                "health": status.get("health", {}).get("status"), "sync": status.get("sync", {}).get("status")})
        application_sets = []
        for item in listing("/apis/argoproj.io/v1alpha1/applicationsets"):
            meta, spec = item.get("metadata", {}), item.get("spec", {})
            application_sets.append({"name": meta.get("name"), "namespace": meta.get("namespace"),
                "uid": meta.get("uid"),
                "generators": sorted({key for generator in spec.get("generators", [])
                    if isinstance(generator, dict) for key in generator if key != "template"}),
                "project": spec.get("template", {}).get("spec", {}).get("project", "default")})
        namespaces = sorted({row["namespace"] for row in instances + applications + application_sets if row.get("namespace")})
        endpoints = []
        for namespace in namespaces[:50]:
            if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", namespace):
                continue
            services = listing(f"/api/v1/namespaces/{namespace}/services", labelSelector="app.kubernetes.io/component=server,app.kubernetes.io/part-of=argocd")
            service_names = {item.get("metadata", {}).get("name") for item in services}
            for item in services:
                name = item.get("metadata", {}).get("name")
                endpoints.append({"namespace": namespace, "name": name, "kind": "Service",
                    "address": f"{name}.{namespace}.svc", "ports": item.get("spec", {}).get("ports", [])})
            for item in listing(f"/apis/route.openshift.io/v1/namespaces/{namespace}/routes"):
                spec = item.get("spec", {})
                if spec.get("to", {}).get("name") in service_names:
                    endpoints.append({"namespace": namespace, "name": item.get("metadata", {}).get("name"),
                        "kind": "Route", "address": spec.get("host"), "ports": []})
        if len(namespaces) > 50:
            limitations.append("Endpoint discovery capped at 50 namespaces.")
        return {"argocd_instances": instances, "applications": applications, "application_sets": application_sets, "endpoints": endpoints,
            "coverage": coverage, "limitations": limitations, "partial": bool(limitations),
            "checks": [f"{len(instances)} installation records, {len(applications)} Applications, {len(endpoints)} endpoint records."],
            "association_note": "Namespace co-location does not prove controller ownership. Endpoint addresses are observed, not connection-tested."}

    def catalog(self):
        return {
            "operators": "Cluster operator availability and degraded conditions",
            "version": "OpenShift upgrade history and current version",
            "nodes": "Node conditions and capacity (no workload enumeration)",
            "machine-pools": "MachineConfigPool rollout and degraded conditions",
            "cluster-health": "Cluster-wide survey of unhealthy workloads, warning events, and unbound PVCs",
            **{f"pods:{ns}": f"Pod status and images in incident namespace {ns}" for ns in self.namespaces},
            **{f"events:{ns}": f"Recent warning events in incident namespace {ns}" for ns in self.namespaces},
            **{f"rollouts:{ns}": f"Deployment rollout state in incident namespace {ns}" for ns in self.namespaces},
            **{f"storage:{ns}": f"PersistentVolumeClaim state in incident namespace {ns}" for ns in self.namespaces},
            **{key: (
                f"Previous Kubernetes logs for restarted incident container {ns}/{pod}/{container}"
                if mode == "previous" else
                f"Deeper Loki history for observed incident container {ns}/{pod}/{container}"
                if mode == "loki" else
                f"Expanded current logs for observed incident container {ns}/{pod}/{container}"
            ) for key, (ns, pod, container, mode) in self.log_targets.items()},
            **({"platform-metrics": "Recent API/etcd/cluster-operator availability metrics"} if self.monitor else {}),
        }

    def collect(self, key):
        if key not in self.catalog():
            raise ValueError("Collector is outside the admitted incident scope.")
        if key in self.log_targets:
            ns, pod, container, mode = self.log_targets[key]
            if mode == "loki":
                return self._collect_loki_logs(ns, pod, container)
            try:
                return self._collect_kubernetes_logs(
                    ns, pod, container, previous=mode == "previous",
                )
            except ValueError as exc:
                if mode != "previous" or self.loki is None:
                    raise
                try:
                    result = self._collect_loki_logs(ns, pod, container)
                except IncidentReadError as loki_exc:
                    raise IncidentReadError(
                        f"Previous Kubernetes logs failed: {exc} Scoped Loki fallback failed: {loki_exc}"
                    ) from loki_exc
                except Exception as loki_exc:
                    raise IncidentReadError(
                        f"Previous Kubernetes logs failed: {exc} Scoped Loki fallback failed with an "
                        "unexpected collector error."
                    ) from loki_exc
                result["limitations"].insert(
                    0,
                    f"Previous Kubernetes logs failed: {exc} Scoped Loki history was used instead and may span container instances.",
                )
                result["kubernetes_previous_error"] = str(exc)
                return result
        if key == "cluster-health":
            return self._collect_cluster_health()
        if key == "platform-metrics":
            result = self.monitor.get("/api/v1/query_range", {
                "query": 'up{job=~"apiserver|etcd"} or cluster_operator_up{job="cluster-version-operator"}',
                "start": int(time.time())-self.policy.metric_range_seconds, "end": int(time.time()), "step": self.policy.metric_step_seconds})
            if result.get("status") != "success":
                raise IncidentReadError("Monitoring query returned an unsuccessful response.")
            series = result.get("data", {}).get("result", [])
            limitations = []
            if len(series) > self.policy.metric_series:
                limitations.append(
                    f"Platform metrics returned {len(series)} series; retained the first {self.policy.metric_series}."
                )
            return {"series": series[:self.policy.metric_series], "partial": len(series)>self.policy.metric_series,
                    "limitations": limitations}
        paths = {"operators": "/apis/config.openshift.io/v1/clusteroperators",
                 "version": "/apis/config.openshift.io/v1/clusterversions",
                 "nodes": "/api/v1/nodes",
                 "machine-pools": "/apis/machineconfiguration.openshift.io/v1/machineconfigpools"}
        params = {"limit": self.policy.page_size}
        kind, _, ns = key.partition(":")
        if kind in ("pods", "events", "rollouts", "storage"):
            prefix = "/apis/apps/v1" if kind == "rollouts" else "/api/v1"
            resource = "deployments" if kind == "rollouts" else "persistentvolumeclaims" if kind == "storage" else kind
            path = f"{prefix}/namespaces/{ns}/{resource}"
            if kind == "events":
                params["fieldSelector"] = "type=Warning"
        else:
            path = paths[key]
        rows, limitations = [], []
        retained_bytes = 0
        for item in self._items(path, params, limitations):
            meta, spec, status = item.get("metadata", {}), item.get("spec", {}), item.get("status", {})
            row = {"name": meta.get("name"), "namespace": meta.get("namespace"),
                   "uid": meta.get("uid"), "created_at": meta.get("creationTimestamp")}
            if kind == "events":
                stamp = item.get("lastTimestamp") or item.get("eventTime") or meta.get("creationTimestamp")
                if stamp and datetime.fromisoformat(stamp.replace("Z", "+00:00")) < datetime.now(timezone.utc) - timedelta(seconds=self.policy.event_range_seconds):
                    continue
                row.update(reason=item.get("reason"), message=item.get("message", ""),
                           last_seen=stamp, involved_object=item.get("involvedObject"))
            else:
                # Never send arbitrary annotations, environment values, or full specs.
                conditions=[]
                for condition in status.get('conditions', []):
                    healthy = (condition.get('type'),condition.get('status')) in {
                        ('Available','True'),('Ready','True'),('Upgradeable','True'),
                        ('Degraded','False'),('Progressing','False'),('Disabled','False')}
                    fields = ('type','status') if healthy else ('type','status','reason','message','lastTransitionTime')
                    conditions.append({k:(str(v) if k in ('message','reason') else v)
                        for k,v in condition.items() if k in fields})
                row['conditions']=conditions
                if kind == "pods":
                    containers=[]
                    projected_statuses = [
                        *(status.get('containerStatuses', [])),
                        *(status.get('initContainerStatuses', [])),
                    ]
                    for container in projected_statuses:
                        state={}
                        for state_name, details in container.get('state', {}).items():
                            state[state_name]={k:(str(v) if k=='message' else v) for k,v in details.items()
                                if k in ('reason','message','exitCode','startedAt','finishedAt')}
                        last_state = {}
                        for state_name, details in container.get('lastState', {}).items():
                            last_state[state_name] = {k:(str(v) if k == 'message' else v)
                                for k,v in details.items()
                                if k in ('reason','message','exitCode','startedAt','finishedAt')}
                        containers.append({'name':container.get('name'),'ready':container.get('ready'),
                            'restartCount':container.get('restartCount'),'state':state,
                            'lastState':last_state})
                    row.update(phase=status.get("phase"), containers=containers,
                        images=[c.get("image") for c in spec.get("containers", [])],
                        owner_references=[{field: owner.get(field) for field in (
                            "apiVersion", "kind", "name", "uid", "controller"
                        ) if owner.get(field) is not None} for owner in meta.get("ownerReferences", [])],
                        persistent_volume_claims=[
                            volume.get("persistentVolumeClaim", {}).get("claimName")
                            for volume in spec.get("volumes", [])
                            if volume.get("persistentVolumeClaim", {}).get("claimName")
                        ])
                    # Only exact names read from admitted alert namespaces become log capabilities.
                    statuses = {str(c.get("name")): c for c in projected_statuses}
                    candidate_containers = [
                        *(spec.get("containers", [])),
                        *(spec.get("initContainers", [])),
                    ]
                    for c in candidate_containers:
                        pod_name, container_name = meta.get("name", ""), c.get("name", "")
                        if (all(re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", x)
                                    for x in (pod_name, container_name))):
                            suffix = hashlib.sha256(f"{ns}/{pod_name}/{container_name}".encode()).hexdigest()[:20]
                            self.log_targets["logs:" + suffix] = (ns, pod_name, container_name, "current")
                            container_status = statuses.get(container_name, {})
                            if int(container_status.get("restartCount") or 0) > 0 or container_status.get("lastState"):
                                self.log_targets["logs-previous:" + suffix] = (ns, pod_name, container_name, "previous")
                            if self.loki is not None:
                                self.log_targets["loki-logs:" + suffix] = (ns, pod_name, container_name, "loki")
                elif kind == "rollouts":
                    row.update(generation=meta.get("generation"), observed_generation=status.get("observedGeneration"),
                        replicas=spec.get("replicas"), available=status.get("availableReplicas"),
                        images=[c.get("image") for c in spec.get("template", {}).get("spec", {}).get("containers", [])])
                elif kind == "storage":
                    row.update(phase=status.get("phase"), storage_class=spec.get("storageClassName"),
                        volume=spec.get("volumeName"), capacity=status.get("capacity", {}).get("storage"))
                elif kind == "version":
                    row.update(history=status.get("history", []), desired=status.get("desired"))
                elif kind == "nodes":
                    row.update(capacity=status.get("capacity", {}), allocatable=status.get("allocatable", {}),
                        roles=[k.removeprefix('node-role.kubernetes.io/') for k in meta.get('labels', {}) if k.startswith('node-role.kubernetes.io/')])
                elif kind == "operators":
                    row["versions"] = status.get("versions", [])
                    unhealthy = any(
                        (condition.get("type") == "Available" and condition.get("status") == "False")
                        or (condition.get("type") == "Degraded" and condition.get("status") == "True")
                        for condition in status.get("conditions", [])
                    )
                    if unhealthy:
                        related = []
                        for item_ref in status.get("relatedObjects", []):
                            if item_ref.get("resource") == "secrets":
                                continue
                            projected = {field: item_ref.get(field) for field in (
                                "group", "resource", "namespace", "name"
                            ) if item_ref.get(field)}
                            if projected:
                                related.append(projected)
                        row["related_objects"] = related
                        self._extend_namespaces(
                            item.get("namespace") or (item.get("name") if item.get("resource") == "namespaces" else "")
                            for item in related
                        )
                elif kind == "machine-pools":
                    row.update(machine_count=status.get("machineCount"), ready=status.get("readyMachineCount"),
                               updated=status.get("updatedMachineCount"), degraded=status.get("degradedMachineCount"))
            row_bytes = len(json.dumps(row).encode("utf-8"))
            if retained_bytes + row_bytes > self.policy.max_collection_bytes:
                limitations.append(f"Collection {key} reached the {self.policy.max_collection_bytes}-byte projected evidence budget after {len(rows)} objects.")
                break
            rows.append(row)
            retained_bytes += row_bytes
        if self.namespace_limit_reached:
            limitations.append(f"Namespace discovery reached the configured {self.policy.max_namespaces}-namespace ceiling.")
        return {"rows": rows, "partial": bool(limitations), "scope": key, "limitations": limitations}

    def _collect_cluster_health(self):
        """Scan cluster health to completion while retaining only compact exceptions."""

        now = datetime.now(timezone.utc)
        rows, limitations, coverage = [], [], []
        partial = False
        unhealthy_observations = 0
        retained_bytes = 0
        retention_limited = False
        requests = (
            ("Pod", "/api/v1/pods"),
            ("Deployment", "/apis/apps/v1/deployments"),
            ("StatefulSet", "/apis/apps/v1/statefulsets"),
            ("DaemonSet", "/apis/apps/v1/daemonsets"),
            ("PersistentVolumeClaim", "/api/v1/persistentvolumeclaims"),
            ("Event", "/api/v1/events"),
        )
        for kind, path in requests:
            continue_token = ""
            seen_tokens = set()
            scanned = kind_unhealthy = pages = 0
            complete = True
            while True:
                params = {"limit": self.policy.page_size}
                if kind == "Event":
                    params["fieldSelector"] = "type=Warning"
                if continue_token:
                    params["continue"] = continue_token
                try:
                    if time.monotonic() >= self.deadline:
                        raise IncidentReadError("Incident collection deadline reached.")
                    payload = self.get(path, params)
                except IncidentReadError as exc:
                    limitations.append(f"Cluster-wide {kind} health survey failed: {exc}")
                    complete = False
                    break
                except Exception:
                    limitations.append(
                        f"Cluster-wide {kind} health survey failed: unexpected response-processing error."
                    )
                    complete = False
                    break
                items = payload.get("items", [])
                if not isinstance(items, list):
                    limitations.append(
                        f"Cluster-wide {kind} health survey failed: response did not contain an object list."
                    )
                    complete = False
                    break
                pages += 1
                scanned += len(items)
                for item in items:
                    meta = item.get("metadata", {})
                    spec = item.get("spec", {})
                    status = item.get("status", {})
                    namespace = meta.get("namespace")
                    row = {"kind": kind, "namespace": namespace, "name": meta.get("name")}
                    unhealthy = False
                    if kind == "Pod":
                        statuses = [
                            *status.get("initContainerStatuses", []),
                            *status.get("containerStatuses", []),
                        ]
                        unhealthy = status.get("phase") not in ("Running", "Succeeded") or any(
                            not container.get("ready", False)
                            and container.get("state", {}).get("waiting")
                            for container in statuses
                        )
                        if unhealthy:
                            row.update(phase=status.get("phase"), containers=[{
                                "name": container.get("name"), "ready": container.get("ready"),
                                "restartCount": container.get("restartCount"),
                                "waiting_reason": (container.get("state", {}).get("waiting") or {}).get("reason"),
                                "last_reason": (container.get("lastState", {}).get("terminated") or {}).get("reason"),
                            } for container in statuses],
                                owner_references=[{field: owner.get(field) for field in (
                                    "apiVersion", "kind", "name", "uid", "controller"
                                ) if owner.get(field) is not None} for owner in meta.get("ownerReferences", [])],
                                persistent_volume_claims=[
                                    volume.get("persistentVolumeClaim", {}).get("claimName")
                                    for volume in spec.get("volumes", [])
                                    if volume.get("persistentVolumeClaim", {}).get("claimName")
                                ])
                    elif kind in ("Deployment", "StatefulSet"):
                        desired = int(spec.get("replicas") or 0)
                        ready = int((
                            status.get("availableReplicas")
                            if kind == "Deployment" else status.get("readyReplicas")
                        ) or 0)
                        unhealthy = desired > ready
                        if unhealthy:
                            row.update(desired=desired, ready=ready, generation=meta.get("generation"),
                                observed_generation=status.get("observedGeneration"))
                    elif kind == "DaemonSet":
                        desired = int(status.get("desiredNumberScheduled") or 0)
                        ready = int(status.get("numberReady") or 0)
                        unhealthy = desired > ready
                        if unhealthy:
                            row.update(desired=desired, ready=ready,
                                unavailable=status.get("numberUnavailable"))
                    elif kind == "PersistentVolumeClaim":
                        unhealthy = status.get("phase") != "Bound"
                        if unhealthy:
                            row.update(phase=status.get("phase"),
                                storage_class=spec.get("storageClassName"),
                                volume=spec.get("volumeName"))
                    else:
                        stamp = (
                            item.get("lastTimestamp") or item.get("eventTime")
                            or meta.get("creationTimestamp")
                        )
                        try:
                            recent = bool(stamp) and datetime.fromisoformat(
                                stamp.replace("Z", "+00:00")
                            ) >= now - timedelta(seconds=self.policy.event_range_seconds)
                        except (TypeError, ValueError):
                            recent = False
                        unhealthy = recent
                        if unhealthy:
                            row.update(reason=item.get("reason"),
                                message=str(item.get("message") or ""),
                                last_seen=stamp, involved_object=item.get("involvedObject"))
                    if unhealthy and self._valid_namespace(str(namespace or "")):
                        kind_unhealthy += 1
                        unhealthy_observations += 1
                        self._extend_namespaces([namespace])
                        row_bytes = len(json.dumps(row).encode("utf-8"))
                        if retained_bytes + row_bytes <= self.policy.max_collection_bytes:
                            rows.append(row)
                            retained_bytes += row_bytes
                        else:
                            retention_limited = True
                next_token = str(payload.get("metadata", {}).get("continue") or "")
                if not next_token:
                    break
                if next_token == continue_token or next_token in seen_tokens:
                    limitations.append(
                        f"Cluster-wide {kind} health survey stopped because the Kubernetes API "
                        "repeated a continuation token."
                    )
                    complete = False
                    break
                seen_tokens.add(next_token)
                continue_token = next_token
            coverage.append({
                "kind": kind, "pages": pages, "scanned": scanned,
                "unhealthy": kind_unhealthy, "complete": complete,
            })
            partial = partial or not complete
        if retention_limited:
            partial = True
            limitations.append(
                f"Cluster health survey found {unhealthy_observations} unhealthy observations across the "
                f"completed scans and retained {len(rows)} within the configured {self.policy.max_collection_bytes}-byte collection budget."
            )
        if self.namespace_limit_reached:
            partial = True
            limitations.append(f"Namespace discovery reached the configured {self.policy.max_namespaces}-namespace ceiling.")
        return {"rows": rows, "partial": partial, "scope": "cluster-health",
                "coverage": coverage, "discovered_namespaces": list(self.namespaces),
                "limitations": limitations}

    def _collect_kubernetes_logs(self, namespace, pod, container, *, previous):
        started = time.monotonic()
        params = {
            "container": container,
            "tailLines": self.log_tail_lines,
            "limitBytes": self.max_log_bytes,
            "sinceSeconds": self.log_range_seconds,
            "timestamps": "true",
        }
        if previous:
            params["previous"] = "true"
            params.pop("sinceSeconds")
        try:
            with self.client.stream(
                "GET", self.origin + f"/api/v1/namespaces/{namespace}/pods/{pod}/log",
                params=params,
            ) as response:
                if response.status_code != 200:
                    label = "Previous container logs" if previous else "Pod logs"
                    raise IncidentReadError(f"{label} request returned HTTP {response.status_code}.")
                body = bytearray()
                for chunk in response.iter_bytes():
                    if time.monotonic() - started > self.policy.read_timeout_seconds or time.monotonic() >= self.deadline:
                        raise IncidentReadError(f"Pod log read exceeded the {self.policy.read_timeout_seconds}-second read or investigation deadline.")
                    body.extend(chunk)
                    if len(body) > self.max_log_bytes:
                        break
        except httpx.TimeoutException as exc:
            raise IncidentReadError("Pod log request timed out.") from exc
        except httpx.RequestError as exc:
            raise IncidentReadError("Pod log connection failed.") from exc
        mode = "previous terminated container" if previous else "current container"
        retained = body[:self.max_log_bytes]
        text = retained.decode("utf-8", errors="replace")
        limitations = []
        if len(body) > self.max_log_bytes or len(retained) >= self.max_log_bytes:
            limitations.append(
                f"Pod log collection reached the {self.max_log_bytes // 1024} KiB byte limit for the "
                f"{mode}; remaining response bytes were omitted."
            )
        elif len(text.splitlines()) >= self.log_tail_lines:
            limitations.append(
                f"Pod log collection returned the configured {self.log_tail_lines}-line maximum for the "
                f"{mode}; earlier lines may exist."
            )
        return {
            "namespace": namespace,
            "pod": pod,
            "container": container,
            "mechanism": "kubernetes-pod-log",
            "previous": previous,
            "logs": text,
            "limitations": limitations,
        }

    def _collect_loki_logs(self, namespace, pod, container):
        if self.loki is None:
            raise ValueError("Scoped Loki logging is unavailable.")
        end = self.log_window_end or datetime.now(timezone.utc)
        start = self.log_window_start or end - timedelta(seconds=self.loki_range_seconds)
        if end <= start:
            end = start + timedelta(seconds=min(self.loki_range_seconds, 1800))
        try:
            snapshot = self.loki.query_container_logs(
                namespace=namespace, pod=pod, container=container,
                start=start, end=end, limit=self.loki_log_limit,
            )
        except httpx.TimeoutException as exc:
            raise IncidentReadError("Scoped Loki container log request timed out.") from exc
        except httpx.RequestError as exc:
            raise IncidentReadError("Scoped Loki container log connection failed.") from exc
        except Exception as exc:
            raise IncidentReadError("Scoped Loki container log query failed.") from exc
        retained = []
        retained_bytes = 0
        for entry in snapshot.entries:
            line = f"{entry.timestamp_ns} {entry.line}"
            encoded = line.encode("utf-8", errors="replace")
            remaining = self.max_log_bytes - retained_bytes
            if remaining <= 0:
                break
            if len(encoded) > remaining:
                encoded = encoded[:remaining]
                line = encoded.decode("utf-8", errors="ignore")
            retained.append(line)
            retained_bytes += len(encoded) + 1
        retained.reverse()
        partial = not snapshot.is_complete or len(retained) < len(snapshot.entries)
        limitations = []
        if not snapshot.is_complete:
            limitations.append(
                f"Scoped Loki history reached the {self.loki_log_limit}-line query limit; additional lines may exist."
            )
        if len(retained) < len(snapshot.entries):
            limitations.append(
                f"Scoped Loki history returned {len(snapshot.entries)} lines and retained {len(retained)} before "
                f"reaching the {self.max_log_bytes // 1024} KiB evidence limit."
            )
        if not retained:
            limitations.append("Loki returned no lines for the exact container and alert window.")
        return {
            "namespace": namespace,
            "pod": pod,
            "container": container,
            "mechanism": "loki-infrastructure-query",
            "previous": None,
            "range_start": start.isoformat(),
            "range_end": end.isoformat(),
            "logs": "\n".join(retained),
            "partial": partial,
            "limitations": limitations,
        }

    def argocd(self, projects, target_servers, target_names, since, namespace=None):
        """Read bounded Application state and correlate only exact destinations.

        New connectors use Argo CD's read-only API directly. ``namespace`` keeps
        saved Kubernetes-hosted connectors readable while operators migrate them.
        """
        limitations = []
        if namespace is not None:
            if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", namespace):
                raise ValueError("Invalid Argo CD namespace.")
            path = f"/apis/argoproj.io/v1alpha1/namespaces/{namespace}/applications"
            params = {"limit": self.policy.page_size}
        else:
            path, params = "/api/v1/applications", {}
        rows, applications = [], []
        for app in self._items(path, params, limitations):
            application_start, change_start = len(applications), len(rows)
            if not isinstance(app, dict):
                continue
            spec, status = app.get("spec", {}), app.get("status", {})
            if not isinstance(spec, dict) or not isinstance(status, dict):
                continue
            dest = spec.get("destination", {})
            if not isinstance(dest, dict):
                continue
            if spec.get("project", "default") not in projects:
                continue
            destination_server = dest.get("server") if isinstance(dest.get("server"), str) else ""
            destination_name = dest.get("name") if isinstance(dest.get("name"), str) else None
            if ((target_servers or target_names)
                    and destination_server.rstrip("/") not in target_servers
                    and destination_name not in target_names):
                continue
            metadata = app.get("metadata", {}) if isinstance(app.get("metadata", {}), dict) else {}
            status_resources = status.get("resources", [])
            if not isinstance(status_resources, list):
                status_resources = []
            resources = [{"group": item.get("group"), "kind": item.get("kind"),
                "namespace": item.get("namespace"), "name": item.get("name"),
                "status": item.get("status"), "health": (item.get("health", {}).get("status")
                    if isinstance(item.get("health", {}), dict) else None)}
                for item in status_resources if isinstance(item, dict)]
            current_sources = spec.get("sources")
            if not isinstance(current_sources, list):
                current_sources = [spec.get("source", {})]
            current_sources = [source for source in current_sources if isinstance(source, dict)]
            sync = status.get("sync", {}) if isinstance(status.get("sync", {}), dict) else {}
            current_revisions = sync.get("revisions")
            if not isinstance(current_revisions, list):
                current_revisions = [sync.get("revision")]
            applications.append({"application": metadata.get("name"),
                "project": spec.get("project"),
                "destination": {"server": dest.get("server"), "name": dest.get("name"),
                    "namespace": dest.get("namespace")},
                "sources": [{"repository": source.get("repoURL"), "path": source.get("path"),
                    "target_revision": source.get("targetRevision"),
                    "deployed_revision": current_revisions[index] if index < len(current_revisions) else None}
                    for index, source in enumerate(current_sources)],
                "managed_resources": resources,
                "health": (status.get("health", {}).get("status")
                    if isinstance(status.get("health", {}), dict) else None),
                "sync": sync.get("status")})
            history_rows = status.get("history", [])
            if not isinstance(history_rows, list):
                history_rows = []
            for history in history_rows:
                if not isinstance(history, dict):
                    continue
                stamp = history.get("deployedAt")
                if not isinstance(stamp, str):
                    continue
                try:
                    deployed_at = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
                except ValueError:
                    continue
                if deployed_at.tzinfo is None or deployed_at < since:
                    continue
                sources = history.get("sources") or [history.get("source", {})]
                revisions = history.get("revisions") or [history.get("revision")]
                if not isinstance(sources, list) or not isinstance(revisions, list):
                    continue
                for source, revision in zip(sources, revisions):
                    if not isinstance(source, dict):
                        continue
                    rows.append({"application": metadata.get("name"), "project": spec.get("project"),
                        "deployed_at": stamp, "revision": revision, "repository": source.get("repoURL"),
                        "path": source.get("path"),
                        "destination": {"server": dest.get("server"), "name": dest.get("name"),
                            "namespace": dest.get("namespace")},
                        "managed_resources": resources,
                        "health": (status.get("health", {}).get("status")
                            if isinstance(status.get("health", {}), dict) else None),
                        "sync": sync.get("status")})
            if len(json.dumps({"applications": applications, "changes": rows}).encode("utf-8")) > self.policy.max_collection_bytes:
                del applications[application_start:]
                del rows[change_start:]
                limitations.append(f"Argo CD reached the {self.policy.max_collection_bytes}-byte projected collection budget; additional application evidence was not retained.")
                break
        return {"applications": applications, "changes": rows,
                "partial": bool(limitations), "limitations": limitations}

    def github(self, repository, revision, api_prefix):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) or not re.fullmatch(r"[a-fA-F0-9]{40,64}", revision or ""):
            raise ValueError("GitHub metadata requires an allowed owner/repository and exact commit SHA.")
        prefix = "/api/v3" if api_prefix == "/api/v3" else ""
        # Git commit endpoint omits file diffs, unlike REST /commits/{sha}.
        commit = self.get(f"{prefix}/repos/{repository}/git/commits/{revision}")
        prs, limitations, page = [], [], 1
        while True:
            if time.monotonic() >= self.deadline:
                limitations.append("GitHub collection deadline reached.")
                break
            batch = self.get(f"{prefix}/repos/{repository}/commits/{revision}/pulls", {"per_page": min(100, self.policy.page_size), "page": page})
            if not isinstance(batch, list):
                raise IncidentReadError("GitHub returned an invalid pull-request list.")
            known = {p.get("number") for p in prs}
            fresh = [p for p in batch if p.get("number") not in known]
            exhausted = False
            for item in fresh:
                projected = {"number": item.get("number"), "title": item.get("title"),
                    "user": {"login": item.get("user", {}).get("login")}, "merged_at": item.get("merged_at")}
                if len(json.dumps([*prs, projected]).encode("utf-8")) > self.policy.max_collection_bytes:
                    limitations.append(f"GitHub reached the {self.policy.max_collection_bytes}-byte projected collection budget.")
                    exhausted = True
                    break
                prs.append(projected)
            if exhausted:
                break
            if len(batch) < min(100, self.policy.page_size):
                break
            if not fresh or len(json.dumps(prs).encode("utf-8")) >= self.policy.max_collection_bytes:
                limitations.append("GitHub pagination repeated results or reached the configured collection byte budget.")
                break
            page += 1
        return {"repository": repository, "revision": revision,
            "commit_title": commit.get("message", "").split("\n")[0],
            "author": commit.get("author", {}).get("name"),
            "committed_at": commit.get("committer", {}).get("date"),
            "pull_requests": [{"number": p.get("number"), "title": p.get("title"),
                "author": p.get("user", {}).get("login"), "merged_at": p.get("merged_at"),
                "url": f"{self.origin}/{'/'.join(quote(x, safe='') for x in repository.split('/'))}/pull/{int(p['number'])}"}
                for p in prs], "partial": bool(limitations), "limitations": limitations}


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
