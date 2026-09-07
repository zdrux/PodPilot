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


def https_origin(value):
    p = urlsplit(value)
    if p.scheme != "https" or not p.hostname or p.username or p.password or p.query or p.fragment or p.path not in ("", "/"):
        raise ValueError("An HTTPS origin without credentials, path, query or fragment is required.")
    return value.rstrip("/")


class IncidentReadError(ValueError):
    """A sanitized collector failure that is safe to retain as operator evidence."""


class IncidentReader:
    def __init__(self, origin, token, ca=None, verify=True, transport=None,
            log_tail_lines=1000, max_log_bytes=98304, log_range_seconds=7200,
            loki_log_limit=2000, loki_range_seconds=21600,
            event_projection_bytes=32768, namespaces=()):
        self.origin = https_origin(origin)
        if not token:
            raise ValueError("Investigation credential is missing.")
        self.token = token
        self.log_targets = {}
        self.monitor = None
        self.loki = None
        self.log_tail_lines = max(100, min(int(log_tail_lines), 5000))
        self.max_log_bytes = max(16384, min(int(max_log_bytes), 262144))
        self.log_range_seconds = max(1800, min(int(log_range_seconds), 86400))
        self.loki_log_limit = max(100, min(int(loki_log_limit), 5000))
        self.loki_range_seconds = max(1800, min(int(loki_range_seconds), 86400))
        self.event_projection_bytes = max(8192, min(int(event_projection_bytes), 131072))
        initial_namespaces = tuple(dict.fromkeys(str(namespace).strip() for namespace in namespaces))
        if len(initial_namespaces) > 20 or any(not self._valid_namespace(namespace)
                for namespace in initial_namespaces):
            raise ValueError("Incident namespaces must be valid Kubernetes namespace names (maximum 20).")
        self.namespaces = initial_namespaces
        self.log_window_start = None
        self.log_window_end = None
        self.client = httpx.Client(verify=tls_context(ca) if verify else False,
            timeout=8, follow_redirects=False, transport=transport,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})

    def close(self):
        self.client.close()
        if self.monitor:
            self.monitor.close()

    def set_log_window(self, alert_onset):
        """Anchor optional Loki history around the alert rather than wall-clock time."""

        self.log_window_start = alert_onset - timedelta(minutes=30)
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
            if len(expanded) >= 40:
                break
            namespace = str(namespace or "").strip()
            if self._valid_namespace(namespace) and namespace not in expanded:
                expanded.append(namespace)
        self.namespaces = tuple(expanded)

    def get(self, path, params=None):
        # Paths are owned by this module, never arbitrary model/webhook URLs.
        started = time.monotonic()
        try:
            with self.client.stream("GET", self.origin + path, params=params) as response:
                if response.status_code != 200:
                    raise IncidentReadError(f"Kubernetes API returned HTTP {response.status_code}.")
                data = bytearray()
                for chunk in response.iter_bytes():
                    if time.monotonic() - started > 15:
                        raise IncidentReadError("Kubernetes API read exceeded the 15-second time limit.")
                    data.extend(chunk)
                    if len(data) > 524288:
                        raise IncidentReadError("Kubernetes API response exceeded the 512 KiB response limit.")
        except httpx.TimeoutException as exc:
            raise IncidentReadError("Kubernetes API request timed out.") from exc
        except httpx.RequestError as exc:
            raise IncidentReadError("Kubernetes API connection failed.") from exc
        try:
            return json.loads(data)
        except (TypeError, ValueError) as exc:
            raise IncidentReadError("Kubernetes API returned an invalid JSON response.") from exc

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
                "start": int(time.time())-1800, "end": int(time.time()), "step": 60})
            if result.get("status") != "success":
                raise IncidentReadError("Monitoring query returned an unsuccessful response.")
            series = result.get("data", {}).get("result", [])
            limitations = []
            if len(series) > 12:
                limitations.append(
                    f"Platform metrics returned {len(series)} series; retained the first 12."
                )
            return {"series": series[:12], "partial": len(series)>12,
                    "limitations": limitations}
        paths = {"operators": "/apis/config.openshift.io/v1/clusteroperators",
                 "version": "/apis/config.openshift.io/v1/clusterversions",
                 "nodes": "/api/v1/nodes",
                 "machine-pools": "/apis/machineconfiguration.openshift.io/v1/machineconfigpools"}
        params = {"limit": 60}
        kind, _, ns = key.partition(":")
        if kind in ("pods", "events", "rollouts", "storage"):
            prefix = "/apis/apps/v1" if kind == "rollouts" else "/api/v1"
            resource = "deployments" if kind == "rollouts" else "persistentvolumeclaims" if kind == "storage" else kind
            path = f"{prefix}/namespaces/{ns}/{resource}"
            if kind == "events":
                params["fieldSelector"] = "type=Warning"
        else:
            path = paths[key]
        payload = self.get(path, params)
        items = payload.get("items", [])
        if not isinstance(items, list):
            raise IncidentReadError("Kubernetes API response did not contain an object list.")
        rows = []
        for item in items[:60]:
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
                conditions=[]
                for condition in status.get('conditions', [])[:8]:
                    healthy = (condition.get('type'),condition.get('status')) in {
                        ('Available','True'),('Ready','True'),('Upgradeable','True'),
                        ('Degraded','False'),('Progressing','False'),('Disabled','False')}
                    fields = ('type','status') if healthy else ('type','status','reason','message','lastTransitionTime')
                    conditions.append({k:(str(v)[:200] if k in ('message','reason') else v)
                        for k,v in condition.items() if k in fields})
                row['conditions']=conditions
                if kind == "pods":
                    containers=[]
                    projected_statuses = [
                        *(status.get('containerStatuses', [])[:8]),
                        *(status.get('initContainerStatuses', [])[:4]),
                    ]
                    for container in projected_statuses[:12]:
                        state={}
                        for state_name, details in container.get('state', {}).items():
                            state[state_name]={k:(str(v)[:200] if k=='message' else v) for k,v in details.items()
                                if k in ('reason','message','exitCode','startedAt','finishedAt')}
                        last_state = {}
                        for state_name, details in container.get('lastState', {}).items():
                            last_state[state_name] = {k:(str(v)[:200] if k == 'message' else v)
                                for k,v in details.items()
                                if k in ('reason','message','exitCode','startedAt','finishedAt')}
                        containers.append({'name':container.get('name'),'ready':container.get('ready'),
                            'restartCount':container.get('restartCount'),'state':state,
                            'lastState':last_state})
                    row.update(phase=status.get("phase"), containers=containers,
                        images=[c.get("image") for c in spec.get("containers", [])],
                        owner_references=[{field: owner.get(field) for field in (
                            "apiVersion", "kind", "name", "uid", "controller"
                        ) if owner.get(field) is not None} for owner in meta.get("ownerReferences", [])[:4]],
                        persistent_volume_claims=[
                            volume.get("persistentVolumeClaim", {}).get("claimName")
                            for volume in spec.get("volumes", [])[:20]
                            if volume.get("persistentVolumeClaim", {}).get("claimName")
                        ])
                    # Only exact names read from admitted alert namespaces become log capabilities.
                    statuses = {str(c.get("name")): c for c in projected_statuses}
                    current_targets = sum(mode == "current" for *_, mode in self.log_targets.values())
                    candidate_containers = [
                        *(spec.get("containers", [])[:4]),
                        *(spec.get("initContainers", [])[:4]),
                    ]
                    for c in candidate_containers[:8]:
                        pod_name, container_name = meta.get("name", ""), c.get("name", "")
                        if (current_targets < 30 and
                                all(re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", x)
                                    for x in (pod_name, container_name))):
                            suffix = hashlib.sha256(f"{ns}/{pod_name}/{container_name}".encode()).hexdigest()[:20]
                            self.log_targets["logs:" + suffix] = (ns, pod_name, container_name, "current")
                            container_status = statuses.get(container_name, {})
                            if int(container_status.get("restartCount") or 0) > 0 or container_status.get("lastState"):
                                self.log_targets["logs-previous:" + suffix] = (ns, pod_name, container_name, "previous")
                            if self.loki is not None:
                                self.log_targets["loki-logs:" + suffix] = (ns, pod_name, container_name, "loki")
                            current_targets += 1
                elif kind == "rollouts":
                    row.update(generation=meta.get("generation"), observed_generation=status.get("observedGeneration"),
                        replicas=spec.get("replicas"), available=status.get("availableReplicas"),
                        images=[c.get("image") for c in spec.get("template", {}).get("spec", {}).get("containers", [])])
                elif kind == "storage":
                    row.update(phase=status.get("phase"), storage_class=spec.get("storageClassName"),
                        volume=spec.get("volumeName"), capacity=status.get("capacity", {}).get("storage"))
                elif kind == "version":
                    row.update(history=status.get("history", [])[:10], desired=status.get("desired"))
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
                        for item_ref in status.get("relatedObjects", [])[:40]:
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
            rows.append(row)
        upstream_partial = bool(payload.get("metadata", {}).get("continue")) or len(items) > 60
        limitations = []
        if upstream_partial:
            limitations.append(
                f"Kubernetes pagination limit reached for {key}: inspected the first "
                f"{min(len(items), 60)} objects; additional objects were available."
            )
        if kind == "events":
            observed_rows = len(rows)
            rows, projection_partial = self._project_event_rows(rows)
            upstream_partial = upstream_partial or projection_partial
            if projection_partial:
                limitations.append(
                    f"Recent warning-event projection found {observed_rows} rows and retained {len(rows)} "
                    f"within the {self.event_projection_bytes // 1024} KiB evidence limit."
                )
        return {"rows": rows, "partial": upstream_partial,
                "scope": key, "limitations": limitations}

    def _collect_cluster_health(self):
        """Scan cluster health to completion while retaining only compact exceptions."""

        now = datetime.now(timezone.utc)
        rows, limitations, coverage = [], [], []
        partial = False
        unhealthy_observations = 0
        retained_limit = 120
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
                params = {"limit": 60}
                if kind == "Event":
                    params["fieldSelector"] = "type=Warning"
                if continue_token:
                    params["continue"] = continue_token
                try:
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
                            } for container in statuses[:12]],
                                owner_references=[{field: owner.get(field) for field in (
                                    "apiVersion", "kind", "name", "uid", "controller"
                                ) if owner.get(field) is not None} for owner in meta.get("ownerReferences", [])[:4]],
                                persistent_volume_claims=[
                                    volume.get("persistentVolumeClaim", {}).get("claimName")
                                    for volume in spec.get("volumes", [])[:20]
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
                            ) >= now - timedelta(hours=2)
                        except (TypeError, ValueError):
                            recent = False
                        unhealthy = recent
                        if unhealthy:
                            row.update(reason=item.get("reason"),
                                message=str(item.get("message") or "")[:1000],
                                last_seen=stamp, involved_object=item.get("involvedObject"))
                    if unhealthy and self._valid_namespace(str(namespace or "")):
                        kind_unhealthy += 1
                        unhealthy_observations += 1
                        self._extend_namespaces([namespace])
                        if len(rows) < retained_limit:
                            rows.append(row)
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
        if unhealthy_observations > retained_limit:
            partial = True
            limitations.append(
                f"Cluster health survey found {unhealthy_observations} unhealthy observations across the "
                f"completed scans and retained the first {retained_limit}."
            )
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
                    if time.monotonic() - started > 15:
                        raise IncidentReadError("Pod log read exceeded the 15-second time limit.")
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

    def _project_event_rows(self, rows):
        def priority(row):
            text = f"{row.get('reason', '')} {row.get('message', '')}".casefold()
            severity = sum(marker in text for marker in (
                "fail", "error", "backoff", "unhealthy", "kill", "evict", "timeout",
            ))
            return severity, str(row.get("last_seen") or row.get("created_at") or "")

        ranked = sorted(rows, key=priority, reverse=True)
        retained = []
        for row in ranked:
            candidate = {"rows": [*retained, row]}
            if len(json.dumps(candidate, ensure_ascii=False).encode("utf-8")) <= self.event_projection_bytes:
                retained.append(row)
                continue
            remaining = self.event_projection_bytes - len(json.dumps(
                {"rows": retained}, ensure_ascii=False,
            ).encode("utf-8")) - 256
            if remaining > 200 and row.get("message"):
                compact = dict(row)
                compact["message"] = str(row["message"]).encode("utf-8")[:remaining].decode(
                    "utf-8", errors="ignore",
                ) + "…"
                if len(json.dumps({"rows": [*retained, compact]}, ensure_ascii=False).encode("utf-8")) <= self.event_projection_bytes:
                    retained.append(compact)
            break
        retained.sort(key=lambda row: str(row.get("last_seen") or row.get("created_at") or ""))
        return retained, len(retained) < len(rows)

    def argocd(self, projects, target_servers, target_names, since, namespace=None):
        """Read bounded Application state and correlate only exact destinations.

        New connectors use Argo CD's read-only API directly. ``namespace`` keeps
        saved Kubernetes-hosted connectors readable while operators migrate them.
        """
        if namespace is not None:
            if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", namespace):
                raise ValueError("Invalid Argo CD namespace.")
            path = f"/apis/argoproj.io/v1alpha1/namespaces/{namespace}/applications"
            payload = self.get(path, {"limit": 60})
        else:
            payload = self.get("/api/v1/applications")
        if not isinstance(payload, dict) or not isinstance(payload.get("items", []), list):
            raise ValueError("Argo CD returned an invalid Application list.")
        rows = []
        applications = []
        for app in payload.get("items", [])[:60]:
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
                for item in status_resources[:60] if isinstance(item, dict)]
            current_sources = spec.get("sources")
            if not isinstance(current_sources, list):
                current_sources = [spec.get("source", {})]
            current_sources = [source for source in current_sources[:10] if isinstance(source, dict)]
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
            for history in history_rows[-10:]:
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
        upstream_partial = bool(payload.get("metadata", {}).get("continue"))
        retained_partial = len(rows) > 30 or len(applications) > 30
        partial = upstream_partial or retained_partial
        limitations = []
        if upstream_partial:
            limitations.append(
                "Argo CD API pagination limit was reached; additional applications were available."
            )
        if retained_partial:
            limitations.append(
                f"Argo CD collection found {len(applications)} applications and {len(rows)} recent changes; "
                "retained at most 30 of each."
            )
        return {"applications": applications[:30], "changes": rows[:30],
                "partial": partial, "limitations": limitations}

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
