"""Single-process PoC fleet incident ingestion, configuration and bounded worker."""
import asyncio
import hashlib
import hmac
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timezone, timedelta
from threading import Lock
from uuid import uuid4
from urllib.parse import urlsplit

from fastapi import Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, StreamingResponse
from pydantic import BaseModel, Field, ConfigDict, ValidationError
from sqlalchemy import select, update, func
from sqlalchemy.orm import Session

from podpilot_api.auth import Role
from podpilot_api.models import Cluster, AuditEvent, AdHocConversation
from podpilot_api.incident_models import ConnectorDiscovery, IncidentConnection, FleetIncident, IncidentRun
from podpilot_diagnostics.incidents import DEFAULT_ALERTS, AlertWebhook, admitted
from podpilot_openshift.incidents import IncidentReadError, IncidentReader, https_origin, clean_evidence
from podpilot_openshift.log_metrics import LokiQueryClient
from podpilot_openshift.credentials import KubernetesSecretCredentialStore


def utcnow():
    return datetime.now(timezone.utc)


def _json_object(value):
    try:
        parsed = json.loads(value or "{}")
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _repository_identity(value):
    """Return an exact lower-case Git host and owner/repository pair."""
    if not isinstance(value, str) or not value.strip():
        return None, None
    raw = value.strip()
    if re.fullmatch(r"[^/@\s]+@[^:/\s]+:[^\s]+", raw):
        _, remainder = raw.split("@", 1)
        host, path = remainder.split(":", 1)
    else:
        parsed = urlsplit(raw)
        host, path = parsed.hostname, parsed.path
    repository = path.strip("/") if isinstance(path, str) else ""
    if repository.endswith(".git"):
        repository = repository[:-4]
    if not host or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        return None, None
    return host.casefold(), repository.casefold()


def _github_repository_host(value):
    """Map a GitHub REST API host to the corresponding Git repository host."""
    host = str(value or "").casefold().rstrip(".")
    return "github.com" if host == "api.github.com" else host


def _connector_state_version(db):
    digest = hashlib.sha256()
    for row in db.scalars(select(IncidentConnection).order_by(IncidentConnection.id)):
        digest.update(f"{row.id}|{row.enabled}|{row.updated_at.isoformat()}|{row.config_json}".encode())
    for row in db.scalars(select(ConnectorDiscovery).order_by(ConnectorDiscovery.connector_id)):
        digest.update(f"{row.connector_id}|{row.status}|{row.updated_at.isoformat()}|{row.result_json}|{row.error}".encode())
    return digest.hexdigest()[:24]


def _connector_topology(connections, discoveries, clusters):
    cluster_by_id = {cluster.id: cluster for cluster in clusters}
    cluster_candidates = []
    for cluster in clusters:
        servers = {cluster.api_url.rstrip("/")}
        if cluster.is_system:
            servers.add("https://kubernetes.default.svc")
        aliases = {cluster.name}
        cluster_connection = next((row for row in connections
            if row.kind == "cluster" and row.cluster_id == cluster.id), None)
        if cluster_connection:
            aliases.update(str(item) for item in _json_object(cluster_connection.config_json).get(
                "cluster_aliases", []) if isinstance(item, str))
        cluster_candidates.append((cluster, servers, aliases))

    github_candidates = []
    for row in connections:
        if row.kind != "github" or not row.enabled:
            continue
        cfg = _json_object(row.config_json)
        host = _github_repository_host(urlsplit(cfg.get("url", "")).hostname)
        repositories = {str(item).casefold() for item in cfg.get("repositories", []) if isinstance(item, str)}
        if host:
            github_candidates.append((row, host.casefold(), repositories))

    discovery_by_id = {item.connector_id: item for item in discoveries}
    connector_views = []
    matrix = []
    for row in connections:
        discovery = discovery_by_id.get(row.id)
        result = _json_object(discovery.result_json) if discovery else {}
        status = discovery.status if discovery else "not_run"
        if discovery and discovery.completed_at and row.updated_at:
            completed = discovery.completed_at.replace(tzinfo=discovery.completed_at.tzinfo or timezone.utc)
            updated = row.updated_at.replace(tzinfo=row.updated_at.tzinfo or timezone.utc)
            if updated > completed and status not in {"queued", "running"}:
                status = "stale"
        connector_views.append({"id": row.id, "name": row.name, "kind": row.kind,
            "status": status, "error": discovery.error if discovery else None,
            "updated_at": discovery.updated_at if discovery else None,
            "checks": result.get("checks", [])[:8],
            "application_count": len(result.get("applications", [])),
            "repository_count": len(result.get("repositories", []))})
        if row.kind != "argocd" or not discovery or discovery.status not in {"completed", "partial"}:
            continue
        hosting = cluster_by_id.get(row.cluster_id)
        for application in result.get("applications", [])[:60]:
            if not isinstance(application, dict):
                continue
            destination = application.get("destination") if isinstance(application.get("destination"), dict) else {}
            server = str(destination.get("server") or "").rstrip("/")
            name = destination.get("name")
            if server == "https://kubernetes.default.svc" and hosting and row.cluster_id:
                cluster_matches = [hosting]
            else:
                cluster_matches = [cluster for cluster, servers, aliases in cluster_candidates
                    if (server and server in servers) or (isinstance(name, str) and name in aliases)]
            sources = application.get("sources") if isinstance(application.get("sources"), list) else []
            for source in sources or [{}]:
                source = source if isinstance(source, dict) else {}
                repo_host, repository = _repository_identity(source.get("repository"))
                github_matches = [candidate for candidate, host, allowed in github_candidates
                    if repo_host == host and repository in allowed]
                ambiguous = len(cluster_matches) > 1 or len(github_matches) > 1
                confirmed = len(cluster_matches) == 1 and len(github_matches) == 1
                matrix.append({"application": application.get("application") or "Unnamed Application",
                    "project": application.get("project") or "default", "argocd": row.name,
                    "hosting_cluster": hosting.name if hosting else ("Direct API" if not row.cluster_id else "Unavailable"),
                    "destination": server or name or "Not reported",
                    "cluster": cluster_matches[0].name if len(cluster_matches) == 1 else
                        (f"{len(cluster_matches)} matches" if cluster_matches else "Unmatched"),
                    "repository": repository or source.get("repository") or "Not reported",
                    "github": github_matches[0].name if len(github_matches) == 1 else
                        (f"{len(github_matches)} matches" if github_matches else "Unmatched"),
                    "path": source.get("path") or "/", "status": "Ambiguous" if ambiguous else
                        ("Confirmed" if confirmed else "Incomplete")})
    matrix.sort(key=lambda item: (item["status"] != "Incomplete", item["argocd"], item["application"]))
    return connector_views, matrix


def _bounded_activity_text(value, limit=600):
    """Normalize activity copy and avoid leaving a visibly broken final word."""

    text = re.sub(r"\s+", " ", str(value)).strip()
    if len(text) <= limit:
        return text
    head = text[:limit - 1].rsplit(" ", 1)[0].rstrip(" ,;:-")
    return f"{head or text[:limit - 1].rstrip()}…"


def _activity_result(source, data):
    """Return a short operator-safe description of retained evidence."""

    if not isinstance(data, dict):
        return "Evidence retained for review."
    summary = data.get("summary") or data.get("overview")
    if isinstance(summary, str) and summary.strip():
        return _bounded_activity_text(summary)
    alerts = data.get("alerts")
    if isinstance(alerts, list):
        return f"Received {len(alerts)} alert signal{'s' if len(alerts) != 1 else ''}."
    rows = data.get("rows")
    if isinstance(rows, list):
        return f"Collected {len(rows)} platform record{'s' if len(rows) != 1 else ''}."
    changes = data.get("changes")
    if isinstance(changes, list):
        return f"Collected {len(changes)} recent deployment change{'s' if len(changes) != 1 else ''}."
    if "logs" in data:
        return "Collected a bounded platform log excerpt."
    if data.get("limitation"):
        return _bounded_activity_text(data["limitation"])
    return "Evidence retained for review."


def _evidence_object_refs(item):
    """Project exact object coordinates from one evidence item for UI navigation."""

    data = item.get("data") if isinstance(item, dict) else None
    if not isinstance(data, dict):
        return []
    candidates = []
    rows = data.get("rows")
    if isinstance(rows, list):
        candidates.extend(row for row in rows if isinstance(row, dict))
    alerts = data.get("alerts")
    if isinstance(alerts, list):
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            labels = alert.get("labels")
            if isinstance(labels, dict):
                for field, kind in (
                    ("pod", "Pod"), ("deployment", "Deployment"),
                    ("statefulset", "StatefulSet"), ("daemonset", "DaemonSet"),
                ):
                    if labels.get(field):
                        candidates.append({
                            "kind": kind, "namespace": labels.get("namespace"),
                            "name": labels[field],
                        })

    refs = []
    seen = set()
    for candidate in candidates:
        name = str(candidate.get("name") or candidate.get("pod") or "").strip()
        if not name:
            continue
        namespace = str(candidate.get("namespace") or "").strip()
        kind = str(candidate.get("kind") or candidate.get("resource") or "Resource").strip()
        key = (kind.casefold(), namespace, name)
        if key in seen:
            continue
        seen.add(key)
        refs.append({
            "kind": kind,
            "namespace": namespace,
            "name": name,
            "evidence_id": str(item.get("id") or ""),
        })
        if len(refs) >= 12:
            break
    return refs


def _briefing_problems(briefing):
    """Return structured briefing problems, with a bounded legacy-summary fallback."""

    authored = briefing.get("problems") if isinstance(briefing, dict) else None
    if isinstance(authored, list):
        problems = [str(item).strip() for item in authored if str(item).strip()]
        if problems:
            return problems[:8]
    summary = str(briefing.get("summary") or "").strip() if isinstance(briefing, dict) else ""
    if not summary:
        return []
    paragraphs = [item.strip(" \t\r\n-*•") for item in re.split(r"\n+", summary) if item.strip()]
    if len(paragraphs) > 1:
        return paragraphs[:8]
    return [
        item.strip()
        for item in re.split(r"(?<=[.!?])\s+(?=(?:[*_`]*[A-Z0-9]))", summary)
        if item.strip()
    ][:8]


def _queued_activity():
    now = utcnow().isoformat()
    return json.dumps({
        "version": 1,
        "phase": "Queued",
        "current_work": "Waiting for an incident worker",
        "updated_at": now,
        "tasks": [{
            "id": "coordinator",
            "role": "coordinator",
            "label": "Incident coordinator",
            "state": "queued",
            "work": "Waiting for an incident worker",
            "queued_at": now,
            "started_at": None,
            "ended_at": None,
            "result": "",
        }],
        "events": [],
    })


def _incident_activity_view(incident, run):
    alerts = list(_json_object(incident.alerts_json).values())
    alert_names = list(dict.fromkeys(
        str((alert.get("labels") or {}).get("alertname") or "Unknown alert")
        for alert in alerts if isinstance(alert, dict)
    ))[:6]
    activity = _json_object(run.activity_json) if run else {}
    briefing = _json_object(getattr(run, "briefing_json", "{}")) if run else {}
    tasks = [task for task in activity.get("tasks", []) if isinstance(task, dict)][:24]
    for task in tasks:
        if task.get("state") == "stopped" and task.get("result") == "Stopped when the incident worker restarted.":
            task["result"] = (
                "The PodPilot incident worker restarted before this task finished. "
                "Collected evidence was retained; rerun the investigation to continue."
            )
    evidence = []
    if run:
        try:
            parsed_evidence = json.loads(run.evidence_json or "[]")
            evidence = parsed_evidence if isinstance(parsed_evidence, list) else []
        except (TypeError, ValueError):
            evidence = []
    specialist_summaries = {
        str(item.get("source")): _activity_result(item.get("source"), item.get("data"))
        for item in evidence
        if isinstance(item, dict) and str(item.get("source") or "").endswith(" specialist")
    }
    # Specialist evidence retains the complete bounded report. Prefer it over
    # activity text persisted by older builds that cut summaries at 240 chars.
    tasks = [
        {
            **task,
            "result": specialist_summaries.get(str(task.get("source")), task.get("result", "")),
        }
        for task in tasks
    ]
    known_sources = {str(task.get("source", "")) for task in tasks}
    for item in evidence:
        source = str(item.get("source") or "")
        if not source.endswith(" specialist") or source in known_sources:
            continue
        tasks.append({
            "id": f"legacy-{item.get('id', len(tasks) + 1)}",
            "role": "specialist",
            "label": source,
            "source": source,
            "state": "completed",
            "work": "Review retained specialist evidence",
            "started_at": item.get("observed_at"),
            "ended_at": item.get("observed_at"),
            "result": _activity_result(source, item.get("data")),
        })
    status = run.status if run else "not_started"
    if not any(task.get("role") == "coordinator" for task in tasks) and run:
        coordinator_state = {
            "queued": "queued", "running": "running", "completed": "completed",
            "partial": "completed", "budget_exhausted": "stopped",
            "interrupted": "stopped", "failed": "error",
        }.get(status, "stopped")
        tasks.insert(0, {
            "id": "coordinator", "role": "coordinator", "label": "Incident coordinator",
            "state": coordinator_state,
            "work": activity.get("current_work") or (
                "Waiting for an incident worker" if status == "queued" else
                "Investigation finished" if status in {"completed", "partial"} else
                "Investigation is not active"
            ),
            "started_at": run.created_at.isoformat() if status != "queued" else None,
            "ended_at": run.completed_at.isoformat() if run.completed_at else None,
        })
    specialists = [task for task in tasks if task.get("role") == "specialist"]
    counts = {
        "queued": sum(task.get("state") == "queued" for task in specialists),
        "running": sum(task.get("state") == "running" for task in specialists),
        "completed": sum(task.get("state") == "completed" for task in specialists),
        "error": sum(task.get("state") in {"error", "stopped"} for task in specialists),
    }
    results = []
    for item in evidence[-6:]:
        results.append({
            "id": str(item.get("id") or ""),
            "source": str(item.get("source") or "Evidence")[:160],
            "observed_at": item.get("observed_at"),
            "summary": _activity_result(item.get("source"), item.get("data")),
        })
    events = []
    for event in activity.get("events", [])[-6:]:
        if not isinstance(event, dict):
            continue
        label = str(event.get("label") or "Investigation")[:120]
        recorded_state = str(event.get("state") or "completed")
        summary = event.get("summary") or ""
        if recorded_state == "completed" and label in specialist_summaries:
            summary = specialist_summaries[label]
        events.append({
            "at": event.get("at"),
            "label": label,
            # Journal entries are immutable history. A recorded running transition
            # means the task started; only the current workstream may look active.
            "state": "started" if recorded_state == "running" else recorded_state[:32],
            "summary": _bounded_activity_text(summary),
        })
    return {
        "incident": incident,
        "run": run,
        "status": status,
        "active": status in {"queued", "running"},
        "alert_names": alert_names,
        "main_alert": alert_names[0] if alert_names else incident.title,
        "phase": str(activity.get("phase") or status.replace("_", " ")).capitalize(),
        "current_work": str(activity.get("current_work") or (
            "Waiting for an incident worker" if status == "queued" else
            "Investigation finished; open the case for the full assessment."
        ))[:300],
        "findings": _briefing_problems(briefing),
        "updated_at": activity.get("updated_at") or (
            run.completed_at.isoformat() if run and run.completed_at else incident.updated_at.isoformat()
        ),
        "tasks": tasks,
        "specialists": specialists,
        "counts": counts,
        "results": results,
        "events": events,
        "evidence_count": len(evidence),
    }


def _incident_state_version(db, incident_id=None, cluster_id=None):
    """Return a compact version for browser-visible incident state."""

    incident_query = select(FleetIncident).order_by(FleetIncident.updated_at.desc()).limit(100)
    if incident_id:
        incident_query = select(FleetIncident).where(FleetIncident.id == incident_id)
    elif cluster_id:
        incident_query = incident_query.where(FleetIncident.cluster_id == cluster_id)
    incidents = list(db.scalars(incident_query))
    digest = hashlib.sha256()
    for incident in incidents:
        digest.update("|".join((
            incident.id,
            incident.alert_state,
            incident.updated_at.isoformat(),
            incident.alerts_json,
            incident.limitations_json,
        )).encode("utf-8"))
        run_query = select(IncidentRun).where(
            IncidentRun.incident_id == incident.id
        ).order_by(IncidentRun.created_at.desc())
        if not incident_id:
            run_query = run_query.limit(1)
        for run in db.scalars(run_query):
            digest.update("|".join((
                run.id,
                run.status,
                run.completed_at.isoformat() if run.completed_at else "",
                run.activity_json,
                run.evidence_json,
                run.briefing_json,
            )).encode("utf-8"))
    return digest.hexdigest()[:24]


def _serialized_bytes(value):
    return len(json.dumps(value, ensure_ascii=False, default=str).encode("utf-8"))


def _project_evidence_item(item, max_bytes):
    """Keep a useful bounded projection instead of replacing oversized evidence."""

    if _serialized_bytes(item) <= max_bytes:
        return item, None
    data = item.get("data") if isinstance(item.get("data"), dict) else {}
    if isinstance(data.get("rows"), list):
        original = data["rows"]
        projected = {**data, "rows": [], "partial": True}
        for row in original:
            candidate = {**item, "data": {**projected, "rows": [*projected["rows"], row]}}
            if _serialized_bytes(candidate) > max(0, max_bytes - 512):
                break
            projected["rows"].append(row)
        projected.setdefault("limitations", []).append(
            f"Retained {len(projected['rows'])} of {len(original)} rows within the per-collector evidence budget."
        )
        return {**item, "data": projected}, (
            f"{item.get('source', 'Collector')}: evidence projection retained "
            f"{len(projected['rows'])} of {len(original)} rows."
        )
    if isinstance(data.get("logs"), str):
        projected = dict(data)
        raw = projected["logs"].encode("utf-8", errors="replace")
        overhead = _serialized_bytes({**item, "data": {**projected, "logs": ""}})
        retained = raw[-max(0, max_bytes - overhead - 256):].decode("utf-8", errors="ignore")
        projected["logs"] = "[Earlier lines omitted by the evidence projection budget.]\n" + retained
        projected["partial"] = True
        projected.setdefault("limitations", []).append(
            "Earlier log lines were omitted by the per-collector evidence budget."
        )
        return {**item, "data": projected}, (
            f"{item.get('source', 'Log collector')}: earlier log lines were truncated."
        )
    return {**item, "data": {
        "limitation": "Evidence exceeded the per-collector projection limit and has no safe compact projection."
    }}, f"{item.get('source', 'Collector')}: evidence projection exceeded the limit."


def _limitation_key(value):
    normalized = re.sub(r"\*+|`+|\bE\d+\b", " ", str(value).casefold())
    source = next(iter(re.findall(r"(?:events|logs(?:-previous)?|loki-logs):[a-z0-9_.:-]+", normalized)), "").rstrip(":")
    if "projection" in normalized:
        return f"projection:{source}"
    if "missing or invalid evidence citation" in normalized:
        return "invalid-citations"
    normalized = re.sub(r"[^a-z0-9]+", " ", normalized)
    return " ".join(normalized.split())[:240]


def _dedupe_limitations(values, *, exclude_keys=()):
    excluded = set(exclude_keys)
    seen = set()
    result = []
    for value in values:
        text = str(value).strip()
        key = _limitation_key(text)
        if not text or key in seen or key in excluded:
            continue
        seen.add(key)
        result.append(text)
    return result


def _evidence_limitations(evidence, *, model_authored=None):
    grouped = {}
    for item in evidence:
        data = item.get("data") if isinstance(item, dict) else None
        if not isinstance(data, dict):
            continue
        source = str(item.get("source") or "Evidence")
        is_model_authored = source.casefold().endswith(" specialist")
        if model_authored is not None and is_model_authored is not model_authored:
            continue
        for limitation in data.get("limitations", []):
            if not isinstance(limitation, str) or not limitation.strip():
                continue
            grouped.setdefault(limitation.strip(), []).append(source)
    result = []
    for limitation, sources in grouped.items():
        unique_sources = list(dict.fromkeys(sources))
        source_label = ", ".join(unique_sources[:5])
        if len(unique_sources) > 5:
            source_label += f", and {len(unique_sources) - 5} more collectors"
        result.append(f"{source_label}: {limitation}")
    return result


def _collector_failure_reason(exc):
    """Return only package-normalized failures; never persist arbitrary exception text."""

    if isinstance(exc, IncidentReadError):
        return str(exc)
    if isinstance(exc, TimeoutError):
        return "collector operation timed out."
    return "unexpected collector error."


class ConnectionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str | None = Field(default=None, max_length=36)
    kind: str = Field(pattern="^(cluster|argocd|github)$")
    name: str = Field(min_length=1, max_length=100)
    cluster_id: str | None = Field(default=None, max_length=36)
    access_mode: str = Field(default="direct", pattern="^(direct|kubernetes)$")
    enabled: bool = False
    token: str = Field(default="", max_length=16384)
    webhook_token: str = Field(default="", max_length=512)
    namespace: str = Field(default="openshift-gitops", pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")
    projects: list[str] = Field(default_factory=list, max_length=30)
    cluster_aliases: list[str] = Field(default_factory=list, max_length=30)
    target_cluster_ids: list[str] = Field(default_factory=list, max_length=30)
    destination_names: dict[str, str] = Field(default_factory=dict, max_length=30)
    url: str = Field(default="", max_length=2048)
    monitoring_url: str = Field(default="", max_length=2048)
    api_prefix: str = Field(default="/api/v3", pattern=r"^(/api/v3)?$")
    repositories: list[str] = Field(default_factory=list, max_length=30)
    custom_ca_pem: str | None = Field(default=None, max_length=32768)
    allowed_alerts: list[str] = Field(default_factory=lambda: list(DEFAULT_ALERTS), min_length=1, max_length=100)


class IncidentService:
    def __init__(self, settings, store, model_context, provider, cluster_store=None):
        self.settings, self.store = settings, store
        self.model_context, self.provider = model_context, provider
        self.cluster_store = cluster_store
        self.lock = asyncio.Lock()
        self.reader_factory = IncidentReader

    def credentials(self):
        if self.store is None:
            self.store = KubernetesSecretCredentialStore(self.settings.incident_secret_namespace,
                self.settings.incident_secret_name)
        return self.store

    def require_enabled(self):
        if not self.settings.incidents_enabled:
            raise HTTPException(404, "Incident response is not enabled.")

    @staticmethod
    def access_mode(row, config):
        if row.kind != "argocd":
            return "direct"
        return config.get("access_mode") or ("direct" if config.get("url") else "kubernetes")

    def hosting_cluster_token(self, cluster, db):
        if cluster.credential_key and self.cluster_store:
            token = self.cluster_store.get(cluster.credential_key)
            if token:
                return token
        if cluster.is_system:
            try:
                token = self.settings.service_account_token_path.read_text(encoding="utf-8").strip()
                if token:
                    return token
            except OSError:
                pass
        # Compatibility for incident cluster connectors that predate reuse of the
        # registered cluster credential store.
        host_connection = db.scalar(select(IncidentConnection).where(
            IncidentConnection.kind == "cluster", IncidentConnection.cluster_id == cluster.id,
            IncidentConnection.enabled.is_(True)))
        return self.credentials().get(host_connection.credential_key) if host_connection else None

    def token_for(self, row, db):
        config = json.loads(row.config_json or "{}")
        if self.access_mode(row, config) == "kubernetes":
            cluster = db.get(Cluster, row.cluster_id)
            return self.hosting_cluster_token(cluster, db) if cluster else None
        return self.credentials().get(row.credential_key)

    def audit(self, db, actor, action, outcome="success", **details):
        db.add(AuditEvent(actor=actor, action=f"incident.{action}", outcome=outcome,
                          details_json=json.dumps(details)))

    def view(self, user):
        self.require_enabled()
        if user.role < Role.INVESTIGATOR:
            raise HTTPException(403, "Incidents require the SRE Investigator role or higher.")

    def manage(self, user):
        self.view(user)
        if not user.can_manage_configuration:
            raise HTTPException(403, "Connector configuration requires administrator access.")

    def cluster_reader(self, cluster, token, namespaces=()):
        origin = self.settings.delegated_system_api_url if cluster.is_system else cluster.api_url
        ca = cluster.custom_ca_pem
        if cluster.is_system:
            ca = self.settings.service_account_ca_path.read_text(encoding="utf-8")
        reader = self.reader_factory(
            origin, token, ca, True if cluster.is_system else cluster.tls_verify,
            log_tail_lines=self.settings.incident_log_tail_lines,
            max_log_bytes=self.settings.incident_log_max_bytes,
            log_range_seconds=self.settings.incident_log_range_seconds,
            loki_log_limit=self.settings.incident_loki_log_limit,
            loki_range_seconds=self.settings.incident_loki_range_seconds,
            namespaces=namespaces,
        )
        loki_options = {
            "token": token,
            "tenant": "infrastructure",
            "timeout_seconds": self.settings.loki_timeout_seconds,
            "max_series": self.settings.loki_max_series,
            "max_response_bytes": min(
                self.settings.incident_max_evidence_bytes,
                self.settings.incident_log_max_bytes * 4,
            ),
        }
        if cluster.is_system:
            reader.loki = LokiQueryClient(
                base_url=self.settings.loki_url,
                ca_path=self.settings.service_ca_path,
                **loki_options,
            )
        else:
            reader.loki = LokiQueryClient.for_remote_cluster(
                api_url=origin,
                api_tls_verify=cluster.tls_verify,
                route_name=self.settings.loki_route_name,
                **loki_options,
            )
        return reader

    def ingest(self, engine, source_id, supplied_token, payload):
        with Session(engine) as db:
            source = db.get(IncidentConnection, source_id)
            if not source or source.kind != "cluster" or not source.enabled:
                raise HTTPException(401, "Invalid webhook connection.")
            expected = self.credentials().get(source.webhook_key)
            if not expected or not hmac.compare_digest(expected.encode(), supplied_token.encode()):
                raise HTTPException(401, "Invalid webhook credential.")
            cluster = db.get(Cluster, source.cluster_id)
            if not cluster or not cluster.is_enabled or cluster.visibility != "shared":
                raise HTTPException(409, "Incident cluster is unavailable or private.")
            webhook = AlertWebhook.model_validate(payload)
            cfg = json.loads(source.config_json)
            alerts = [a for a in webhook.alerts if admitted(a, cfg["allowed_alerts"])]
            if not alerts:
                return {"accepted": 0, "incident_id": None}
            key = hashlib.sha256(webhook.groupKey.encode()).hexdigest()
            incident = db.scalar(select(FleetIncident).where(FleetIncident.source_id == source_id,
                FleetIncident.group_key == key).order_by(FleetIncident.created_at.desc()).limit(1))
            previous = json.loads(incident.alerts_json) if incident else {}
            def newer_firing(a):
                old = previous.get(a.fingerprint)
                return a.status == "firing" and (not old or a.startsAt > datetime.fromisoformat(old["startsAt"]))
            create = incident is None or (incident.alert_state == "resolved" and any(newer_firing(a) for a in alerts))
            if create:
                if not any(a.status == "firing" for a in alerts):
                    return {"accepted": 0, "incident_id": None}
                pending = db.scalar(select(func.count()).select_from(IncidentRun).where(IncidentRun.status.in_(["queued", "running"])))
                if pending >= 100:
                    raise HTTPException(503, "Incident queue is full; retry this notification.")
                prefix = ("[TEST] " if all(a.labels.get('podpilot_test') == 'true' for a in alerts)
                    else "[SIMULATION] " if all(a.labels.get('podpilot_simulation') == 'true' for a in alerts) else "")
                incident = FleetIncident(id=str(uuid4()), cluster_id=cluster.id, source_id=source.id,
                    group_key=key, title=(prefix + ", ".join(sorted({a.labels["alertname"] for a in alerts})))[:500],
                    alert_state="firing", alerts_json="{}", limitations_json="[]")
                db.add(incident)
                previous = {}
            for alert in alerts:
                old = previous.get(alert.fingerprint)
                # Older deliveries cannot roll back a resolution or a newer occurrence.
                if old:
                    old_start = datetime.fromisoformat(old["startsAt"])
                    if alert.startsAt < old_start or (alert.startsAt == old_start and old["status"] == "resolved"):
                        continue
                previous[alert.fingerprint] = clean_evidence(alert.model_dump(mode="json"))
            if len(previous) > 200:
                raise HTTPException(422, "Incident alert group exceeds 200 fingerprints; narrow Alertmanager grouping.")
            limitations = json.loads(incident.limitations_json)
            if webhook.truncatedAlerts and "Alertmanager truncated this group; alert coverage is incomplete." not in limitations:
                limitations.append("Alertmanager truncated this group; alert coverage is incomplete.")
            incident.alerts_json = json.dumps(previous)
            incident.limitations_json = json.dumps(limitations)
            incident.alert_state = "firing" if any(a["status"] == "firing" for a in previous.values()) else "resolved"
            if webhook.truncatedAlerts and incident.alert_state == "resolved":
                incident.alert_state = "unknown"
            incident.updated_at = utcnow()
            if create:
                db.add(IncidentRun(id=str(uuid4()), incident_id=incident.id, actor=f"webhook:{source.id}",
                    alert_snapshot_json=incident.alerts_json, status="queued",
                    activity_json=_queued_activity()))
            self.audit(db, f"webhook:{source.id}", "received", incident_id=incident.id, created=create,
                       alert_count=len(alerts), truncated=webhook.truncatedAlerts)
            db.commit()
            return {"accepted": len(alerts), "incident_id": incident.id, "created": create}

    def save(self, engine, value, user):
        self.manage(user)
        with Session(engine) as db:
            row = db.get(IncidentConnection, value.id) if value.id else None
            cluster = None
            if value.id and not row:
                raise HTTPException(404, "Connection not found.")
            if row and row.kind != value.kind:
                raise HTTPException(422, "Connection kind cannot change.")
            if value.kind == "cluster":
                cluster = db.get(Cluster, value.cluster_id)
                if not cluster or not cluster.is_enabled or cluster.visibility != "shared":
                    raise HTTPException(422, "Select an enabled shared cluster.")
            if value.kind == "cluster":
                if value.monitoring_url:
                    value.monitoring_url = https_origin(value.monitoring_url)
                value.cluster_aliases = list(dict.fromkeys(alias.strip() for alias in value.cluster_aliases if alias.strip()))
                if any(len(alias) > 253 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]*", alias)
                        for alias in value.cluster_aliases):
                    raise HTTPException(422, "Argo CD destination aliases must be exact names without spaces.")
                value.allowed_alerts = list(dict.fromkeys(
                    alert.strip() for alert in value.allowed_alerts if alert.strip()
                ))
                if not value.allowed_alerts or any(
                        not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_:]{0,252}", alert)
                        for alert in value.allowed_alerts):
                    raise HTTPException(422, "Specify at least one valid Prometheus alert name.")
                duplicate = db.scalar(select(IncidentConnection).where(IncidentConnection.kind == "cluster",
                    IncidentConnection.cluster_id == value.cluster_id))
                if duplicate and (not row or duplicate.id != row.id):
                    raise HTTPException(409, "Edit the existing incident connection for this cluster.")
            if value.kind == "argocd":
                if value.access_mode == "kubernetes":
                    cluster = db.get(Cluster, value.cluster_id)
                    if not cluster or not cluster.is_enabled or cluster.visibility != "shared":
                        raise HTTPException(422, "Select an enabled shared hosting cluster.")
                    value.url = ""
                    value.custom_ca_pem = None
                else:
                    value.url = https_origin(value.url)
                    value.cluster_id = None
                value.projects = list(dict.fromkeys(project.strip() for project in value.projects if project.strip()))
                if not value.projects or any(len(project) > 253 or not re.fullmatch(
                        r"[a-z0-9][a-z0-9._-]*", project) for project in value.projects):
                    raise HTTPException(422, "Specify at least one allowed Argo CD project.")
            if value.kind == "github":
                value.url = https_origin(value.url)
                if not value.repositories or any(not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", r) or any(x in (".", "..") for x in r.split('/')) for r in value.repositories):
                    raise HTTPException(422, "Specify allowed GitHub repositories as owner/repository.")
            config = value.model_dump(exclude={"id", "kind", "name", "cluster_id", "enabled", "token", "webhook_token"})
            connection_id = row.id if row else str(uuid4())
            credential_key = f"connection-{connection_id}"
            webhook_key = f"webhook-{connection_id}" if value.kind == "cluster" else None
            existing_token = None
            if value.enabled and not value.token:
                if value.kind == "argocd" and value.access_mode == "kubernetes":
                    existing_token = self.hosting_cluster_token(cluster, db)
                else:
                    existing_token = self.credentials().get(credential_key)
            if value.enabled and not (value.token or existing_token):
                detail = ("The selected hosting cluster has no stored credential available to incident response."
                    if value.kind == "argocd" and value.access_mode == "kubernetes" else
                    "A read-only credential is required before enabling the connection.")
                raise HTTPException(422, detail)
            if value.kind == "cluster" and value.enabled and not (value.webhook_token or self.credentials().get(webhook_key)):
                raise HTTPException(422, "Set a webhook bearer token of at least 32 characters.")
            if value.webhook_token and len(value.webhook_token) < 32:
                raise HTTPException(422, "Webhook bearer tokens must contain at least 32 characters.")
            if value.token and not (value.kind == "argocd" and value.access_mode == "kubernetes"):
                self.credentials().set(value.token, credential_key)
            elif value.kind == "argocd" and value.access_mode == "kubernetes":
                self.credentials().delete(credential_key)
            if value.webhook_token and webhook_key:
                self.credentials().set(value.webhook_token, webhook_key)
            if not row:
                row = IncidentConnection(id=connection_id, credential_key=credential_key, webhook_key=webhook_key)
                db.add(row)
            row.kind, row.name, row.cluster_id, row.enabled = value.kind, value.name, value.cluster_id, value.enabled
            row.config_json, row.updated_at = json.dumps(config), utcnow()
            self.audit(db, user.username, "connection_saved", connection_id=row.id, kind=row.kind,
                enabled=row.enabled, tls_verify=(cluster.tls_verify if cluster else True))
            db.commit()
            return {"id": row.id}

    def queue_discovery(self, engine, connection_id, actor):
        with Session(engine) as db:
            row = db.get(IncidentConnection, connection_id)
            if not row:
                raise HTTPException(404, "Connection not found.")
            discovery = db.get(ConnectorDiscovery, connection_id)
            if discovery and discovery.status in {"queued", "running"}:
                return {"id": connection_id, "discovery_status": discovery.status, "queued": False}
            now = utcnow()
            if not discovery:
                discovery = ConnectorDiscovery(connector_id=connection_id, requested_by=actor)
                db.add(discovery)
            discovery.status = "queued"
            discovery.requested_by = actor
            discovery.error = None
            discovery.started_at = None
            discovery.completed_at = None
            discovery.updated_at = now
            self.audit(db, actor, "connector_discovery_queued", connection_id=connection_id)
            db.commit()
            return {"id": connection_id, "discovery_status": "queued", "queued": True}

    def discover_connection(self, engine, connection_id):
        reader = None
        with Session(engine) as db:
            row = db.get(IncidentConnection, connection_id)
            discovery = db.get(ConnectorDiscovery, connection_id)
            if not row or not discovery:
                return
            discovery.status = "running"
            discovery.started_at = discovery.updated_at = utcnow()
            discovery.error = None
            db.commit()
            cfg = _json_object(row.config_json)
            token = self.token_for(row, db)
            cluster = db.get(Cluster, row.cluster_id) if row.cluster_id else None
            snapshot = {"id": row.id, "kind": row.kind, "name": row.name,
                "cluster_id": row.cluster_id, "config": cfg, "token": token, "cluster": cluster}
        try:
            if not snapshot["token"]:
                raise ValueError("credential unavailable")
            cfg = snapshot["config"]
            if snapshot["kind"] == "github":
                reader = self.reader_factory(cfg["url"], snapshot["token"], cfg.get("custom_ca_pem"))
                repositories, failures = [], []
                for repository in cfg.get("repositories", [])[:30]:
                    try:
                        info = reader.get(f"{cfg.get('api_prefix', '/api/v3')}/repos/{repository}")
                        if str(info.get("full_name", "")).casefold() != repository.casefold():
                            raise ValueError("repository identity mismatch")
                        repositories.append({"repository": repository,
                            "default_branch": info.get("default_branch")})
                    except Exception:
                        failures.append(repository)
                if not repositories and failures:
                    raise ValueError("no configured repositories were readable")
                result = {"checks": [f"{len(repositories)} configured repositories readable."],
                    "repositories": repositories, "unavailable_repositories": failures,
                    "partial": bool(failures)}
            elif snapshot["kind"] == "argocd":
                mode = cfg.get("access_mode") or ("direct" if cfg.get("url") else "kubernetes")
                if mode == "direct":
                    reader = self.reader_factory(cfg["url"], snapshot["token"], cfg.get("custom_ca_pem"))
                    namespace = None
                else:
                    if not snapshot["cluster"]:
                        raise ValueError("hosting cluster unavailable")
                    reader = self.cluster_reader(snapshot["cluster"], snapshot["token"])
                    namespace = cfg.get("namespace", "openshift-gitops")
                inventory = reader.argocd(cfg.get("projects", []), set(), set(),
                    utcnow() - timedelta(days=3650), namespace=namespace)
                applications = [{"application": app.get("application"), "project": app.get("project"),
                    "destination": app.get("destination"), "sources": app.get("sources", [])[:10],
                    "health": app.get("health"), "sync": app.get("sync")}
                    for app in inventory.get("applications", [])[:30] if isinstance(app, dict)]
                result = {"applications": applications, "partial": inventory.get("partial", False),
                    "limitations": inventory.get("limitations", []),
                    "checks": [f"{len(applications)} Applications discovered in allowed projects."],
                    "access_mode": mode,
                    "namespace": namespace}
            else:
                if not snapshot["cluster"]:
                    raise ValueError("cluster unavailable")
                reader = self.cluster_reader(snapshot["cluster"], snapshot["token"])
                version = reader.collect("version")
                capabilities = {"version": True}
                checks = ["Kubernetes API identity and version read succeeded."]
                for key in ("operators", "nodes", "machine-pools"):
                    try:
                        reader.collect(key)
                        capabilities[key] = True
                        checks.append(f"{key}: available")
                    except Exception:
                        capabilities[key] = False
                        checks.append(f"{key}: unavailable")
                try:
                    reader.get("/apis/argoproj.io/v1alpha1/applications", {"limit": 1})
                    capabilities["argocd_applications"] = True
                    checks.append("Argo CD Application resources: discoverable")
                except Exception:
                    capabilities["argocd_applications"] = False
                    checks.append("Argo CD Application resources: unavailable")
                result = {"checks": checks, "cluster": {"id": snapshot["cluster"].id,
                    "name": snapshot["cluster"].name, "api_url": snapshot["cluster"].api_url,
                    "version": version}, "capabilities": capabilities, "partial": False}
            result = clean_evidence(result, [snapshot["token"]])
            status = "partial" if result.get("partial") else "completed"
            with Session(engine) as db:
                discovery = db.get(ConnectorDiscovery, connection_id)
                if discovery:
                    discovery.status = status
                    discovery.result_json = json.dumps(result)
                    discovery.error = None
                    discovery.completed_at = discovery.updated_at = utcnow()
                    self.audit(db, discovery.requested_by, "connector_discovery_completed",
                        connection_id=connection_id, status=status)
                    db.commit()
        except Exception:
            with Session(engine) as db:
                discovery = db.get(ConnectorDiscovery, connection_id)
                if discovery:
                    discovery.status = "error"
                    discovery.error = "Discovery could not read the configured endpoint. Check its credential, TLS policy, scope, and availability."
                    discovery.completed_at = discovery.updated_at = utcnow()
                    self.audit(db, discovery.requested_by, "connector_discovery_completed", "failed",
                        connection_id=connection_id)
                    db.commit()
        finally:
            if reader:
                reader.close()

    def test_connection(self, engine, connection_id, user):
        self.queue_discovery(engine, connection_id, user.username)
        self.discover_connection(engine, connection_id)
        with Session(engine) as db:
            discovery = db.get(ConnectorDiscovery, connection_id)
            if not discovery or discovery.status == "error":
                raise HTTPException(502, discovery.error if discovery else "Connector discovery failed.")
            return {"checks": _json_object(discovery.result_json).get("checks", []),
                "discovery_status": discovery.status}

    def investigate(self, engine, run_id):
        started = time.monotonic()
        evidence, coordination_evidence, limitations = [], [], []
        secrets = []
        reader = None
        specialist_reports = 0
        activity_guard = Lock()
        activity = {
            "version": 1,
            "phase": "Starting",
            "current_work": "Preparing the investigation",
            "updated_at": utcnow().isoformat(),
            "tasks": [{
                "id": "coordinator", "role": "coordinator",
                "label": "Incident coordinator", "state": "running",
                "work": "Preparing the investigation", "queued_at": None,
                "started_at": utcnow().isoformat(), "ended_at": None, "result": "",
            }],
            "events": [],
        }
        briefing = {"summary": "Investigation could not establish a cause.", "hypotheses": [],
                    "next_steps": ["Review available evidence and restore missing investigation access."], "evidence_ids": []}
        status = "completed"

        def write_activity_locked():
            activity["updated_at"] = utcnow().isoformat()
            activity["tasks"] = activity.get("tasks", [])[:24]
            activity["events"] = activity.get("events", [])[-12:]
            with Session(engine) as activity_db:
                activity_db.execute(update(IncidentRun).where(IncidentRun.id == run_id).values(
                    activity_json=json.dumps(activity)))
                activity_db.commit()

        def coordinator_activity(work, *, phase=None, state=None, result=None):
            with activity_guard:
                coordinator = activity["tasks"][0]
                changed = coordinator.get("work") != work
                coordinator["work"] = str(work)[:300]
                activity["current_work"] = str(work)[:300]
                if phase:
                    activity["phase"] = str(phase)[:80]
                if state:
                    coordinator["state"] = state
                    if state in {"completed", "error", "stopped"}:
                        coordinator["ended_at"] = utcnow().isoformat()
                if result is not None:
                    coordinator["result"] = _bounded_activity_text(result)
                if changed:
                    activity["events"].append({
                        "at": utcnow().isoformat(), "label": "Coordinator",
                        "state": state or "running", "summary": _bounded_activity_text(work),
                    })
                write_activity_locked()

        def queue_specialist(label, work, source_item):
            with activity_guard:
                task_id = f"specialist-{len([t for t in activity['tasks'] if t.get('role') == 'specialist']) + 1}"
                activity["tasks"].append({
                    "id": task_id, "role": "specialist", "label": f"{label} specialist",
                    "source": f"{label} specialist", "state": "queued",
                    "work": str(work)[:300], "source_evidence_id": source_item.get("id"),
                    "queued_at": utcnow().isoformat(), "started_at": None,
                    "ended_at": None, "result": "",
                })
                activity["events"].append({
                    "at": utcnow().isoformat(), "label": f"{label} specialist",
                    "state": "queued", "summary": _bounded_activity_text(work),
                })
                write_activity_locked()
                return task_id

        def update_specialist(task_id, state, *, work=None, result=None):
            with activity_guard:
                task = next((item for item in activity["tasks"] if item.get("id") == task_id), None)
                if not task:
                    return
                task["state"] = state
                if work:
                    task["work"] = str(work)[:300]
                if state == "running" and not task.get("started_at"):
                    task["started_at"] = utcnow().isoformat()
                if state in {"completed", "error", "stopped"}:
                    task["ended_at"] = utcnow().isoformat()
                if result is not None:
                    task["result"] = _bounded_activity_text(result)
                activity["events"].append({
                    "at": utcnow().isoformat(), "label": task.get("label", "Specialist"),
                    "state": state, "summary": _bounded_activity_text(result or task.get("work") or ""),
                })
                write_activity_locked()

        def evidence_activity(item):
            with activity_guard:
                activity["events"].append({
                    "at": item["observed_at"], "label": item["source"],
                    "state": "completed", "summary": _activity_result(item["source"], item.get("data")),
                    "evidence_id": item["id"],
                })
                write_activity_locked()

        def record(source, data, *, coordinate=True):
            item = clean_evidence({"id": f"E{len(evidence)+1}", "source": source,
                "observed_at": utcnow().isoformat(), "cluster_id": cluster.id, "data": data}, secrets)
            collector_limit = max(32_768, min(
                self.settings.incident_max_evidence_bytes,
                self.settings.incident_log_max_bytes + 32_768,
            ))
            item, projection_limitation = _project_evidence_item(item, collector_limit)
            if projection_limitation:
                limitations.append(projection_limitation)
            if _serialized_bytes(evidence) + _serialized_bytes(item) > self.settings.incident_max_evidence_bytes:
                limitations.append("Total evidence budget reached; remaining collection is incomplete.")
                raise ValueError("Evidence budget reached")
            evidence.append(item)
            if coordinate:
                if _serialized_bytes(coordination_evidence) + _serialized_bytes(item) <= self.settings.incident_max_coordinator_bytes:
                    coordination_evidence.append(item)
                else:
                    limitations.append(f"{source}: retained for operators but omitted from coordinator context.")
            with Session(engine) as progress_db:
                progress_db.execute(update(IncidentRun).where(IncidentRun.id == run_id).values(evidence_json=json.dumps(evidence)))
                progress_db.commit()
            evidence_activity(item)
            return item

        def summarize_specialist(label, source_item, objective):
            nonlocal specialist_reports
            if not profile or not api_key or specialist_reports >= self.settings.incident_max_specialist_reports:
                return None
            if time.monotonic()-started > run_timeout:
                return None
            specialist_work = {
                "Argo CD": "Correlate recent platform deployment revisions with the alert onset",
                "GitHub": "Review commit and pull-request metadata for the correlated revision",
            }.get(label, objective)
            task_id = queue_specialist(label, specialist_work, source_item)
            update_specialist(task_id, "running")
            try:
                decision = self.provider.incident_step(deadline_profile(), api_key, {
                    "objective": objective,
                    "evidence": [source_item], "limitations": [],
                    "available_collectors": {}, "remaining_rounds": 0,
                    "specialist": label})
                if decision.collect:
                    limitations.append(f"{label} specialist requested unsupported additional collection.")
                    update_specialist(task_id, "error", result="Requested unsupported additional collection.")
                    return None
                report = decision.model_dump(exclude={"collect"})
                valid = {source_item["id"]}
                report["evidence_ids"] = [item for item in decision.evidence_ids if item in valid]
                if not report["evidence_ids"]:
                    limitations.append(f"{label} specialist returned no valid source citation.")
                specialist_reports += 1
                update_specialist(task_id, "completed", result=_activity_result(label, report))
                return record(f"{label} specialist", report)
            except Exception:
                limitations.append(f"{label} specialist analysis unavailable; bounded source evidence is retained.")
                update_specialist(task_id, "error", result="Analysis unavailable; source evidence was retained.")
                return None

        def analyze_log(work):
            source_item, task_id = work
            update_specialist(task_id, "running")
            analyzer = getattr(self.provider, "analyze_logs", None)
            if not callable(analyzer):
                update_specialist(task_id, "error", result=f"Analyzer unavailable for {source_item['id']}.")
                return None, f"Pod log specialist is unavailable for {source_item['id']}."
            data = source_item["data"]
            try:
                analysis = analyzer(deadline_profile(), api_key, {
                    "operator_request": "Identify incident-relevant anomalies in this container log.",
                    "investigation_context": [item for item in coordination_evidence if item["source"] == "Alertmanager notification"],
                    "logs": [{"evidence_id": source_item["id"], "namespace": data.get("namespace"),
                        "pod": data.get("pod"), "container": data.get("container"),
                        "excerpt": data.get("logs", "")}],
                })
                update_specialist(task_id, "completed", result=_activity_result("Pod log specialist", analysis.model_dump()))
                return ({**analysis.model_dump(), "source_evidence_ids": [source_item["id"]]}, None)
            except Exception:
                update_specialist(task_id, "error", result=f"Analysis failed for {source_item['id']}; logs retained.")
                return None, f"Pod log specialist could not analyze {source_item['id']}; raw bounded logs are retained."
        try:
            with Session(engine) as db:
                run = db.get(IncidentRun, run_id)
                incident = db.get(FleetIncident, run.incident_id)
                source = db.get(IncidentConnection, incident.source_id)
                cluster = db.get(Cluster, incident.cluster_id)
                if not source.enabled or not cluster.is_enabled or cluster.visibility != "shared":
                    raise ValueError("Incident connection is disabled.")
                alert_snapshot = json.loads(run.alert_snapshot_json)
                synthetic = all(a.get('labels', {}).get('podpilot_test') == 'true' for a in alert_snapshot.values())
                simulation = all(a.get('labels', {}).get('podpilot_simulation') == 'true' for a in alert_snapshot.values())
                run_timeout = 240 if synthetic else self.settings.incident_run_timeout_seconds
                hard_deadline_minutes = run_timeout / 60
                hard_deadline_limit = (
                    f"Overall {hard_deadline_minutes:g}-minute safety deadline reached."
                )
                limitations.extend(json.loads(incident.limitations_json))
                connector_rows = list(db.scalars(select(IncidentConnection).where(
                    IncidentConnection.enabled.is_(True), IncidentConnection.kind != "cluster")
                    .order_by(IncidentConnection.kind, IncidentConnection.name).limit(11)))
                connectors = connector_rows[:10]
                if len(connector_rows) > 10:
                    limitations.append("Only the first 10 enabled Argo CD/GitHub connectors were checked.")
            coordinator_activity("Validating cluster access and investigation policy", phase="Starting")
            token = self.credentials().get(source.credential_key)
            secrets.append(token)
            profile, api_key = self.model_context(engine)
            secrets.append(api_key)
            if profile and api_key:
                context_window = self.settings.incident_context_window_tokens
                output_limit = min(profile.max_output_tokens, max(1024, context_window // 4))
                input_limit = min(profile.max_input_tokens, max(1024, context_window - output_limit - 2048))
                profile = replace(profile, timeout_seconds=self.settings.incident_model_timeout_seconds,
                    max_output_tokens=output_limit, max_input_tokens=input_limit)
            def deadline_profile():
                remaining = run_timeout - (time.monotonic()-started)
                if remaining <= 1:
                    raise TimeoutError("Incident run deadline reached.")
                # Preserve the model profile's retry policy for every coordinator and
                # specialist call. Near the outer safety deadline, shorten each attempt
                # so the configured retry opportunities still fit inside the run.
                attempts = profile.max_retries + 1
                attempt_timeout = min(profile.timeout_seconds, remaining / attempts)
                return replace(profile, timeout_seconds=max(1.0, attempt_timeout))
            alert_namespaces = sorted({
                str((alert.get("labels") or {}).get("namespace") or "")
                for alert in alert_snapshot.values()
                if isinstance(alert, dict) and alert.get("status") == "firing"
                and re.fullmatch(
                    r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?",
                    str((alert.get("labels") or {}).get("namespace") or ""),
                )
            })
            if len(alert_namespaces) > 20:
                limitations.append(
                    "Alert group named more than 20 namespaces; namespaced evidence collection was limited to 20."
                )
                alert_namespaces = alert_namespaces[:20]
            reader = self.cluster_reader(cluster, token, alert_namespaces)
            source_config = json.loads(source.config_json)
            if source_config.get("monitoring_url"):
                reader.monitor = self.reader_factory(source_config["monitoring_url"], token,
                    source_config.get("custom_ca_pem"), cluster.tls_verify)
            else:
                limitations.append("Monitoring endpoint is not configured; platform metric trends are unavailable.")
            if not cluster.tls_verify and not cluster.is_system:
                limitations.append("Kubernetes TLS certificate and hostname verification is disabled for this cluster.")
            coordinator_activity("Reading the alert and current ClusterOperator health", phase="Initial assessment")
            record("Alertmanager notification", {"alerts": [{
                "status": a["status"], "starts_at": a["startsAt"],
                "labels": {k:v[:500] for k,v in a["labels"].items() if k in {
                    "alertname", "severity", "namespace", "name", "pod", "node", "instance", "job", "reason", "podpilot_test", "podpilot_simulation"}},
                "summary": a.get("annotations", {}).get("summary", "")[:500],
            } for a in list(alert_snapshot.values())[:20]], "total_alerts": len(alert_snapshot),
                "partial": len(alert_snapshot)>20})
            try:
                record("operators", reader.collect("operators"))
            except Exception as exc:
                limitations.append(
                    f"Cluster operator snapshot failed: {_collector_failure_reason(exc)} "
                    "Other evidence collection continued."
                )
            cluster_health_collected = False
            if "cluster-health" in reader.catalog():
                try:
                    coordinator_activity("Surveying unhealthy resources across the cluster", phase="Initial assessment")
                    record("cluster-health", reader.collect("cluster-health"))
                    cluster_health_collected = True
                except Exception as exc:
                    limitations.append(
                        "Cluster-wide unhealthy-resource survey failed: "
                        f"{_collector_failure_reason(exc)} Scoped investigation continued."
                    )
            # Preserve recent changes before model-guided investigation; no arbitrary repository traversal.
            changes = []
            onset = min(datetime.fromisoformat(a["startsAt"]) for a in alert_snapshot.values())
            set_log_window = getattr(reader, "set_log_window", None)
            if callable(set_log_window):
                set_log_window(onset)
            if connectors:
                coordinator_activity("Correlating recent platform deployments and repository metadata", phase="Change correlation")
            for connector in connectors:
                if time.monotonic()-started > self.settings.incident_connector_timeout_seconds:
                    limitations.append("Connector collection time budget reached.")
                    break
                cfg = json.loads(connector.config_json)
                if connector.kind != "argocd":
                    continue
                other = None
                try:
                    with Session(engine) as db:
                        credential = self.token_for(connector, db)
                    secrets.append(credential)
                    servers = {cluster.api_url.rstrip('/')}
                    configured_aliases = source_config.get("cluster_aliases", [])
                    if not isinstance(configured_aliases, list):
                        configured_aliases = []
                    names = {cluster.name, *(alias for alias in configured_aliases if isinstance(alias, str))}
                    if self.access_mode(connector, cfg) == "direct":
                        other = self.reader_factory(cfg["url"], credential, cfg.get("custom_ca_pem"))
                        result = other.argocd(cfg["projects"], servers, names, onset - timedelta(hours=2))
                    else:
                        with Session(engine) as db:
                            host = db.get(Cluster, connector.cluster_id)
                        if not host or not host.is_enabled or host.visibility != "shared":
                            raise ValueError("Argo CD hosting cluster unavailable")
                        other = self.cluster_reader(host, credential)
                        if host.id == cluster.id:
                            servers.add("https://kubernetes.default.svc")
                        legacy_names = cfg.get("destination_names", {})
                        names.update([legacy_names[cluster.id]] if cluster.id in legacy_names else [])
                        result = other.argocd(cfg["projects"], servers, names,
                            onset - timedelta(hours=2), namespace=cfg.get("namespace", "openshift-gitops"))
                    source_item = record(f"Argo CD: {connector.name}", result, coordinate=False)
                    summarize_specialist("Argo CD", source_item,
                        "Correlate only this Argo CD deployment evidence with the incident onset. Return a compact cited report of relevant platform deployment changes, contradictions, and gaps. Do not request more collection.")
                    changes.extend(result["changes"])
                    for application in result.get("applications", [])[:30]:
                        for app_source in application.get("sources", [])[:10]:
                            if app_source.get("repository") and app_source.get("deployed_revision"):
                                changes.append({"application": application.get("application"),
                                    "project": application.get("project"),
                                    "repository": app_source["repository"], "path": app_source.get("path"),
                                    "revision": app_source["deployed_revision"],
                                    "relationship": "current Argo CD sync"})
                except Exception as exc:
                    limitations.append(
                        f"Argo CD connector {connector.name} failed: {_collector_failure_reason(exc)}"
                    )
                finally:
                    if other:
                        other.close()
            for connector in connectors:
                if connector.kind != "github" or time.monotonic()-started > self.settings.incident_connector_timeout_seconds:
                    continue
                cfg = json.loads(connector.config_json)
                other = None
                try:
                    credential = self.credentials().get(connector.credential_key)
                    secrets.append(credential)
                    other = self.reader_factory(cfg["url"], credential, cfg.get("custom_ca_pem"))
                    candidates = {}
                    for change in changes[:40]:
                        repo_url = change.get("repository") or ""
                        # Support HTTPS and the common git@host:owner/repo.git form.
                        if repo_url.startswith("git@"):
                            repo_url = "ssh://" + repo_url.replace(":", "/", 1)
                        parsed = urlsplit(repo_url)
                        repo = parsed.path.strip('/').removesuffix('.git')
                        identity = (repo, change.get("revision"))
                        if (_github_repository_host(parsed.hostname) != _github_repository_host(
                                urlsplit(cfg["url"]).hostname) or repo not in cfg["repositories"]
                                or not re.fullmatch(r"[a-fA-F0-9]{40,64}", change.get("revision") or "")):
                            continue
                        candidates.setdefault(identity, []).append({
                            "application": change.get("application"), "project": change.get("project"),
                            "path": change.get("path"), "deployed_at": change.get("deployed_at"),
                            "relationship": change.get("relationship", "Argo CD deployment history"),
                        })
                    for (repo, revision), deployment_contexts in list(candidates.items())[:10]:
                        if time.monotonic()-started > self.settings.incident_connector_timeout_seconds:
                            break
                        metadata = other.github(repo, revision, cfg["api_prefix"])
                        metadata["deployment_contexts"] = deployment_contexts[:10]
                        source_item = record(f"GitHub: {connector.name}",
                            metadata, coordinate=False)
                        summarize_specialist("GitHub", source_item,
                            "Assess only this revision and pull-request metadata for incident relevance. Return a compact cited report of timing, likely relationship, contradictions, and gaps. Do not infer diff contents or request more collection.")
                except Exception as exc:
                    limitations.append(
                        f"GitHub connector {connector.name} failed: {_collector_failure_reason(exc)}"
                    )
                finally:
                    if other:
                        other.close()
            if not profile or not api_key:
                coordinator_activity("Collecting deterministic cluster snapshots", phase="Evidence collection")
                limitations.append("No usable model profile; deterministic cluster snapshots only.")
                for key in ("version", "nodes", "machine-pools"):
                    try:
                        record(key, reader.collect(key))
                    except Exception:
                        limitations.append(f"{key}: evidence unavailable.")
                status = "partial"
            else:
                available = reader.catalog()
                available.pop("operators", None)
                consumed = {"operators"}
                if cluster_health_collected:
                    available.pop("cluster-health", None)
                    consumed.add("cluster-health")
                max_rounds = 6 if synthetic else self.settings.incident_max_rounds
                for step in range(max_rounds):
                    if time.monotonic()-started > run_timeout:
                        limitations.append(hard_deadline_limit)
                        status = "budget_exhausted"
                        break
                    coordinator_activity(
                        f"Planning investigation round {step + 1} (max {max_rounds})",
                        phase="Investigation planning",
                    )
                    decision = self.provider.incident_step(deadline_profile(), api_key, {
                        "objective": (
                            "This signal is labelled as a synthetic webhook test. Verify basic platform access from the operator snapshot and at most version/node snapshots, then finish with a concise test result. The test signal is not evidence of an etcd outage. Report any independently observed health issues separately; do not pursue an RCA for the synthetic signal."
                            if synthetic else
                            "This is a controlled incident simulation. Conduct a normal, thorough Kubernetes or OpenShift investigation across relevant bounded collectors and specialist reports, but do not assume the simulated alert labels prove a real failure. Separate observed cluster impact from the scenario premise and finish with cited findings and operator next steps."
                            if simulation else
                            "Investigate this admitted critical Kubernetes or OpenShift incident; identify impact, likely causes, contradictions, recent changes and operator next steps."
                        ),
                        "evidence": coordination_evidence,
                        "limitations": _dedupe_limitations([
                            *_evidence_limitations(evidence), *limitations,
                        ]),
                        "available_collectors": available if step < max_rounds-1 else {},
                        "remaining_rounds": max_rounds-1-step,
                        "specialist_reports": specialist_reports})
                    if not decision.collect:
                        coordinator_activity("Validating citations and preparing the operator briefing", phase="Final assessment")
                        briefing = clean_evidence(decision.model_dump(exclude={"collect"}), secrets)
                        valid_ids = {e["id"] for e in evidence}
                        if not decision.evidence_ids or set(decision.evidence_ids)-valid_ids:
                            limitations.append("Model briefing has missing or invalid evidence citations; treat as unverified.")
                            status = "partial"
                        briefing["evidence_ids"] = [e for e in decision.evidence_ids if e in valid_ids]
                        break
                    if step == max_rounds-1:
                        status = "budget_exhausted"
                        limitations.append(
                            f"Coordinator turn budget reached after {max_rounds} investigation rounds."
                        )
                        break
                    log_items = []
                    for key in decision.collect:
                        if time.monotonic()-started > run_timeout:
                            limitations.append(hard_deadline_limit)
                            status = "budget_exhausted"
                            break
                        if key not in available:
                            limitations.append("Model requested an unavailable collector; request rejected.")
                            continue
                        collector_label = available.pop(key)
                        consumed.add(key)
                        try:
                            coordinator_activity(f"Collecting {collector_label}", phase="Evidence collection")
                            is_log_collector = key.startswith(("logs:", "logs-previous:", "loki-logs:"))
                            source_item = record(key, reader.collect(key), coordinate=not is_log_collector)
                            if is_log_collector:
                                log_items.append(source_item)
                            available = {k:v for k,v in reader.catalog().items() if k not in consumed}
                        except Exception as exc:
                            detail = _collector_failure_reason(exc)
                            limitations.append(
                                f"{key}: {detail}" if detail else
                                f"{key}: read unavailable or response too large."
                            )
                    slots = max(0, self.settings.incident_max_specialist_reports-specialist_reports)
                    selected_logs = log_items[:slots]
                    if selected_logs:
                        specialist_work = []
                        for source_item in selected_logs:
                            data = source_item.get("data") or {}
                            target = "/".join(filter(None, [data.get("namespace"), data.get("pod"), data.get("container")]))
                            work = f"Analyze bounded incident logs{f' for {target}' if target else ''}"
                            specialist_work.append((source_item, queue_specialist("Pod log", work, source_item)))
                        coordinator_activity(
                            f"Waiting for {len(selected_logs)} Pod log specialist{'s' if len(selected_logs) != 1 else ''}",
                            phase="Specialist analysis",
                        )
                        with ThreadPoolExecutor(max_workers=min(3, len(selected_logs)),
                                thread_name_prefix="incident-log-specialist") as pool:
                            analyses = list(pool.map(analyze_log, specialist_work))
                        for source_item, (analysis, error) in zip(selected_logs, analyses):
                            if analysis:
                                specialist_reports += 1
                                record("Pod log specialist", analysis)
                            else:
                                limitations.append(error)
                                if _serialized_bytes(coordination_evidence) + _serialized_bytes(source_item) <= self.settings.incident_max_coordinator_bytes:
                                    coordination_evidence.append(source_item)
                    for source_item in log_items[slots:]:
                        limitations.append(f"Pod log specialist report limit reached; {source_item['id']} remains in retained evidence.")
        except Exception:
            status = "partial" if evidence else "failed"
            limitations.append("Investigation interrupted by an unavailable credential, API, or model. Inspect connection tests and retained evidence.")
        finally:
            if reader:
                reader.close()
        model_limitations = _dedupe_limitations([
            *_evidence_limitations(evidence, model_authored=True),
            *briefing.get("limitations", []),
        ])
        system_limitations = _dedupe_limitations([
            *_evidence_limitations(evidence, model_authored=False),
            *limitations,
        ])
        system_keys = {_limitation_key(item) for item in system_limitations}
        model_limitations = _dedupe_limitations(model_limitations, exclude_keys=system_keys)
        briefing["system_limitations"] = system_limitations
        briefing["model_limitations"] = model_limitations
        briefing["limitations"] = [*system_limitations, *model_limitations]
        briefing = clean_evidence(briefing, secrets)
        coordinator_state = "completed" if status in {"completed", "partial"} else "error" if status == "failed" else "stopped"
        coordinator_activity(
            "Investigation finished; open the case for the full assessment.",
            phase=status.replace("_", " ").capitalize(), state=coordinator_state,
            result=f"Retained {len(evidence)} evidence item{'s' if len(evidence) != 1 else ''}; status {status.replace('_', ' ')}.",
        )
        with Session(engine) as db:
            db.execute(update(IncidentRun).where(IncidentRun.id == run_id).values(status=status,
                evidence_json=json.dumps(evidence), briefing_json=json.dumps(briefing),
                activity_json=json.dumps(activity), completed_at=utcnow()))
            self.audit(db, "system:incident-worker", "run_finished", status, run_id=run_id, evidence_count=len(evidence))
            db.commit()

    async def worker(self, app):
        engine = app.state.engine
        # A interrupted run retains evidence and is explicitly partial; never silently re-run it.
        with Session(engine) as db:
            interrupted_at = utcnow().isoformat()
            for run in db.scalars(select(IncidentRun).where(IncidentRun.status == "running")):
                activity = _json_object(run.activity_json)
                activity["phase"] = "Interrupted"
                activity["current_work"] = "Worker restarted; retained evidence is available"
                activity["updated_at"] = interrupted_at
                for task in activity.get("tasks", []):
                    if task.get("state") in {"queued", "running"}:
                        task["state"] = "stopped"
                        task["ended_at"] = interrupted_at
                        task["result"] = (
                            "The PodPilot incident worker restarted before this task finished. "
                            "Collected evidence was retained; rerun the investigation to continue."
                        )
                run.status = "interrupted"
                run.activity_json = json.dumps(activity)
                run.briefing_json = json.dumps({"summary": "The PodPilot incident worker restarted during the investigation. Retained evidence is available; an operator can rerun."})
            db.commit()
        claim_lock = asyncio.Lock()
        async def slot():
            while True:
                async with claim_lock:
                    with Session(engine) as db:
                        run_id = db.scalar(select(IncidentRun.id).where(IncidentRun.status == "queued").order_by(IncidentRun.created_at).limit(1))
                        if run_id:
                            claimed = db.execute(update(IncidentRun).where(IncidentRun.id == run_id,
                                IncidentRun.status == "queued").values(status="running")).rowcount
                            db.commit()
                        else:
                            claimed = False
                if claimed:
                    task = asyncio.create_task(asyncio.to_thread(self.investigate, engine, run_id))
                    try:
                        await asyncio.shield(task)
                    except asyncio.CancelledError:
                        # Drain bounded in-flight reads before the lifespan disposes its engine.
                        await task
                        raise
                else:
                    await asyncio.sleep(2)
        await asyncio.gather(*(slot() for _ in range(self.settings.incident_worker_concurrency)))


def install_incidents(app, service, current_user, templates, csrf_token, verify_csrf):
    def page(request, user, template, context):
        token, fresh = csrf_token(request)
        response = templates.TemplateResponse(request=request, name=template,
            context={"user": user, "csrf_token": token, **context})
        if fresh:
            response.set_cookie("podpilot_csrf", token, secure=service.settings.auth_mode == "proxy", httponly=True, samesite="strict", max_age=28800)
        return response

    def schedule_discovery(connection_id):
        task = asyncio.create_task(asyncio.to_thread(
            service.discover_connection, app.state.engine, connection_id
        ), name=f"podpilot-connector-discovery-{connection_id}")
        app.state.connector_discovery_tasks.add(task)
        task.add_done_callback(app.state.connector_discovery_tasks.discard)

    @app.post("/api/v1/incident-webhooks/{source_id}", status_code=202)
    async def webhook(source_id: str, request: Request):
        service.require_enabled()
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 131072:
                raise HTTPException(413, "Webhook exceeds 128 KiB.")
        token = request.headers.get("authorization", "").removeprefix("Bearer ")
        try:
            async with service.lock:
                return await asyncio.to_thread(service.ingest, app.state.engine, source_id, token, json.loads(body))
        except (ValidationError, ValueError):
            raise HTTPException(422, "Invalid Alertmanager notification.")

    @app.get("/incidents")
    async def incidents(request: Request, user=Depends(current_user)):
        service.view(user)
        with Session(app.state.engine) as db:
            query = select(FleetIncident).order_by(FleetIncident.updated_at.desc())
            cluster_filter = request.query_params.get("cluster", "")
            if cluster_filter:
                query = query.where(FleetIncident.cluster_id == cluster_filter)
            rows = list(db.scalars(query.limit(100)))
            clusters = {c.id: c.name for c in db.scalars(select(Cluster).where(Cluster.visibility == "shared"))}
            runs = {r.id: db.scalar(select(IncidentRun).where(IncidentRun.incident_id == r.id).order_by(IncidentRun.created_at.desc()).limit(1)) for r in rows}
        views = [_incident_activity_view(row, runs[row.id]) for row in rows]
        active = [item for item in views if item["active"]]
        history = [item for item in views if not item["active"]]
        return page(request, user, "incidents.html", {
            "incidents": rows, "clusters": clusters, "runs": runs,
            "active_incidents": active, "historical_incidents": history,
        })

    @app.get("/incidents/{incident_id}")
    async def detail(incident_id: str, request: Request, user=Depends(current_user)):
        service.view(user)
        with Session(app.state.engine) as db:
            incident = db.get(FleetIncident, incident_id)
            if not incident:
                raise HTTPException(404, "Incident not found.")
            cluster = db.get(Cluster, incident.cluster_id)
            runs = list(db.scalars(select(IncidentRun).where(IncidentRun.incident_id == incident_id).order_by(IncidentRun.created_at.desc()).limit(25)))
            state_version = _incident_state_version(db, incident_id=incident_id)
        alerts = list(json.loads(incident.alerts_json).values())
        grouped_alerts = {}
        for alert in alerts:
            labels = alert.get("labels") or {}
            annotations = alert.get("annotations") or {}
            key = (labels.get("alertname", "Unknown alert"), alert.get("status", "unknown"), alert.get("startsAt", ""))
            if key not in grouped_alerts:
                grouped_alerts[key] = {
                    "name": key[0], "status": key[1], "started_at": key[2],
                    "severity": labels.get("severity", "unknown"),
                    "summary": annotations.get("summary") or annotations.get("description") or "",
                    "count": 0,
                }
            grouped_alerts[key]["count"] += 1

        run_views = []
        for index, run in enumerate(runs):
            briefing = json.loads(run.briefing_json)
            evidence = json.loads(run.evidence_json)
            valid_ids = {str(item.get("id")) for item in evidence}
            narrative = json.dumps({
                "summary": briefing.get("summary", ""),
                "hypotheses": briefing.get("hypotheses", []),
                "next_steps": briefing.get("next_steps", []),
            })
            mentioned_ids = re.findall(r"\bE\d+\b", narrative)
            supporting_ids = list(dict.fromkeys([
                *[str(item) for item in briefing.get("evidence_ids", [])],
                *mentioned_ids,
            ]))
            has_typed_limitations = (
                "system_limitations" in briefing or "model_limitations" in briefing
            )
            evidence_cards = []
            object_refs = []
            for item in evidence:
                card = dict(item)
                card["summary"] = _activity_result(str(item.get("source") or ""), item.get("data"))
                card["objects"] = _evidence_object_refs(item)
                evidence_cards.append(card)
                object_refs.extend(card["objects"])
            activity_view = _incident_activity_view(incident, run)
            run_views.append({
                "row": run,
                "number": len(runs) - index,
                "briefing": briefing,
                "problems": _briefing_problems(briefing),
                "evidence": evidence_cards,
                "source_count": len({
                    str(item.get("source") or "").strip()
                    for item in evidence
                    if str(item.get("source") or "").strip()
                }),
                "activity": activity_view,
                "object_refs": object_refs[:24],
                "valid_evidence_ids": sorted(
                    valid_ids,
                    key=lambda item: int(item[1:]) if item[1:].isdigit() else 0,
                ),
                "supporting_ids": [item for item in supporting_ids if item in valid_ids],
                "hypotheses": [re.sub(r"^\s*(?:\d+\s*[.)]\s*|[-*•]\s*)", "", str(item)) for item in briefing.get("hypotheses", [])],
                "next_steps": [re.sub(r"^\s*(?:\d+\s*[.)]\s*|[-*•]\s*)", "", str(item)) for item in briefing.get("next_steps", [])],
                "system_limitations": [re.sub(r"^\s*[-*•]\s*", "", str(item)) for item in (
                    briefing.get("system_limitations", []) if has_typed_limitations else []
                )],
                "model_limitations": [re.sub(r"^\s*[-*•]\s*", "", str(item)) for item in briefing.get(
                    "model_limitations", [],
                )],
                "legacy_limitations": [] if has_typed_limitations else [
                    re.sub(r"^\s*[-*•]\s*", "", str(item))
                    for item in briefing.get("limitations", [])
                ],
            })
        return page(request, user, "incident_detail.html", {"incident": incident, "cluster": cluster,
            "alerts": alerts, "alert_groups": list(grouped_alerts.values()),
            "incident_limitations": json.loads(incident.limitations_json), "runs": run_views,
            "state_version": state_version})

    @app.get("/api/v1/incidents/events")
    async def incident_events(request: Request, user=Depends(current_user)):
        service.view(user)
        cluster_id = request.query_params.get("cluster") or None

        async def stream():
            last_seen = request.headers.get("last-event-id", "")
            heartbeat_at = utcnow()
            while True:
                if await request.is_disconnected():
                    return
                with Session(app.state.engine) as db:
                    version = _incident_state_version(db, cluster_id=cluster_id)
                if version != last_seen:
                    last_seen = version
                    yield f"id: {version}\nevent: update\ndata: {{\"version\":\"{version}\"}}\n\n"
                now = utcnow()
                if (now - heartbeat_at).total_seconds() >= 10:
                    yield ": heartbeat\n\n"
                    heartbeat_at = now
                await asyncio.sleep(0.5)

        return StreamingResponse(stream(), media_type="text/event-stream", headers={
            "Cache-Control": "no-cache, no-store",
            "X-Accel-Buffering": "no",
        })

    @app.get("/api/v1/incidents/{incident_id}/events")
    async def incident_detail_events(incident_id: str, request: Request, user=Depends(current_user)):
        service.view(user)
        with Session(app.state.engine) as db:
            if db.get(FleetIncident, incident_id) is None:
                raise HTTPException(404, "Incident not found.")

        async def stream():
            last_seen = request.headers.get("last-event-id", "")
            heartbeat_at = utcnow()
            while True:
                if await request.is_disconnected():
                    return
                with Session(app.state.engine) as db:
                    if db.get(FleetIncident, incident_id) is None:
                        return
                    version = _incident_state_version(db, incident_id=incident_id)
                if version != last_seen:
                    last_seen = version
                    yield f"id: {version}\nevent: update\ndata: {{\"version\":\"{version}\"}}\n\n"
                now = utcnow()
                if (now - heartbeat_at).total_seconds() >= 10:
                    yield ": heartbeat\n\n"
                    heartbeat_at = now
                await asyncio.sleep(0.5)

        return StreamingResponse(stream(), media_type="text/event-stream", headers={
            "Cache-Control": "no-cache, no-store",
            "X-Accel-Buffering": "no",
        })

    @app.post("/api/v1/incidents/{incident_id}/rerun")
    async def rerun(incident_id: str, request: Request, user=Depends(current_user)):
        service.view(user)
        verify_csrf(request)
        async with service.lock:
            with Session(app.state.engine) as db:
                incident = db.get(FleetIncident, incident_id)
                if not incident:
                    raise HTTPException(404, "Incident not found.")
                existing = db.scalar(select(IncidentRun.id).where(IncidentRun.incident_id == incident_id, IncidentRun.status.in_(["queued", "running"])))
                if existing:
                    raise HTTPException(409, "An investigation is already queued or running.")
                if db.scalar(select(func.count()).select_from(IncidentRun).where(IncidentRun.status.in_(["queued", "running"]))) >= 100:
                    raise HTTPException(503, "Incident queue is full.")
                db.add(IncidentRun(id=str(uuid4()), incident_id=incident.id, actor=user.username,
                    alert_snapshot_json=incident.alerts_json, status="queued",
                    activity_json=_queued_activity()))
                service.audit(db, user.username, "rerun", incident_id=incident.id)
                db.commit()
        return {"ok": True}

    @app.post("/api/v1/incidents/{incident_id}/continue")
    async def continue_in_ask(incident_id: str, request: Request, user=Depends(current_user)):
        service.view(user)
        verify_csrf(request)
        if not service.settings.delegated_access_enabled:
            raise HTTPException(409, "Enable delegated Ask access before continuing an incident interactively.")
        with Session(app.state.engine) as db:
            incident = db.get(FleetIncident, incident_id)
            if not incident:
                raise HTTPException(404, "Incident not found.")
            run = db.scalar(select(IncidentRun).where(IncidentRun.incident_id == incident_id,
                IncidentRun.status.notin_(["queued", "running"])).order_by(IncidentRun.created_at.desc()).limit(1))
            if not run:
                raise HTTPException(409, "Wait for an investigation to finish before continuing in Ask.")
            cluster = db.get(Cluster, incident.cluster_id)
            run_ids = list(db.scalars(select(IncidentRun.id).where(
                IncidentRun.incident_id == incident_id,
            ).order_by(IncidentRun.created_at, IncidentRun.id)))
            run_number = run_ids.index(run.id) + 1
            cid = str(uuid4())
            retained = json.loads(run.evidence_json)
            evidence = [{"id": f"incident-{run.id}-{e['id']}", "tool": "incident_snapshot",
                "summary": e['source'], "source": f"Incident {incident_id} / run {run.id}",
                "collected_at": e['observed_at'], "cluster_id": incident.cluster_id,
                "origin": {"type": "incident", "incident_id": incident_id,
                    "run_id": run.id, "evidence_id": e['id']},
                "data": e['data']} for e in retained]
            briefing = json.loads(run.briefing_json)
            completed_at = (run.completed_at or run.created_at).isoformat()
            observed_at = [str(item.get("observed_at") or "") for item in retained if item.get("observed_at")]
            prompt = (
                f'Continue investigating incident "{incident.title}" using the imported historical evidence '
                f"from Investigation {run_number}. Revalidate the current state on cluster "
                f'"{cluster.name if cluster else incident.cluster_id}"; determine whether the reported condition '
                "and suspected causes still exist; investigate unresolved evidence gaps and relevant adjacent "
                "dependencies; and compare new observations with the imported timestamps. Clearly distinguish "
                "historical evidence from current evidence, cite both, and do not make changes."
            )
            context = (
                "Imported incident context (historical snapshot)\n"
                f"Incident: {incident.title} ({incident.id})\n"
                f"Investigation: {run_number} ({run.id})\n"
                f"Completed: {completed_at}\n"
                f"Assessment: {briefing.get('summary', '')}\n"
                "Treat imported observations as historical evidence. Revalidate current state before asserting "
                "that a condition persists."
            )
            handoff = {
                "version": 1, "status": "pending", "incident_id": incident.id,
                "incident_title": incident.title, "run_id": run.id, "run_number": run_number,
                "completed_at": completed_at, "evidence_count": len(evidence),
                "evidence_started_at": min(observed_at) if observed_at else None,
                "evidence_ended_at": max(observed_at) if observed_at else None,
                "report_url": f"/incidents/{incident_id}",
                "summary": str(briefing.get("summary") or "")[:1200],
                "prompt": prompt[:service.settings.chat_max_chars],
            }
            db.add(AdHocConversation(id=cid, created_by=user.username, title=f"Incident: {incident.title}"[:253],
                status="active", cluster_ids_json=json.dumps([incident.cluster_id]), execution_mode="read_only",
                # A nonempty expired session marker invokes the existing reconnect flow. It grants no capability.
                delegated_session_id=f"incident-{uuid4()}", evidence_json=json.dumps(evidence),
                context_summary=context[:4000], handoff_json=json.dumps(handoff)))
            service.audit(db, user.username, "continue_in_ask", incident_id=incident_id, conversation_id=cid)
            db.commit()
        return {"url": f"/ask/{cid}"}

    @app.get("/settings/connectors")
    async def connectors(request: Request, user=Depends(current_user)):
        service.manage(user)
        with Session(app.state.engine) as db:
            rows = list(db.scalars(select(IncidentConnection).order_by(IncidentConnection.kind, IncidentConnection.name)))
            clusters = list(db.scalars(select(Cluster).where(Cluster.visibility == "shared", Cluster.is_enabled.is_(True))))
            discoveries = list(db.scalars(select(ConnectorDiscovery).order_by(ConnectorDiscovery.updated_at.desc())))
        discovery_views, topology = _connector_topology(rows, discoveries, clusters)
        selected = next((r for r in rows if r.id == request.query_params.get("edit")), None)
        requested_kind = request.query_params.get("type")
        new_kind = requested_kind if requested_kind in {"cluster", "argocd", "github"} else None
        requested_cluster_id = request.query_params.get("cluster_id") if new_kind == "cluster" else None
        new_cluster = next((cluster for cluster in clusters if cluster.id == requested_cluster_id), None)
        receiver_status = None
        if selected and selected.kind == "cluster":
            with Session(app.state.engine) as db:
                receiver_status = {
                    "last_delivery": db.scalar(
                        select(func.max(FleetIncident.updated_at))
                        .where(FleetIncident.source_id == selected.id)
                    ),
                    "incident_count": db.scalar(
                        select(func.count()).select_from(FleetIncident)
                        .where(FleetIncident.source_id == selected.id)
                    ),
                }
        return page(request, user, "connectors.html", {"connections": rows, "clusters": clusters,
            "selected": selected, "new_kind": new_kind, "new_cluster": new_cluster,
            "choose_kind": request.query_params.get("new") == "1" and new_kind is None,
            "config": json.loads(selected.config_json) if selected else {}, "default_alerts": DEFAULT_ALERTS,
            "discovery_views": discovery_views, "topology": topology,
            "receiver_status": receiver_status,
            "incident_policy": {
                "context_window_tokens": service.settings.incident_context_window_tokens,
                "run_timeout_seconds": service.settings.incident_run_timeout_seconds,
                "max_rounds": service.settings.incident_max_rounds,
                "max_specialists": service.settings.incident_max_specialist_reports,
                "worker_concurrency": service.settings.incident_worker_concurrency,
                "evidence_bytes": service.settings.incident_max_evidence_bytes,
                "coordinator_bytes": service.settings.incident_max_coordinator_bytes,
                "log_tail_lines": service.settings.incident_log_tail_lines,
                "log_bytes": service.settings.incident_log_max_bytes,
                "log_range_seconds": service.settings.incident_log_range_seconds,
                "loki_log_limit": service.settings.incident_loki_log_limit,
                "loki_range_seconds": service.settings.incident_loki_range_seconds,
            }})

    @app.get("/api/v1/incident-connections/events")
    async def connector_events(request: Request, user=Depends(current_user)):
        service.manage(user)
        async def stream():
            last_seen = request.headers.get("last-event-id", "")
            heartbeat_at = utcnow()
            while True:
                if await request.is_disconnected():
                    return
                with Session(app.state.engine) as db:
                    version = _connector_state_version(db)
                if version != last_seen:
                    last_seen = version
                    yield f'id: {version}\nevent: update\ndata: {{"version":"{version}"}}\n\n'
                now = utcnow()
                if (now - heartbeat_at).total_seconds() >= 10:
                    yield ": heartbeat\n\n"
                    heartbeat_at = now
                await asyncio.sleep(0.5)
        return StreamingResponse(stream(), media_type="text/event-stream", headers={
            "Cache-Control": "no-cache, no-store", "X-Accel-Buffering": "no"})

    @app.get("/settings/webhooks")
    async def webhook_settings(request: Request, user=Depends(current_user)):
        service.manage(user)
        return RedirectResponse("/settings/connectors", status_code=303)

    @app.post("/api/v1/incident-connections")
    async def save(request: Request, user=Depends(current_user)):
        service.manage(user)
        verify_csrf(request)
        body = await request.body()
        if len(body) > 65536:
            raise HTTPException(413, "Configuration exceeds 64 KiB.")
        try:
            value = ConnectionInput.model_validate_json(body)
            async with service.lock:
                result = await asyncio.to_thread(service.save, app.state.engine, value, user)
                if value.enabled and service.settings.incident_connector_discovery_enabled:
                    queued = await asyncio.to_thread(service.queue_discovery,
                        app.state.engine, result["id"], user.username)
                    if queued["queued"]:
                        schedule_discovery(result["id"])
                    result["discovery_status"] = queued["discovery_status"]
                return result
        except (ValidationError, ValueError):
            raise HTTPException(422, "Invalid connector configuration; check field formats.")
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(503, "Credential Secret unavailable. Verify the incident Secret and scoped RBAC.")

    @app.post("/api/v1/incident-connections/{connection_id}/test")
    async def test(connection_id: str, request: Request, user=Depends(current_user)):
        service.manage(user)
        verify_csrf(request)
        queued = await asyncio.to_thread(service.queue_discovery,
            app.state.engine, connection_id, user.username)
        if queued["queued"]:
            schedule_discovery(connection_id)
        return queued
