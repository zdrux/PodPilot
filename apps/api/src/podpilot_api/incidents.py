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
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field, ConfigDict, ValidationError
from sqlalchemy import select, update, func
from sqlalchemy.orm import Session

from podpilot_api.auth import Role
from podpilot_api.models import Cluster, AuditEvent, AdHocConversation, AdHocMessage
from podpilot_api.incident_models import IncidentConnection, FleetIncident, IncidentRun
from podpilot_diagnostics.incidents import DEFAULT_ALERTS, AlertWebhook, admitted
from podpilot_openshift.incidents import IncidentReader, https_origin, clean_evidence
from podpilot_openshift.credentials import KubernetesSecretCredentialStore


def utcnow():
    return datetime.now(timezone.utc)


def _json_object(value):
    try:
        parsed = json.loads(value or "{}")
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _activity_result(source, data):
    """Return a short operator-safe description of retained evidence."""

    if not isinstance(data, dict):
        return "Evidence retained for review."
    summary = data.get("summary") or data.get("overview")
    if isinstance(summary, str) and summary.strip():
        return re.sub(r"\s+", " ", summary).strip()[:240]
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
        return str(data["limitation"])[:240]
    return "Evidence retained for review."


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
    events = [{
        "at": event.get("at"),
        "label": str(event.get("label") or "Investigation")[:120],
        # Journal entries are immutable history. A recorded running transition
        # means the task started; only the current workstream may look active.
        "state": (
            "started" if str(event.get("state") or "") == "running"
            else str(event.get("state") or "completed")[:32]
        ),
        "summary": str(event.get("summary") or "")[:240],
    } for event in activity.get("events", [])[-6:] if isinstance(event, dict)]
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


class ConnectionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str | None = Field(default=None, max_length=36)
    kind: str = Field(pattern="^(cluster|argocd|github)$")
    name: str = Field(min_length=1, max_length=100)
    cluster_id: str | None = Field(default=None, max_length=36)
    enabled: bool = False
    token: str = Field(default="", max_length=16384)
    webhook_token: str = Field(default="", max_length=512)
    namespace: str = Field(default="openshift-gitops", pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")
    projects: list[str] = Field(default_factory=list, max_length=30)
    target_cluster_ids: list[str] = Field(default_factory=list, max_length=30)
    destination_names: dict[str, str] = Field(default_factory=dict, max_length=30)
    url: str = Field(default="", max_length=2048)
    monitoring_url: str = Field(default="", max_length=2048)
    api_prefix: str = Field(default="/api/v3", pattern=r"^(/api/v3)?$")
    repositories: list[str] = Field(default_factory=list, max_length=30)
    custom_ca_pem: str | None = Field(default=None, max_length=32768)
    allowed_alerts: list[str] = Field(default_factory=lambda: list(DEFAULT_ALERTS), min_length=1, max_length=40)


class IncidentService:
    def __init__(self, settings, store, model_context, provider):
        self.settings, self.store = settings, store
        self.model_context, self.provider = model_context, provider
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

    def token_for(self, row, db):
        token = self.credentials().get(row.credential_key)
        if not token and row.kind == 'argocd':
            host_connection = db.scalar(select(IncidentConnection).where(
                IncidentConnection.kind == 'cluster', IncidentConnection.cluster_id == row.cluster_id,
                IncidentConnection.enabled.is_(True)))
            if host_connection:
                token = self.credentials().get(host_connection.credential_key)
        return token

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

    def cluster_reader(self, cluster, token):
        origin = self.settings.delegated_system_api_url if cluster.is_system else cluster.api_url
        ca = cluster.custom_ca_pem
        if cluster.is_system:
            ca = self.settings.service_account_ca_path.read_text(encoding="utf-8")
        return self.reader_factory(origin, token, ca, True if cluster.is_system else cluster.tls_verify)

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
            if value.id and not row:
                raise HTTPException(404, "Connection not found.")
            if row and row.kind != value.kind:
                raise HTTPException(422, "Connection kind cannot change.")
            if value.kind in ("cluster", "argocd"):
                cluster = db.get(Cluster, value.cluster_id)
                if not cluster or not cluster.is_enabled or cluster.visibility != "shared":
                    raise HTTPException(422, "Select an enabled shared hosting cluster.")
            if value.kind == "cluster":
                if value.monitoring_url:
                    value.monitoring_url = https_origin(value.monitoring_url)
                if set(value.allowed_alerts) - set(DEFAULT_ALERTS):
                    raise HTTPException(422, "PoC alert policy must be a subset of the reviewed platform allowlist.")
                duplicate = db.scalar(select(IncidentConnection).where(IncidentConnection.kind == "cluster",
                    IncidentConnection.cluster_id == value.cluster_id))
                if duplicate and (not row or duplicate.id != row.id):
                    raise HTTPException(409, "Edit the existing incident connection for this cluster.")
            if value.kind == "argocd":
                if not value.projects or not value.target_cluster_ids:
                    raise HTTPException(422, "Specify platform Argo CD projects and target clusters.")
                for target in value.target_cluster_ids:
                    target_row = db.get(Cluster, target)
                    if not target_row or target_row.visibility != "shared" or not target_row.is_enabled:
                        raise HTTPException(422, "Argo CD targets must be enabled shared clusters.")
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
                probe_row = IncidentConnection(credential_key=credential_key, kind=value.kind, cluster_id=value.cluster_id)
                existing_token = self.token_for(probe_row, db)
            if value.enabled and not (value.token or existing_token):
                raise HTTPException(422, "A read-only credential is required before enabling the connection.")
            if value.kind == "cluster" and value.enabled and not (value.webhook_token or self.credentials().get(webhook_key)):
                raise HTTPException(422, "Set a webhook bearer token of at least 32 characters.")
            if value.webhook_token and len(value.webhook_token) < 32:
                raise HTTPException(422, "Webhook bearer tokens must contain at least 32 characters.")
            if value.token:
                self.credentials().set(value.token, credential_key)
            if value.webhook_token and webhook_key:
                self.credentials().set(value.webhook_token, webhook_key)
            if not row:
                row = IncidentConnection(id=connection_id, credential_key=credential_key, webhook_key=webhook_key)
                db.add(row)
            row.kind, row.name, row.cluster_id, row.enabled = value.kind, value.name, value.cluster_id, value.enabled
            row.config_json, row.updated_at = json.dumps(config), utcnow()
            self.audit(db, user.username, "connection_saved", connection_id=row.id, kind=row.kind,
                enabled=row.enabled, tls_verify=(cluster.tls_verify if value.kind != "github" else True))
            db.commit()
            return {"id": row.id}

    def test_connection(self, engine, connection_id, user):
        with Session(engine) as db:
            row = db.get(IncidentConnection, connection_id)
            if not row:
                raise HTTPException(404, "Connection not found.")
            reader = None
            try:
                token = self.token_for(row, db)
                cfg = json.loads(row.config_json)
                if row.kind == "github":
                    reader = self.reader_factory(cfg["url"], token, cfg.get("custom_ca_pem"))
                    for repo in cfg["repositories"]:
                        info = reader.get(f"{cfg['api_prefix']}/repos/{repo}")
                        if info.get("full_name", "").lower() != repo.lower():
                            raise ValueError("Repository identity mismatch.")
                    checks = ["Configured GitHub API and repository metadata reads succeeded. PAT scope is managed in GitHub."]
                else:
                    cluster = db.get(Cluster, row.cluster_id)
                    reader = self.cluster_reader(cluster, token)
                    if row.kind == "argocd":
                        reader.get(f"/apis/argoproj.io/v1alpha1/namespaces/{cfg['namespace']}/applications", {"limit": 1})
                        checks = ["Argo CD Application reads succeeded."]
                    else:
                        checks = []
                        for key in ("operators", "version", "nodes", "machine-pools"):
                            try:
                                reader.collect(key)
                                checks.append(f"{key}: available")
                            except Exception:
                                checks.append(f"{key}: unavailable; check permissions and API availability")
                        if cfg.get("monitoring_url"):
                            reader.monitor = self.reader_factory(cfg['monitoring_url'], token,
                                cfg.get('custom_ca_pem'), cluster.tls_verify)
                            try:
                                reader.collect('platform-metrics')
                                checks.append('platform-metrics: available')
                            except Exception:
                                checks.append('platform-metrics: unavailable; check monitoring endpoint, CA and access')
                        else:
                            checks.append('platform-metrics: not configured')
                self.audit(db, user.username, "connection_test", connection_id=row.id)
                db.commit()
                return {"checks": checks}
            except Exception:
                self.audit(db, user.username, "connection_test", "failed", connection_id=row.id)
                db.commit()
                raise HTTPException(502, "Connection test failed. Check endpoint, CA, token and read permissions.")
            finally:
                if reader:
                    reader.close()

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
                    coordinator["result"] = str(result)[:240]
                if changed:
                    activity["events"].append({
                        "at": utcnow().isoformat(), "label": "Coordinator",
                        "state": state or "running", "summary": str(work)[:240],
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
                    "state": "queued", "summary": str(work)[:240],
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
                    task["result"] = str(result)[:240]
                activity["events"].append({
                    "at": utcnow().isoformat(), "label": task.get("label", "Specialist"),
                    "state": state, "summary": str(result or task.get("work") or "")[:240],
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
            if len(json.dumps(item)) > 32768:
                item["data"] = {"limitation": "Evidence exceeded the per-collector projection limit."}
                limitations.append(f"{source}: evidence projection exceeded the limit.")
            if len(json.dumps(evidence)) + len(json.dumps(item)) > self.settings.incident_max_evidence_bytes:
                limitations.append("Total evidence budget reached; remaining collection is incomplete.")
                raise ValueError("Evidence budget reached")
            evidence.append(item)
            if coordinate:
                if len(json.dumps(coordination_evidence)) + len(json.dumps(item)) <= self.settings.incident_max_coordinator_bytes:
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
                    "operator_request": "Identify incident-relevant anomalies in this platform container log.",
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
                limitations.extend(json.loads(incident.limitations_json))
                connectors = list(db.scalars(select(IncidentConnection).where(IncidentConnection.enabled.is_(True), IncidentConnection.kind != "cluster").limit(10)))
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
                    max_output_tokens=output_limit, max_input_tokens=input_limit, max_retries=0)
            def deadline_profile():
                remaining = run_timeout - (time.monotonic()-started)
                if remaining <= 1:
                    raise TimeoutError("Incident run deadline reached.")
                return replace(profile, timeout_seconds=min(profile.timeout_seconds, remaining))
            reader = self.cluster_reader(cluster, token)
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
            except Exception:
                limitations.append("Cluster operator snapshot unavailable; other evidence collection will continue.")
            # Preserve recent changes before model-guided investigation; no arbitrary repository traversal.
            changes = []
            onset = min(datetime.fromisoformat(a["startsAt"]) for a in alert_snapshot.values())
            if connectors:
                coordinator_activity("Correlating recent platform deployments and repository metadata", phase="Change correlation")
            for connector in connectors:
                if time.monotonic()-started > self.settings.incident_connector_timeout_seconds:
                    limitations.append("Connector collection time budget reached.")
                    break
                cfg = json.loads(connector.config_json)
                if connector.kind != "argocd" or cluster.id not in cfg["target_cluster_ids"]:
                    continue
                other = None
                try:
                    with Session(engine) as db:
                        host = db.get(Cluster, connector.cluster_id)
                        credential = self.token_for(connector, db)
                    if not host or not host.is_enabled or host.visibility != "shared":
                        raise ValueError("Argo CD hosting cluster unavailable")
                    secrets.append(credential)
                    other = self.cluster_reader(host, credential)
                    servers = {cluster.api_url.rstrip('/')}
                    if host.id == cluster.id:
                        servers.add("https://kubernetes.default.svc")
                    names = [cfg["destination_names"][cluster.id]] if cluster.id in cfg["destination_names"] else []
                    result = other.argocd(cfg["namespace"], cfg["projects"], servers, names, onset - timedelta(hours=2))
                    source_item = record(f"Argo CD: {connector.name} (host {host.id})", result, coordinate=False)
                    summarize_specialist("Argo CD", source_item,
                        "Correlate only this Argo CD deployment evidence with the incident onset. Return a compact cited report of relevant platform deployment changes, contradictions, and gaps. Do not request more collection.")
                    changes.extend(result["changes"])
                    if not host.tls_verify and not host.is_system:
                        limitations.append(f"Argo CD hosting cluster {host.name}: TLS verification disabled.")
                except Exception:
                    limitations.append(f"Argo CD connector {connector.name}: read unavailable.")
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
                    seen = set()
                    for change in changes[:10]:
                        repo_url = change.get("repository") or ""
                        # Support HTTPS and the common git@host:owner/repo.git form.
                        if repo_url.startswith("git@"):
                            repo_url = "ssh://" + repo_url.replace(":", "/", 1)
                        parsed = urlsplit(repo_url)
                        repo = parsed.path.strip('/').removesuffix('.git')
                        identity = (repo, change.get("revision"))
                        if parsed.hostname != urlsplit(cfg["url"]).hostname or repo not in cfg["repositories"] or identity in seen:
                            continue
                        if time.monotonic()-started > self.settings.incident_connector_timeout_seconds:
                            break
                        seen.add(identity)
                        source_item = record(f"GitHub: {connector.name}",
                            other.github(repo, change["revision"], cfg["api_prefix"]), coordinate=False)
                        summarize_specialist("GitHub", source_item,
                            "Assess only this revision and pull-request metadata for incident relevance. Return a compact cited report of timing, likely relationship, contradictions, and gaps. Do not infer diff contents or request more collection.")
                except Exception:
                    limitations.append(f"GitHub connector {connector.name}: revision/PR metadata unavailable.")
                finally:
                    if other:
                        other.close()
            if not profile or not api_key:
                coordinator_activity("Collecting deterministic platform snapshots", phase="Evidence collection")
                limitations.append("No usable model profile; deterministic platform snapshots only.")
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
                max_rounds = 6 if synthetic else self.settings.incident_max_rounds
                for step in range(max_rounds):
                    if time.monotonic()-started > run_timeout:
                        limitations.append("Investigation time budget reached.")
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
                            "This is a controlled incident simulation. Conduct a normal, thorough platform investigation across relevant bounded collectors and specialist reports, but do not assume the simulated alert labels prove a real failure. Separate observed cluster impact from the scenario premise and finish with cited findings and operator next steps."
                            if simulation else
                            "Investigate this critical OpenShift platform incident; identify impact, likely causes, contradictions, recent changes and operator next steps."
                        ),
                        "evidence": coordination_evidence, "limitations": limitations,
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
                        limitations.append(f"Model did not finalize within the {max_rounds}-round limit.")
                        break
                    log_items = []
                    for key in decision.collect:
                        if time.monotonic()-started > run_timeout:
                            limitations.append("Read time budget reached.")
                            break
                        if key not in available:
                            limitations.append("Model requested an unavailable collector; request rejected.")
                            continue
                        collector_label = available.pop(key)
                        consumed.add(key)
                        try:
                            coordinator_activity(f"Collecting {collector_label}", phase="Evidence collection")
                            source_item = record(key, reader.collect(key), coordinate=not key.startswith("logs:"))
                            if key.startswith("logs:"):
                                log_items.append(source_item)
                            available = {k:v for k,v in reader.catalog().items() if k not in consumed}
                        except Exception:
                            limitations.append(f"{key}: read unavailable or response too large.")
                    slots = max(0, self.settings.incident_max_specialist_reports-specialist_reports)
                    selected_logs = log_items[:slots]
                    if selected_logs:
                        specialist_work = []
                        for source_item in selected_logs:
                            data = source_item.get("data") or {}
                            target = "/".join(filter(None, [data.get("namespace"), data.get("pod"), data.get("container")]))
                            work = f"Analyze bounded platform logs{f' for {target}' if target else ''}"
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
                                if len(json.dumps(coordination_evidence)) + len(json.dumps(source_item)) <= self.settings.incident_max_coordinator_bytes:
                                    coordination_evidence.append(source_item)
                    for source_item in log_items[slots:]:
                        limitations.append(f"Pod log specialist report limit reached; {source_item['id']} remains in retained evidence.")
        except Exception:
            status = "partial" if evidence else "failed"
            limitations.append("Investigation interrupted by an unavailable credential, API, or model. Inspect connection tests and retained evidence.")
        finally:
            if reader:
                reader.close()
        briefing["limitations"] = list(dict.fromkeys(briefing.get("limitations", []) + limitations))
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
            "dashboard_stats": {
                "active": len(active),
                "total": len(views),
                "firing": sum(row.alert_state == "firing" for row in rows),
                "specialists": sum(item["counts"]["running"] for item in active),
            },
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
            run_views.append({
                "row": run,
                "number": len(runs) - index,
                "briefing": briefing,
                "evidence": evidence,
                "supporting_ids": [item for item in supporting_ids if item in valid_ids],
                "hypotheses": [re.sub(r"^\s*(?:\d+\s*[.)]\s*|[-*•]\s*)", "", str(item)) for item in briefing.get("hypotheses", [])],
                "next_steps": [re.sub(r"^\s*(?:\d+\s*[.)]\s*|[-*•]\s*)", "", str(item)) for item in briefing.get("next_steps", [])],
                "limitations": [re.sub(r"^\s*[-*•]\s*", "", str(item)) for item in briefing.get("limitations", [])],
            })
        return page(request, user, "incident_detail.html", {"incident": incident, "cluster": cluster,
            "alerts": alerts, "alert_groups": list(grouped_alerts.values()),
            "incident_limitations": json.loads(incident.limitations_json), "runs": run_views})

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
            cid = str(uuid4())
            evidence = [{"id": f"incident-{run.id}-{e['id']}", "tool": "incident_snapshot",
                "summary": e['source'], "source": f"Incident {incident_id} / run {run.id}",
                "collected_at": e['observed_at'], "cluster_id": incident.cluster_id,
                "data": e['data']} for e in json.loads(run.evidence_json)]
            briefing = json.loads(run.briefing_json)
            content = f"Incident handoff: {incident.title}\n\n{briefing.get('summary', '')}\n\nThese are historical observations and preliminary hypotheses. Reconnect with your own cluster credentials to continue. Full incident: /incidents/{incident_id}"
            db.add(AdHocConversation(id=cid, created_by=user.username, title=f"Incident: {incident.title}"[:253],
                status="active", cluster_ids_json=json.dumps([incident.cluster_id]), execution_mode="read_only",
                # A nonempty expired session marker invokes the existing reconnect flow. It grants no capability.
                delegated_session_id=f"incident-{uuid4()}", evidence_json=json.dumps(evidence),
                context_summary=content[:4000]))
            db.add(AdHocMessage(id=str(uuid4()), conversation_id=cid, role="assistant", content=content,
                actor="system:incident-handoff", answer_mode="insufficient_evidence"))
            service.audit(db, user.username, "continue_in_ask", incident_id=incident_id, conversation_id=cid)
            db.commit()
        return {"url": f"/ask/{cid}"}

    @app.get("/settings/connectors")
    async def connectors(request: Request, user=Depends(current_user)):
        service.manage(user)
        with Session(app.state.engine) as db:
            rows = list(db.scalars(select(IncidentConnection).order_by(IncidentConnection.kind, IncidentConnection.name)))
            clusters = list(db.scalars(select(Cluster).where(Cluster.visibility == "shared", Cluster.is_enabled.is_(True))))
        selected = next((r for r in rows if r.id == request.query_params.get("edit")), None)
        return page(request, user, "connectors.html", {"connections": rows, "clusters": clusters,
            "selected": selected, "config": json.loads(selected.config_json) if selected else {}, "default_alerts": DEFAULT_ALERTS})

    @app.get("/settings/webhooks")
    async def webhook_settings(request: Request, user=Depends(current_user)):
        service.manage(user)
        receivers = []
        with Session(app.state.engine) as db:
            for row in db.scalars(select(IncidentConnection).where(IncidentConnection.kind == 'cluster').order_by(IncidentConnection.name)):
                cluster = db.get(Cluster, row.cluster_id)
                latest = db.scalar(select(func.max(FleetIncident.updated_at)).where(FleetIncident.source_id == row.id))
                count = db.scalar(select(func.count()).select_from(FleetIncident).where(FleetIncident.source_id == row.id))
                # Deployment uses an edge-terminated Route; display HTTPS even behind its HTTP upstream.
                origin = str(request.base_url).rstrip('/')
                if service.settings.auth_mode == 'proxy':
                    origin = 'https://' + request.url.netloc
                receivers.append({'id':row.id,'name':row.name,'cluster_name':cluster.name if cluster else row.cluster_id,
                    'cluster_id':row.cluster_id,'enabled':row.enabled,'last_delivery':latest,'incident_count':count,
                    'url':f'{origin}/api/v1/incident-webhooks/{row.id}'})
        return page(request, user, 'webhook_settings.html', {'receivers':receivers,
            'incident_policy': {
                'context_window_tokens': service.settings.incident_context_window_tokens,
                'run_timeout_seconds': service.settings.incident_run_timeout_seconds,
                'max_rounds': service.settings.incident_max_rounds,
                'max_specialists': service.settings.incident_max_specialist_reports,
                'worker_concurrency': service.settings.incident_worker_concurrency,
                'evidence_bytes': service.settings.incident_max_evidence_bytes,
                'coordinator_bytes': service.settings.incident_max_coordinator_bytes,
            }})

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
                return await asyncio.to_thread(service.save, app.state.engine, value, user)
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
        return await asyncio.to_thread(service.test_connection, app.state.engine, connection_id, user)
