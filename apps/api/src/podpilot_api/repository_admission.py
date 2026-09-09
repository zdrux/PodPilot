"""Admit observed CI/CD repositories to existing, matching GitHub connections."""
import json
from datetime import datetime, timezone
from urllib.parse import urlsplit

from sqlalchemy import select

from podpilot_api.incident_models import IncidentConnection
from podpilot_api.models import AuditEvent
from podpilot_openshift.technology_discovery import repository_url


def admit_repositories(db, inventory: dict, *, actor: str, cluster_id: str, can_manage: bool) -> None:
    connections = list(db.scalars(select(IncidentConnection).where(
        IncidentConnection.kind == "github", IncidentConnection.enabled.is_(True),
    )))
    for repository in inventory.get("repositories", []):
        canonical = repository_url(repository.get("url"))
        if not canonical:
            repository["admission"] = "invalid_reference"
            continue
        if not can_manage:
            repository["admission"] = "configuration_admin_required"
            continue
        parsed = urlsplit(canonical)
        name = parsed.path.lstrip("/")
        if len(name.split("/")) != 2:
            repository["admission"] = "provider_not_supported"
            continue
        candidates = []
        for connection in connections:
            config = json.loads(connection.config_json)
            host = urlsplit(config.get("url", "")).hostname
            host = "github.com" if host == "api.github.com" else host
            if host == parsed.hostname:
                candidates.append((connection, config))
        if len(candidates) != 1:
            repository["admission"] = "connector_required" if not candidates else "ambiguous_connectors"
            continue
        connection, config = candidates[0]
        existing = config.get("repositories", [])
        repository["connector_id"] = connection.id
        if name.casefold() in {item.casefold() for item in existing}:
            repository["admission"] = "already_admitted"
            continue
        if len(existing) >= 30:
            repository["admission"] = "connector_capacity_reached"
            continue
        config["repositories"] = [*existing, name]
        connection.config_json = json.dumps(config, sort_keys=True)
        connection.updated_at = datetime.now(timezone.utc)
        repository["admission"] = "admitted"
        db.add(AuditEvent(
            actor=actor, action="repository.auto_admit", outcome="admitted",
            details_json=json.dumps({"cluster_id": cluster_id, "connector_id": connection.id,
                                     "repository": name, "references": repository.get("references", [])}, sort_keys=True),
        ))
