"""Durable fleet incidents, immutable run snapshots, and Secret references."""
from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from podpilot_api.models import Base


def now():
    return datetime.now(timezone.utc)


class IncidentConnection(Base):
    __tablename__ = "incident_connections"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    kind: Mapped[str] = mapped_column(String(16))
    name: Mapped[str] = mapped_column(String(253))
    cluster_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("clusters.id"))
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    config_json: Mapped[str] = mapped_column(Text, default="{}")
    credential_key: Mapped[str] = mapped_column(String(253))
    webhook_key: Mapped[str | None] = mapped_column(String(253))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class FleetIncident(Base):
    __tablename__ = "fleet_incidents"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    cluster_id: Mapped[str] = mapped_column(String(36), ForeignKey("clusters.id"), index=True)
    source_id: Mapped[str] = mapped_column(String(36), ForeignKey("incident_connections.id"))
    group_key: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(500))
    alert_state: Mapped[str] = mapped_column(String(16), default="firing")
    alerts_json: Mapped[str] = mapped_column(Text, default="{}")
    limitations_json: Mapped[str] = mapped_column(Text, default="[]")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)


class IncidentRun(Base):
    __tablename__ = "incident_runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(36), ForeignKey("fleet_incidents.id"), index=True)
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True)
    actor: Mapped[str] = mapped_column(String(253))
    alert_snapshot_json: Mapped[str] = mapped_column(Text)
    evidence_json: Mapped[str] = mapped_column(Text, default="[]")
    briefing_json: Mapped[str] = mapped_column(Text, default="{}")
    activity_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
