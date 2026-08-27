from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    actor: Mapped[str] = mapped_column(String(253), nullable=False)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    details_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    created_by: Mapped[str] = mapped_column(String(253), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    alert_fingerprint: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    alert_name: Mapped[str] = mapped_column(String(253), nullable=False)
    alert_snapshot_json: Mapped[str] = mapped_column(Text, nullable=False)
    analysis_json: Mapped[str] = mapped_column(Text, nullable=False)


class ModelProfile(Base):
    __tablename__ = "model_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider_label: Mapped[str] = mapped_column(String(100), nullable=False)
    base_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    chat_model: Mapped[str] = mapped_column(String(253), nullable=False)
    api_type: Mapped[str] = mapped_column(String(32), nullable=False, default="responses")
    credential_key: Mapped[str] = mapped_column(String(253), nullable=False, default="api_key")
    tls_mode: Mapped[str] = mapped_column(String(32), nullable=False, default="system")
    custom_ca_pem: Mapped[str | None] = mapped_column(Text, nullable=True)
    max_input_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=128_000)
    tool_calling_hint: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    vision_hint: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    embedding_model: Mapped[str | None] = mapped_column(String(253), nullable=True)
    timeout_seconds: Mapped[float] = mapped_column(Float, nullable=False)
    max_output_tokens: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="not_tested")
    capabilities_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_probe_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_by: Mapped[str] = mapped_column(String(253), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class Cluster(Base):
    __tablename__ = "clusters"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(253), nullable=False, unique=True, index=True)
    api_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    credential_key: Mapped[str | None] = mapped_column(String(253), nullable=True, unique=True)
    tags_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    tls_verify: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    is_system: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="not_tested")
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_tested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str] = mapped_column(String(253), nullable=False)
    updated_by: Mapped[str] = mapped_column(String(253), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class KnowledgeDocument(Base):
    __tablename__ = "knowledge_documents"
    __table_args__ = (UniqueConstraint("logical_id", "version", name="uq_knowledge_logical_version"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    logical_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True
    )
    created_by: Mapped[str] = mapped_column(String(253), nullable=False)
    title: Mapped[str] = mapped_column(String(253), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(512), nullable=False)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    cluster_id: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    target_cluster_ids_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    target_tags_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    namespace: Mapped[str | None] = mapped_column(String(253), nullable=True, index=True)
    resource_kind: Mapped[str | None] = mapped_column(String(128), nullable=True)
    resource_name: Mapped[str | None] = mapped_column(String(253), nullable=True)
    owner: Mapped[str] = mapped_column(String(253), nullable=False)
    verification_state: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    sensitivity: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    review_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    is_current: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)


class KnowledgeChunk(Base):
    __tablename__ = "knowledge_chunks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    document_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("knowledge_documents.id"), nullable=False, index=True
    )
    position: Mapped[int] = mapped_column(Integer, nullable=False)
    heading: Mapped[str | None] = mapped_column(String(253), nullable=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    token_estimate: Mapped[int] = mapped_column(Integer, nullable=False)


class RemediationAction(Base):
    __tablename__ = "remediation_actions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id"), nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_by: Mapped[str] = mapped_column(String(253), nullable=False)
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    risk: Mapped[str] = mapped_column(String(16), nullable=False)
    target_namespace: Mapped[str] = mapped_column(String(253), nullable=False)
    target_kind: Mapped[str] = mapped_column(String(64), nullable=False)
    target_name: Mapped[str] = mapped_column(String(253), nullable=False)
    proposal_json: Mapped[str] = mapped_column(Text, nullable=False)
    preview_json: Mapped[str] = mapped_column(Text, nullable=False)
    approved_by: Mapped[str | None] = mapped_column(String(253), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    result_json: Mapped[str | None] = mapped_column(Text, nullable=True)


class DiagnosticCheck(Base):
    __tablename__ = "diagnostic_checks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id"), nullable=False, index=True
    )
    position: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    requested_by: Mapped[str | None] = mapped_column(String(253), nullable=True)
    tool_name: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(253), nullable=False)
    purpose: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    input_json: Mapped[str] = mapped_column(Text, nullable=False)
    result_json: Mapped[str | None] = mapped_column(Text, nullable=True)


class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("investigations.id"), nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    actor: Mapped[str | None] = mapped_column(String(253), nullable=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    answer_mode: Mapped[str | None] = mapped_column(String(32), nullable=True)
    citations_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    tool_intent_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    provider_status: Mapped[str | None] = mapped_column(String(32), nullable=True)


class AdHocConversation(Base):
    __tablename__ = "adhoc_conversations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    created_by: Mapped[str] = mapped_column(String(253), nullable=False)
    title: Mapped[str] = mapped_column(String(253), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    cluster_ids_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    evidence_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    context_summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    summarized_message_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class AdHocMessage(Base):
    __tablename__ = "adhoc_messages"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    conversation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("adhoc_conversations.id"), nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True
    )
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    actor: Mapped[str | None] = mapped_column(String(253), nullable=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    answer_mode: Mapped[str | None] = mapped_column(String(32), nullable=True)
    citations_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    tool_activity_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    provider_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    raw_responses_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")


class AdHocRun(Base):
    __tablename__ = "adhoc_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    conversation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("adhoc_conversations.id"), nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False,
        index=True,
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    message_text: Mapped[str] = mapped_column(Text, nullable=False)
    include_raw_response: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    followup_action_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued", index=True)
    phase: Mapped[str] = mapped_column(String(64), nullable=False, default="queued")
    progress_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    assistant_message_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
