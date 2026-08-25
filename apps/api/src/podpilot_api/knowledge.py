from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from podpilot_api.models import KnowledgeChunk, KnowledgeDocument

_HEADING = re.compile(r"^#{1,6}\s+(.+?)\s*$")
_TERMS = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{1,63}")


@dataclass(frozen=True)
class KnowledgeSearchResult:
    chunk_id: str
    document_id: str
    logical_id: str
    version: int
    title: str
    heading: str | None
    content: str
    source: str
    source_type: str
    cluster_id: str
    namespace: str | None
    owner: str
    sensitivity: str
    rank: float


def ensure_knowledge_fts(engine: Engine) -> None:
    """Create the virtual index for test databases and verify FTS5 is available."""
    with engine.begin() as connection:
        connection.execute(text("""
            CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_chunks_fts USING fts5(
                chunk_id UNINDEXED,
                title,
                heading,
                content,
                tokenize = 'porter unicode61'
            )
        """))


def chunk_markdown(content: str, *, max_chars: int = 2400) -> list[tuple[str | None, str]]:
    blocks = [block.strip() for block in re.split(r"\n\s*\n", content) if block.strip()]
    chunks: list[tuple[str | None, str]] = []
    heading: str | None = None
    pending: list[str] = []
    pending_chars = 0

    def flush() -> None:
        nonlocal pending, pending_chars
        if pending:
            chunks.append((heading, "\n\n".join(pending)))
            pending = []
            pending_chars = 0

    for block in blocks:
        match = _HEADING.match(block)
        if match:
            flush()
            heading = match.group(1)[:253]
            continue
        parts = [block[index:index + max_chars] for index in range(0, len(block), max_chars)]
        for part in parts:
            extra = len(part) + (2 if pending else 0)
            if pending and pending_chars + extra > max_chars:
                flush()
            pending.append(part)
            pending_chars += extra
    flush()
    return chunks or [(heading, content[:max_chars])]


def index_document(db_session: Session, document: KnowledgeDocument) -> None:
    for position, (heading, content) in enumerate(chunk_markdown(document.content)):
        chunk = KnowledgeChunk(
            id=str(uuid4()),
            document_id=document.id,
            position=position,
            heading=heading,
            content=content,
            token_estimate=max(1, (len(content) + 3) // 4),
        )
        db_session.add(chunk)
        db_session.flush()
        db_session.execute(
            text("""
                INSERT INTO knowledge_chunks_fts(chunk_id, title, heading, content)
                VALUES (:chunk_id, :title, :heading, :content)
            """),
            {
                "chunk_id": chunk.id,
                "title": document.title,
                "heading": heading or "",
                "content": content,
            },
        )


def remove_document_from_index(db_session: Session, document_id: str) -> None:
    db_session.execute(text("""
        DELETE FROM knowledge_chunks_fts
        WHERE chunk_id IN (
            SELECT id FROM knowledge_chunks WHERE document_id = :document_id
        )
    """), {"document_id": document_id})


def _fts_query(query: str) -> str | None:
    terms: list[str] = []
    for match in _TERMS.finditer(query):
        term = match.group(0).lower()
        if term not in terms:
            terms.append(term)
        if len(terms) == 16:
            break
    if not terms:
        return None
    return " OR ".join(f'"{term.replace(chr(34), chr(34) * 2)}"' for term in terms)


def search_knowledge(
    db_session: Session,
    *,
    query: str,
    cluster_id: str,
    namespace: str | None = None,
    include_restricted: bool = False,
    limit: int = 8,
    now: datetime | None = None,
) -> list[KnowledgeSearchResult]:
    match_query = _fts_query(query)
    if not match_query:
        return []
    current = now or datetime.now(timezone.utc)
    sensitivity_clause = "" if include_restricted else "AND d.sensitivity != 'restricted'"
    namespace_clause = (
        "AND (d.namespace IS NULL OR d.namespace = :namespace)"
        if namespace else "AND d.namespace IS NULL"
    )
    rows = db_session.execute(text(f"""
        SELECT c.id AS chunk_id, d.id AS document_id, d.logical_id, d.version,
               d.title, c.heading, c.content, d.source, d.source_type,
               d.cluster_id, d.namespace, d.owner, d.sensitivity,
               bm25(knowledge_chunks_fts, 0.0, 5.0, 2.0, 1.0) AS rank
        FROM knowledge_chunks_fts
        JOIN knowledge_chunks c ON c.id = knowledge_chunks_fts.chunk_id
        JOIN knowledge_documents d ON d.id = c.document_id
        WHERE knowledge_chunks_fts MATCH :query
          AND d.is_current = 1
          AND d.is_enabled = 1
          AND d.verification_state = 'reviewed'
          AND (d.expires_at IS NULL OR d.expires_at > :now)
          AND (d.cluster_id = :cluster_id OR d.cluster_id = '*')
          {namespace_clause}
          {sensitivity_clause}
        ORDER BY rank ASC, d.title ASC, c.position ASC
        LIMIT :limit
    """), {
        "query": match_query,
        "now": current,
        "cluster_id": cluster_id,
        "namespace": namespace,
        "limit": max(1, min(limit, 20)),
    }).mappings()
    return [KnowledgeSearchResult(**dict(row)) for row in rows]
