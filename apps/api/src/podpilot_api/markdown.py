from __future__ import annotations

import json
import re

from markdown_it import MarkdownIt
from markdown_it.common.utils import escapeHtml
from markupsafe import Markup


_renderer = MarkdownIt(
    "commonmark",
    {"breaks": True, "html": False, "linkify": False, "typographer": False},
).enable("table")

_HTML_BREAK = re.compile(r"<br[ \t]*/?>", re.IGNORECASE)


def _render_text_with_safe_breaks(_renderer, tokens, index, _options, _env) -> str:
    """Allow only HTML-style line breaks while escaping every other text fragment."""

    parts = _HTML_BREAK.split(tokens[index].content)
    rendered = [escapeHtml(part) for part in parts]
    return "<br>\n".join(rendered)


_renderer.add_render_rule("text", _render_text_with_safe_breaks)

_FENCED_CODE = re.compile(
    r"(?ms)^```(?P<language>json)?[ \t]*\n(?P<body>.*?)\n```[ \t]*$"
)


def _pretty_json_markdown(value: str) -> str:
    """Pretty-print JSON in fenced blocks or standalone JSON paragraphs."""

    def pretty(raw: str) -> str | None:
        try:
            parsed = json.loads(raw)
        except (TypeError, ValueError):
            return None
        if not isinstance(parsed, (dict, list)):
            return None
        return json.dumps(parsed, indent=2, sort_keys=True, ensure_ascii=False)

    def replace_fence(match: re.Match[str]) -> str:
        formatted = pretty(match.group("body"))
        if formatted is None:
            return match.group(0)
        return f"```json\n{formatted}\n```"

    rendered = _FENCED_CODE.sub(replace_fence, value)
    paragraphs = re.split(r"(\n\s*\n)", rendered)
    for index in range(0, len(paragraphs), 2):
        paragraph = paragraphs[index]
        stripped = paragraph.strip()
        if stripped.startswith("```") or not (
            (stripped.startswith("{") and stripped.endswith("}"))
            or (stripped.startswith("[") and stripped.endswith("]"))
        ):
            continue
        formatted = pretty(stripped)
        if formatted is not None:
            paragraphs[index] = f"```json\n{formatted}\n```"
    return "".join(paragraphs)


def render_safe_markdown(value: object) -> Markup:
    """Render CommonMark while keeping raw HTML escaped."""

    return Markup(_renderer.render(_pretty_json_markdown(str(value or ""))))


def split_markdown_tables(
    value: object,
    *,
    max_tables: int = 8,
    max_columns: int = 24,
    max_rows_per_table: int = 1_000,
    max_cell_chars: int = 4_096,
) -> list[dict[str, object]]:
    """Split Markdown into ordered prose and bounded native-table presentation blocks."""

    source = _pretty_json_markdown(str(value or ""))
    if not source:
        return []
    tokens = _renderer.parse(source)
    lines = source.splitlines(keepends=True)
    blocks: list[dict[str, object]] = []
    cursor = 0
    table_count = 0
    index = 0

    def add_markdown(start: int, end: int) -> None:
        content = "".join(lines[start:end]).strip()
        if content:
            blocks.append({"type": "markdown", "content": content})

    while index < len(tokens):
        token = tokens[index]
        if (
            token.type != "table_open"
            or token.map is None
            or table_count >= max_tables
        ):
            index += 1
            continue
        start_line, end_line = token.map
        add_markdown(cursor, start_line)
        headers: list[str] = []
        rows: list[list[str]] = []
        current_row: list[str] | None = None
        current_cell: str | None = None
        in_header = False
        body_row_count = 0
        index += 1
        while index < len(tokens) and tokens[index].type != "table_close":
            nested = tokens[index]
            if nested.type == "thead_open":
                in_header = True
            elif nested.type == "thead_close":
                in_header = False
            elif nested.type == "tr_open":
                current_row = []
            elif nested.type in {"th_open", "td_open"}:
                current_cell = ""
            elif nested.type == "inline" and current_cell is not None:
                current_cell = nested.content[:max_cell_chars]
            elif nested.type in {"th_close", "td_close"} and current_row is not None:
                current_row.append((current_cell or "")[:max_cell_chars])
                current_cell = None
            elif nested.type == "tr_close" and current_row is not None:
                bounded_row = current_row[:max_columns]
                if in_header and not headers:
                    headers = bounded_row
                else:
                    body_row_count += 1
                    if len(rows) < max_rows_per_table:
                        rows.append(bounded_row)
                current_row = None
            index += 1
        column_count = min(max_columns, max(
            len(headers),
            max((len(row) for row in rows), default=0),
        ))
        if column_count:
            headers = [
                (headers[column] if column < len(headers) and headers[column].strip()
                 else f"Column {column + 1}")
                for column in range(column_count)
            ]
            normalized_rows = [
                [
                    row[column] if column < len(row) else ""
                    for column in range(column_count)
                ]
                for row in rows
            ]
            blocks.append({
                "type": "answer_table",
                "version": 1,
                "source": "answer_markdown",
                "trust": "answer_content",
                "columns": [
                    {"key": f"column_{column + 1}", "label": label, "cell_type": "markdown"}
                    for column, label in enumerate(headers)
                ],
                "rows": [{"cells": row} for row in normalized_rows],
                "row_count": len(normalized_rows),
                "omitted_count": max(0, body_row_count - len(normalized_rows)),
            })
            table_count += 1
            cursor = end_line
        else:
            # Keep malformed or empty tables in the prose fallback instead of dropping content.
            cursor = start_line
        index += 1

    add_markdown(cursor, len(lines))
    return blocks or [{"type": "markdown", "content": source}]
