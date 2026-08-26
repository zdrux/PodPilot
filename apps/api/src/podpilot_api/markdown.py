from __future__ import annotations

import json
import re

from markdown_it import MarkdownIt
from markupsafe import Markup


_renderer = MarkdownIt(
    "commonmark",
    {"breaks": True, "html": False, "linkify": False, "typographer": False},
).enable("table")

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
