from __future__ import annotations

from markdown_it import MarkdownIt
from markupsafe import Markup


_renderer = MarkdownIt(
    "commonmark",
    {"breaks": True, "html": False, "linkify": False, "typographer": False},
).enable("table")


def render_safe_markdown(value: object) -> Markup:
    """Render CommonMark while keeping raw HTML escaped."""

    return Markup(_renderer.render(str(value or "")))
