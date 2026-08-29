from podpilot_api.markdown import render_safe_markdown, split_markdown_tables


def test_chat_markdown_renders_tables_and_common_prose() -> None:
    rendered = str(render_safe_markdown(
        "## Pods\n\n| Pod | Ready |\n|---|---|\n| api | **yes** |\n\n- bounded\n- cited"
    ))
    assert "<h2>Pods</h2>" in rendered
    assert "<table>" in rendered
    assert "<strong>yes</strong>" in rendered
    assert "<li>bounded</li>" in rendered


def test_chat_markdown_escapes_html_and_rejects_unsafe_links() -> None:
    rendered = str(render_safe_markdown(
        '<script>alert("x")</script>\n\n[unsafe](javascript:alert(1))'
    ))
    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered
    assert "javascript:" in rendered
    assert '<a href="javascript:' not in rendered


def test_chat_markdown_pretty_prints_fenced_and_standalone_json() -> None:
    fenced = str(render_safe_markdown(
        'Observed payload:\n\n```json\n{"outputs":[{"name":"kafka","ready":true}]}\n```'
    ))
    standalone = str(render_safe_markdown('{"cluster":"central","ready":true}'))

    assert '<code class="language-json">' in fenced
    assert "\n  &quot;outputs&quot;: [\n" in fenced
    assert "\n    {\n" in fenced
    assert '<code class="language-json">' in standalone
    assert "\n  &quot;cluster&quot;: &quot;central&quot;,\n" in standalone


def test_markdown_tables_become_ordered_bounded_native_blocks() -> None:
    blocks = split_markdown_tables(
        "## Policies\n\n"
        "| Name | Ingress rules | Pod selector |\n|---|---|---|\n"
        "| `deny-by-default` | **Blocks** inbound traffic | `{}` |\n\n"
        "The policy effect remains visible."
    )

    assert [block["type"] for block in blocks] == [
        "markdown", "answer_table", "markdown",
    ]
    table = blocks[1]
    assert [column["label"] for column in table["columns"]] == [
        "Name", "Ingress rules", "Pod selector",
    ]
    assert table["rows"] == [{
        "cells": ["`deny-by-default`", "**Blocks** inbound traffic", "`{}`"],
    }]
    assert blocks[2]["content"] == "The policy effect remains visible."


def test_markdown_table_extraction_is_bounded_and_leaves_extra_tables_in_prose() -> None:
    blocks = split_markdown_tables(
        "| A |\n|---|\n| 1 |\n| 2 |\n\n| B |\n|---|\n| 3 |",
        max_tables=1,
        max_rows_per_table=1,
    )

    assert blocks[0]["type"] == "answer_table"
    assert blocks[0]["row_count"] == 1
    assert blocks[0]["omitted_count"] == 1
    assert blocks[1]["type"] == "markdown"
    assert "| B |" in blocks[1]["content"]


def test_extracted_markdown_cells_remain_safe_markdown_not_trusted_html() -> None:
    table = split_markdown_tables(
        "| Policy | Effect |\n|---|---|\n"
        "| deny | <script>alert(1)</script> **blocked** |"
    )[0]
    cell = table["rows"][0]["cells"][1]
    rendered = str(render_safe_markdown(cell))

    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered
    assert "<strong>blocked</strong>" in rendered
