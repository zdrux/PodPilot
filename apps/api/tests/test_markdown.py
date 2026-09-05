from podpilot_api.markdown import (
    render_safe_markdown,
    render_safe_prose_markdown,
    render_safe_table_markdown,
    split_markdown_tables,
)


def test_prose_markdown_does_not_turn_pipe_delimited_evidence_into_a_table() -> None:
    rendered = str(render_safe_prose_markdown(
        "**Likely cause**\n\n"
        "| Evidence | Observation |\n|---|---|\n"
        "| E1 | `restartCount=9` |"
    ))

    assert "<table>" not in rendered
    assert "<strong>Likely cause</strong>" in rendered
    assert "<code>restartCount=9</code>" in rendered
    assert "| Evidence | Observation |" in rendered


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


def test_safe_html_breaks_render_in_markdown_tables_without_enabling_html() -> None:
    rendered = str(render_safe_markdown(
        "| Cluster | Outputs |\n|---|---|\n"
        "| Central | Kafka<br>Syslog<BR />Loki<br/>Archive |"
    ))

    assert "Kafka<br>\nSyslog<br>\nLoki<br>\nArchive" in rendered
    assert "&lt;br" not in rendered


def test_html_break_allowlist_does_not_apply_inside_code_or_to_other_tags() -> None:
    rendered = str(render_safe_markdown(
        "`<br>` <script>alert(1)</script> <br class=\"unsafe\">"
    ))

    assert "<code>&lt;br&gt;</code>" in rendered
    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered
    assert "&lt;br class=&quot;unsafe&quot;&gt;" in rendered


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


def test_flat_json_summary_becomes_an_ordered_native_table() -> None:
    blocks = split_markdown_tables(
        "## Current pod health (post-fix)\n\n"
        '```json\n{"anomalies":[],"anomalyCount":0,"scanComplete":true,"scannedCount":5}\n```\n\n'
        "All matching Pods are healthy."
    )

    assert [block["type"] for block in blocks] == [
        "markdown", "answer_table", "markdown",
    ]
    table = blocks[1]
    assert table["source"] == "answer_json"
    assert table["rows"] == [
        {"cells": ["`anomalies`", "`[]`"]},
        {"cells": ["`anomalyCount`", "`0`"]},
        {"cells": ["`scanComplete`", "`true`"]},
        {"cells": ["`scannedCount`", "`5`"]},
    ]
    assert blocks[2]["content"] == "All matching Pods are healthy."


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


def test_extracted_markdown_table_cells_render_safe_html_breaks() -> None:
    table = split_markdown_tables(
        "| Cluster | Outputs |\n|---|---|\n"
        "| Central | Kafka<br>Syslog<br />Loki |"
    )[0]
    cell = table["rows"][0]["cells"][1]
    rendered = str(render_safe_markdown(cell))

    assert rendered == "<p>Kafka<br>\nSyslog<br>\nLoki</p>\n"


def test_table_cells_repair_break_tags_wrapped_in_model_code_spans() -> None:
    rendered = str(render_safe_table_markdown(
        "`unknown`} `<br>` **tm-vault-output**<BR />`next<br/>line`"
    ))

    assert "unknown" not in rendered
    assert "}" not in rendered
    assert "&lt;br" not in rendered.lower()
    assert "<code><br>" not in rendered
    assert rendered.count("<br>") == 2
    assert "<strong>tm-vault-output</strong>" in rendered
    assert "<code>next<br>\nline</code>" in rendered


def test_table_cell_break_repair_does_not_enable_other_raw_html() -> None:
    rendered = str(render_safe_table_markdown(
        "`<script>alert(1)</script>` <img src=x onerror=alert(1)> `<br>`"
    ))

    assert "<script>" not in rendered
    assert "<img" not in rendered
    assert "&lt;script&gt;" in rendered
    assert "&lt;img src=x onerror=alert(1)&gt;" in rendered
    assert rendered.count("<br>") == 1


def test_table_cells_remove_unmatched_serialization_braces_but_keep_templates() -> None:
    table = split_markdown_tables(
        "| Filters defined |\n|---|\n"
        "| `\"unknown\"`} `<br>` • **forward-syslog** – `tcp://logs:10517`{<br>"
        "• topic `logs-{kubernetes.namespace_name}`<br>• literal `{}`<br>"
        "• JSON `{\"mode\":\"strict\"}` |"
    )[0]
    cell = table["rows"][0]["cells"][0]
    rendered = str(render_safe_table_markdown(cell))

    assert "unknown" not in cell
    assert "10517{" not in cell
    assert "{kubernetes.namespace_name}" in cell
    assert "`{}`" in cell
    assert '`{\"mode\":\"strict\"}`' in cell
    assert "unknown" not in rendered
    assert "10517{" not in rendered
    assert "{kubernetes.namespace_name}" in rendered
    assert "<code>{}</code>" in rendered
    assert '<code>{&quot;mode&quot;:&quot;strict&quot;}</code>' in rendered


def test_table_cell_keeps_unknown_when_it_is_the_only_value() -> None:
    rendered = str(render_safe_table_markdown('"unknown"'))

    assert rendered == '<p>unknown</p>\n'
