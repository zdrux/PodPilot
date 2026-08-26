from podpilot_api.markdown import render_safe_markdown


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
