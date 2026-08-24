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
