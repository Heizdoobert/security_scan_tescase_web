from websec_test.results.dashboard import JSBuilder

def test_js_builder_returns_string():
    builder = JSBuilder()
    js_content = builder.build()
    assert isinstance(js_content, str)
    assert "function toggleRow" in js_content
