# tests/unit/test_css_builder.py
from websec_test.results.dashboard import CSSBuilder

def test_css_builder_returns_string():
    builder = CSSBuilder()
    css_content = builder.build()
    assert isinstance(css_content, str)
    assert "body{font-family:" in css_content
