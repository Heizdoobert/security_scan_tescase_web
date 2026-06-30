from collections import namedtuple

Endpoint = namedtuple("Endpoint", ["url", "method", "param_names"])


def parse_form_inputs(html: str) -> list[dict]:
    """Extract GET form action URLs and input field names from HTML.

    Returns a list of dicts with keys ``url`` and ``param_names``.
    """
    import re
    endpoints = []
    form_pattern = re.compile(
        r'<form[^>]*method=["\'](get|GET)["\'][^>]*>.*?</form>',
        re.DOTALL | re.IGNORECASE
    )
    for form_match in form_pattern.finditer(html):
        form_html = form_match.group(0)
        action_match = re.search(r'action=["\']([^"\']+)', form_html)
        action = action_match.group(1) if action_match else "/"
        input_names = re.findall(r'<input[^>]*name=["\']([^"\']+)[^>]*>', form_html)
        if input_names:
            endpoints.append({"url": action, "param_names": input_names})
    return endpoints
