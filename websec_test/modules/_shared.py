from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class FormField:
    name: str
    type: str
    value: Optional[str] = None

@dataclass
class Form:
    action: str
    method: str
    fields: List[FormField] = field(default_factory=list)

@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    param_names: List[str] = field(default_factory=list) # Kept for backward compatibility
    is_api: bool = False
    forms: List[Form] = field(default_factory=list)

def parse_form_inputs(html: str) -> list[Endpoint]:
    """Extract GET form action URLs and input field names from HTML.

    Returns a list of Endpoint objects with populated forms.
    """
    import re
    endpoints = []
    form_pattern = re.compile(
        r'<form[^>]*method=["\'](get|GET|post|POST)["\'][^>]*>.*?</form>',
        re.DOTALL | re.IGNORECASE
    )
    for form_match in form_pattern.finditer(html):
        form_html = form_match.group(0)
        action_match = re.search(r'action=["\']([^"\']+)', form_html)
        action = action_match.group(1) if action_match else "/"
        method_match = re.search(r'method=["\']([^"\']+)', form_html, re.IGNORECASE)
        method = method_match.group(1).upper() if method_match else "GET"
        input_names = re.findall(r'<input[^>]*name=["\']([^"\']+)[^>]*>', form_html)
        if input_names:
            fields = [FormField(name=n, type="text") for n in input_names]
            form = Form(action=action, method=method, fields=fields)
            endpoints.append(Endpoint(url=action, method=method, param_names=input_names, forms=[form]))
    return endpoints
