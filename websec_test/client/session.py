"""HTTP session management for security testing."""
import re
from urllib.parse import urljoin

import requests


class SessionClient:
    """Wraps requests.Session with CSRF handling and base URL resolution."""

    def __init__(self, target: str, timeout: int = 10):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "WebSecTest/1.0 (Security Scanner)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })

    def _resolve_url(self, url: str) -> str:
        if url.startswith("http://") or url.startswith("https://"):
            return url
        return urljoin(self.target + "/", url.lstrip("/"))

    def get(self, url, **kwargs):
        resolved = self._resolve_url(url)
        return self.session.get(resolved, timeout=self.timeout, **kwargs)

    def post(self, url, data=None, **kwargs):
        resolved = self._resolve_url(url)
        return self.session.post(resolved, data=data, timeout=self.timeout, **kwargs)

    def extract_csrf_token(self, html: str) -> str | None:
        """Extract CSRF token from HTML using common field name patterns."""
        patterns = [
            r'name=["\']csrf_token["\'][^>]*value=["\']([^"\']+)',
            r'name=["\']_token["\'][^>]*value=["\']([^"\']+)',
            r'name=["\']authenticity_token["\'][^>]*value=["\']([^"\']+)',
            r'name=["\']csrfmiddlewaretoken["\'][^>]*value=["\']([^"\']+)',
        ]
        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)
        return None
