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

    def _log_request_response(self, response):
        req = response.request
        log = []
        log.append("=== HTTP REQUEST ===")
        log.append(f"{req.method} {req.url}")
        for k, v in req.headers.items():
            log.append(f"{k}: {v}")
        if req.body:
            body_str = req.body.decode('utf-8') if isinstance(req.body, bytes) else str(req.body)
            log.append(f"\n{body_str}")
        
        log.append("\n=== HTTP RESPONSE ===")
        log.append(f"Status: {response.status_code}")
        for k, v in response.headers.items():
            log.append(f"{k}: {v}")
        log.append(f"\n{response.text[:2000]}") # Truncate body if too long
        
        response.http_log = "\n".join(log)
        self.last_log = response.http_log
        return response

    def get(self, url, **kwargs):
        resolved = self._resolve_url(url)
        resp = self.session.get(resolved, timeout=self.timeout, **kwargs)
        return self._log_request_response(resp)

    def post(self, url, data=None, **kwargs):
        resolved = self._resolve_url(url)
        resp = self.session.post(resolved, data=data, timeout=self.timeout, **kwargs)
        return self._log_request_response(resp)

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
