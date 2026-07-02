from typing import List
from urllib.parse import urlparse
from websec_test.modules._shared import Endpoint, Form, FormField

class PlaywrightCrawler:
    def __init__(self, target_url: str, max_pages: int = 100):
        self.target_url = target_url
        self.max_pages = max_pages
        self.endpoints = []
        self.visited = set()

    def _is_internal_ip(self, ip_or_host: str) -> bool:
        # Basic protection against SSRF
        if ip_or_host in ("127.0.0.1", "localhost", "169.254.169.254"):
            # Only allow localhost if the target itself is localhost
            if "localhost" not in self.target_url and "127.0.0.1" not in self.target_url:
                return True
        return False

    def crawl(self) -> List[Endpoint]:
        try:
            from playwright.sync_api import sync_playwright
            from bs4 import BeautifulSoup
        except ImportError:
            # Fallback if not installed
            return [Endpoint(url="/", method="GET")]

        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=["--disable-webgl", "--disable-geolocation"]
            )
            context = browser.new_context()
            page = context.new_page()

            def route_interceptor(route, request):
                url_parsed = urlparse(request.url)
                if self._is_internal_ip(url_parsed.hostname):
                    route.abort("blockedbyclient")
                else:
                    if request.resource_type in ("fetch", "xhr") and request.url not in self.visited:
                        self.visited.add(request.url)
                        self.endpoints.append(Endpoint(url=request.url, method=request.method, is_api=True))
                    route.continue_()

            page.route("**/*", route_interceptor)
            try:
                page.goto(self.target_url, wait_until="networkidle", timeout=15000)
                html = page.content()
                soup = BeautifulSoup(html, "html.parser")
                
                # Extract Forms
                for form_tag in soup.find_all("form"):
                    action = form_tag.get("action", "/")
                    method = form_tag.get("method", "GET").upper()
                    fields = []
                    for input_tag in form_tag.find_all("input"):
                        name = input_tag.get("name")
                        if name:
                            fields.append(FormField(name=name, type=input_tag.get("type", "text")))
                    
                    if fields:
                        form_obj = Form(action=action, method=method, fields=fields)
                        ep = Endpoint(url=action, method=method, forms=[form_obj])
                        self.endpoints.append(ep)
                        
            except Exception as e:
                print(f"[!] Crawl failed: {e}")
            finally:
                browser.close()
                
        # Basic fallback if empty
        if not self.endpoints:
            self.endpoints.append(Endpoint(url="/", method="GET"))
            
        return self.endpoints
