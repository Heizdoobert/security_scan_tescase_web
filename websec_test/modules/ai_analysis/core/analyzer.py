"""Ollama interaction logic for the AI analysis module."""
from websec_test.client.session import SessionClient
from websec_test.modules._shared import Endpoint
from websec_test.client.ollama_client import OllamaClient, OllamaModelConfig
from websec_test.modules.ai_analysis.core.prompts import SYSTEM_PROMPT

class AiAnalyzer:
    """Handles communication with the Ollama client."""
    
    def __init__(self, config: OllamaModelConfig):
        self.config = config
        self.ollama = OllamaClient(
            config=self.config,
            system_prompt=SYSTEM_PROMPT,
        )
        self.error: str | None = None
        
    def check_availability(self) -> bool:
        if not self.ollama.is_available():
            self.error = (
                f"Ollama server not reachable at {self.ollama.base_url} "
                f"or model '{self.config.model}' not found. "
                f"Run: ollama pull {self.config.model}"
            )
            return False
        self.error = None
        return True
        
    def get_target_details(self, client: SessionClient, url: str) -> tuple[int, str, str] | None:
        """Fetches the target and returns (status_code, headers_str, body_str)."""
        try:
            resp = client.get(url)
            status_code = resp.status_code
            headers = "\n".join(f"  {k}: {v}" for k, v in resp.headers.items())
            body = resp.text[:2000] if resp.text else "(empty)"
            return status_code, headers, body
        except Exception as e:
            self.error = f"Failed to fetch {url}: {e}"
            return None
            
    def query(self, prompt: str) -> str | None:
        """Sends a prompt to Ollama and returns the response."""
        try:
            output = self.ollama.chat(prompt)
            if not output or not output.strip():
                self.error = "Ollama returned empty response"
                return None
            return output
        except Exception as e:
            self.error = f"Ollama query failed: {e}"
            return None
