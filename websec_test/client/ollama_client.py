"""Ollama API client — direct HTTP client for local Ollama inference.

Calls the Ollama REST API directly (no openai SDK dependency needed).
Supports full sampling parameter control: temperature, top_p, top_k,
min_p, presence_penalty, and repetition_penalty.
"""
import json
import os
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class OllamaModelConfig:
    """Sampling parameters for an Ollama model."""

    model: str = "qwen2.5-coder:7b"
    temperature: float = 0.6
    top_p: float = 0.95
    top_k: int = 20
    min_p: float = 0.0
    presence_penalty: float = 0.0
    repeat_penalty: float = 1.0  # Ollama wire name for repetition_penalty
    num_ctx: int = 32768  # context window (tokens)

    def to_options(self) -> dict[str, Any]:
        """Return the Ollama ``options`` dict sent on the wire."""
        return {
            "temperature": self.temperature,
            "top_p": self.top_p,
            "top_k": self.top_k,
            "min_p": self.min_p,
            "presence_penalty": self.presence_penalty,
            "repeat_penalty": self.repeat_penalty,
            "num_ctx": self.num_ctx,
        }


# ── Default configuration (your specified parameters) ──────────────────────
DEFAULT_CONFIG = OllamaModelConfig(
    model="qwen2.5-coder:7b",
    temperature=0.6,
    top_p=0.95,
    top_k=20,
    min_p=0.0,
    presence_penalty=0.0,
    repeat_penalty=1.0,
)


@dataclass
class OllamaMessage:
    """A single chat message."""

    role: str  # "system" | "user" | "assistant"
    content: str


class OllamaClient:
    """Synchronous Ollama chat client using the ``/api/chat`` endpoint.

    Parameters
    ----------
    config : OllamaModelConfig
        Model name and sampling parameters.
    base_url : str | None
        Ollama server URL.  Defaults to ``OLLAMA_BASE_URL`` env var,
        then ``http://localhost:11434``.
    system_prompt : str | None
        Optional system instruction prepended to every conversation.
    timeout : int
        Per-request timeout in seconds (default 120 — LLM inference is slow).
    """

    def __init__(
        self,
        config: OllamaModelConfig | None = None,
        base_url: str | None = None,
        system_prompt: str | None = None,
        timeout: int = 120,
    ):
        self.config = config or DEFAULT_CONFIG
        self.base_url = (
            base_url
            or os.getenv("OLLAMA_BASE_URL")
            or "http://localhost:11434"
        ).rstrip("/")
        self.system_prompt = system_prompt
        self.timeout = timeout
        self._history: list[dict[str, str]] = []

    # ── public API ──────────────────────────────────────────────────────── #

    def chat(self, prompt: str, *, keep_history: bool = False) -> str:
        """Send a single user message and return the assistant reply.

        Parameters
        ----------
        prompt : str
            The user message.
        keep_history : bool
            If ``True``, previous turns are sent for multi-turn context.
        """
        messages: list[dict[str, str]] = []
        if self.system_prompt:
            messages.append({"role": "system", "content": self.system_prompt})

        if keep_history:
            messages.extend(self._history)

        messages.append({"role": "user", "content": prompt})

        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": messages,
            "stream": False,
            "options": self.config.to_options(),
        }

        reply = self._post("/api/chat", payload)
        assistant_text = reply.get("message", {}).get("content", "")

        if keep_history:
            self._history.append({"role": "user", "content": prompt})
            self._history.append({"role": "assistant", "content": assistant_text})

        return assistant_text

    def generate(self, prompt: str) -> str:
        """One-shot generation via the ``/api/generate`` endpoint."""
        payload: dict[str, Any] = {
            "model": self.config.model,
            "prompt": prompt,
            "stream": False,
            "options": self.config.to_options(),
        }
        if self.system_prompt:
            payload["system"] = self.system_prompt

        reply = self._post("/api/generate", payload)
        return reply.get("response", "")

    def is_available(self) -> bool:
        """Check whether the Ollama server is reachable and the model exists."""
        try:
            import requests
            resp = requests.get(
                f"{self.base_url}/api/tags",
                timeout=5,
            )
            if resp.status_code != 200:
                return False
            models = resp.json().get("models", [])
            return any(
                m.get("name", "").startswith(self.config.model.split(":")[0])
                for m in models
            )
        except Exception:
            return False

    def model_info(self) -> dict[str, Any] | None:
        """Return model metadata from Ollama, or ``None`` on failure."""
        try:
            import requests
            resp = requests.post(
                f"{self.base_url}/api/show",
                json={"name": self.config.model},
                timeout=10,
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return None

    def clear_history(self) -> None:
        """Reset conversation history."""
        self._history.clear()

    # ── internals ───────────────────────────────────────────────────────── #

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        import requests
        url = f"{self.base_url}{path}"
        resp = requests.post(
            url,
            json=payload,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def __repr__(self) -> str:
        return (
            f"OllamaClient(model={self.config.model!r}, "
            f"base_url={self.base_url!r}, "
            f"temperature={self.config.temperature})"
        )
