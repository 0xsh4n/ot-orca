"""Ollama backend (local models such as qwen2.5, llama3.1, mistral).

Talks to the Ollama HTTP API (default http://localhost:11434). Because Ollama
runs entirely on the operator's machine, it's the recommended backend for OT
work: no capture data ever leaves the host.
"""

from __future__ import annotations

import json

import requests

from .base import LLMBackend, AIConfig, AIBackendError

DEFAULT_URL = "http://localhost:11434"


class OllamaBackend(LLMBackend):
    def __init__(self, config: AIConfig):
        super().__init__(config)
        self.base = (config.base_url or DEFAULT_URL).rstrip("/")

    def available(self) -> bool:
        try:
            r = requests.get(f"{self.base}/api/tags", timeout=5)
            return r.status_code == 200
        except Exception:
            return False

    def list_models(self) -> list[str]:
        try:
            r = requests.get(f"{self.base}/api/tags", timeout=5)
            r.raise_for_status()
            return [m["name"] for m in r.json().get("models", [])]
        except Exception:
            return []

    def chat(self, system: str, user: str) -> str:
        payload = {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "options": {
                "temperature": self.config.temperature,
                "num_predict": self.config.max_tokens,
            },
        }
        try:
            r = requests.post(f"{self.base}/api/chat", json=payload,
                              timeout=self.config.timeout)
        except requests.exceptions.ConnectionError as exc:
            raise AIBackendError(
                f"Cannot reach Ollama at {self.base}. Is 'ollama serve' running? "
                f"({exc})") from exc
        except requests.exceptions.Timeout as exc:
            raise AIBackendError(
                f"Ollama timed out after {self.config.timeout}s.") from exc
        if r.status_code == 404:
            raise AIBackendError(
                f"Model '{self.config.model}' not found. Pull it with "
                f"'ollama pull {self.config.model}'. Available: "
                f"{', '.join(self.list_models()) or 'none'}")
        if r.status_code != 200:
            raise AIBackendError(f"Ollama error {r.status_code}: {r.text[:200]}")
        try:
            return r.json()["message"]["content"].strip()
        except (KeyError, json.JSONDecodeError) as exc:
            raise AIBackendError(f"Unexpected Ollama response: {exc}") from exc
