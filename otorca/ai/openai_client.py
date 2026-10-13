"""OpenAI-compatible backend.

Works with any service that speaks the OpenAI Chat Completions API: OpenAI
itself, Azure OpenAI, OpenAI Codex-style endpoints, LM Studio, vLLM, llama.cpp
server, Groq, Together, etc. Point ``base_url`` at the endpoint and set
``api_key`` if required.

WARNING surfaced by the analyst: sending capture-derived data to a *remote*
OpenAI endpoint moves OT information off-site. The operator must opt in.
"""

from __future__ import annotations

import requests

from .base import LLMBackend, AIConfig, AIBackendError

DEFAULT_URL = "https://api.openai.com/v1"


class OpenAIBackend(LLMBackend):
    def __init__(self, config: AIConfig):
        super().__init__(config)
        self.base = (config.base_url or DEFAULT_URL).rstrip("/")

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self.config.api_key:
            h["Authorization"] = f"Bearer {self.config.api_key}"
        return h

    def available(self) -> bool:
        try:
            r = requests.get(f"{self.base}/models", headers=self._headers(),
                             timeout=6)
            return r.status_code < 500
        except Exception:
            return False

    def chat(self, system: str, user: str) -> str:
        payload = {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
        }
        try:
            r = requests.post(f"{self.base}/chat/completions", json=payload,
                              headers=self._headers(), timeout=self.config.timeout)
        except requests.exceptions.RequestException as exc:
            raise AIBackendError(f"Cannot reach endpoint {self.base}: {exc}") from exc
        if r.status_code == 401:
            raise AIBackendError("Authentication failed (check api_key).")
        if r.status_code != 200:
            raise AIBackendError(f"API error {r.status_code}: {r.text[:200]}")
        try:
            return r.json()["choices"][0]["message"]["content"].strip()
        except (KeyError, IndexError) as exc:
            raise AIBackendError(f"Unexpected response shape: {exc}") from exc
