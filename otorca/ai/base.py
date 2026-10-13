"""Abstract LLM backend interface for the OT-ORCA AI analyst.

All backends implement :meth:`chat(system, user) -> str`. Backends are optional
and must fail soft: if the service is unreachable, they raise
:class:`AIBackendError` with a human-readable message, and the analyst falls
back to its deterministic, template-based narrative. No scan ever depends on an
AI being present.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass


class AIBackendError(RuntimeError):
    pass


@dataclass
class AIConfig:
    provider: str = "ollama"          # ollama | openai | mcp | none
    model: str = "qwen2.5"            # default local model (e.g. qwen2.5:3b/7b)
    base_url: str = ""                # overrides provider default
    api_key: str = ""                 # for openai-compatible endpoints
    temperature: float = 0.2
    timeout: int = 120
    max_tokens: int = 2048


class LLMBackend(abc.ABC):
    def __init__(self, config: AIConfig):
        self.config = config

    @abc.abstractmethod
    def chat(self, system: str, user: str) -> str:
        ...

    @abc.abstractmethod
    def available(self) -> bool:
        """Cheap reachability check; never raises."""
        ...

    @property
    def name(self) -> str:
        return f"{self.config.provider}:{self.config.model}"
