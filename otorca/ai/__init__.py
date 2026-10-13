"""Optional AI analyst layer (Ollama / OpenAI-compatible / MCP)."""

from .base import AIConfig, AIBackendError  # noqa: F401
from .analyst import Analyst, deterministic_narrative  # noqa: F401
