"""Central configuration objects and defaults for OT-ORCA."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from .ai.base import AIConfig
from .core.capture import CaptureConfig


DEFAULT_OUTPUT_DIR = os.environ.get("OTORCA_OUT", os.path.expanduser("~/otorca-reports"))


@dataclass
class AppConfig:
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    output_dir: str = DEFAULT_OUTPUT_DIR
    enable_ai: bool = False
    active_nmap: bool = False
    nmap_profile: str = "gentle"

    def ensure_output(self) -> str:
        os.makedirs(self.output_dir, exist_ok=True)
        return self.output_dir
