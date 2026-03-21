"""Base class for report renderers."""
from __future__ import annotations
from abc import ABC, abstractmethod
from pathlib import Path


class Renderer(ABC):
    name: str = ""
    display_name: str = ""
    file_extension: str = ""

    @abstractmethod
    def render(self, sbom: dict, vulns: list[dict], output_path: Path, **kwargs) -> Path:
        """Render the report and write to output_path. Returns the output path."""

    def config_options(self) -> list[dict]:
        """Return renderer-specific config options."""
        return []
