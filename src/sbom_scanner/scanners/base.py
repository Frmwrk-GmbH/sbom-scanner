"""Abstract base class for CVE scanner plugins."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path


class Scanner(ABC):
    """Base class for a CVE scanner.

    To add a new scanner:
      1. Create a new file in scanners/ (e.g. trivy.py).
      2. Subclass Scanner.
      3. Implement all abstract methods.
      4. Register in scanners/__init__.py.
    """

    name: str = ""
    # Target ecosystems: ["*"] for all, or specific names like ["npm", "pypi"]
    targets: list[str] = ["*"]

    @abstractmethod
    def is_available(self) -> bool:
        """Check whether the scanner is installed/reachable."""

    @abstractmethod
    def scan(self, sbom_path: Path, lockfiles: list[tuple[str, Path]],
             project_dir: Path) -> list[dict]:
        """Run the scan and return vulnerabilities.

        Args:
            sbom_path: Path to the CycloneDX SBOM (for SBOM-based scanners).
            lockfiles: List of (lockfile_type, path) for lockfile-based scanners.
            project_dir: Project directory.

        Returns:
            List of vulnerability dicts with:
              - id: str (e.g. "CVE-2024-1234", "GHSA-xxxx")
              - summary: str
              - package: str
              - version: str
              - severity: str (e.g. "Critical", "High", "Medium", "Low")
              - fix_versions: list[str] (optional)
              - references: list[str] (URLs, optional)
        """

    def matches_ecosystem(self, ecosystem: str) -> bool:
        """Check whether this scanner handles the given ecosystem."""
        return "*" in self.targets or ecosystem in self.targets
