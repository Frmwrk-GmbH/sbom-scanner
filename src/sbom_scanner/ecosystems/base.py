"""Abstract base class for ecosystem plugins."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path


class Ecosystem(ABC):
    """Base class for an ecosystem plugin.

    To add a new ecosystem:
      1. Create a new file in ecosystems/ (e.g. cargo.py).
      2. Subclass Ecosystem.
      3. Implement all abstract methods.
      4. Register in ecosystems/__init__.py.
    """

    # ── Identification ──
    name: str = ""
    display_name: str = ""
    cdx_prefix: str = ""

    # ── Report configuration ──
    package_url_template: str = ""
    dep_property: str = ""
    latest_property: str = ""
    dep_labels: dict[str, str] = {}
    has_group_column: bool = False
    extra_properties: dict[str, str] = {}
    purl_type: str = ""
    module_property: str = ""

    def report_config(self) -> dict:
        """Return report configuration as a dict.

        Used by the report generator to render tables and badges.
        """
        return {
            "display_name": self.display_name,
            "dep_prop": self.dep_property,
            "latest_prop": self.latest_property,
            "url_template": self.package_url_template,
            "dep_labels": self.dep_labels,
            "has_group_column": self.has_group_column,
            "extra_props": self.extra_properties,
            "purl_type": self.purl_type,
            "module_prop": self.module_property,
        }

    # ── Abstract methods ──

    @abstractmethod
    def detect(self, project_dir: Path, config: dict) -> bool:
        """Check whether this ecosystem is present in the project."""

    @abstractmethod
    def parse(self, project_dir: Path, config: dict) -> list[dict]:
        """Parse lockfiles and return a list of package dicts.

        Each dict must contain at least:
          - name: str
          - version: str
          - dep_type: str (e.g. "direct main", "transitive", "direct dev")
        """

    @abstractmethod
    def fetch_latest_versions(self, packages: list[dict], workers: int = 20) -> dict[str, str]:
        """Fetch the latest stable versions for all packages in parallel."""

    @abstractmethod
    def build_component(self, pkg: dict, latest: str | None) -> dict:
        """Build a CycloneDX component from a package dict."""

    @abstractmethod
    def get_direct_purls(self, packages: list[dict]) -> list[str]:
        """Return PURLs of direct dependencies."""

    # ── Optional methods ──

    def get_osv_lockfiles(self, project_dir: Path, config: dict) -> list[tuple[str, Path]]:
        """Return lockfile paths for osv-scanner."""
        return []

    def parse_dependency_graph(self, project_dir: Path, config: dict, packages: list[dict]) -> list[dict]:
        """Return the dependency graph (optional)."""
        return []

    def package_key(self, pkg: dict) -> str:
        """Unique key for a package (used for latest-version lookup)."""
        return pkg["name"]

    def scan_pattern(self) -> dict | None:
        """Return a scan pattern for the auto-configurator.

        Override to make this ecosystem discoverable by sbom configure.
        Return None if the ecosystem does not support auto-discovery.

        Returns:
            Dict with:
              - detect_files: list[str] — filenames to search for
              - companion_files: list[str] — required sibling files
              - config_keys: dict[str, str] — filename -> config key mapping
              - icon: str — emoji icon for display
            Or for directory-based detection:
              - detect_dir_marker: str — filename that marks the directory
              - config_dir_key: str — config key for the directory path
              - icon: str
        """
        return None
