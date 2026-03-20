"""Grype CVE scanner — scans the CycloneDX SBOM."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from .base import Scanner
from ..i18n import _


class GrypeScanner(Scanner):
    name = "grype"
    targets = ["*"]

    def is_available(self) -> bool:
        try:
            subprocess.run(["grype", "version"], capture_output=True, timeout=10)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def scan(self, sbom_path: Path, lockfiles: list[tuple[str, Path]],
             project_dir: Path) -> list[dict]:
        try:
            result = subprocess.run(
                ["grype", f"sbom:{sbom_path}", "-o", "json"],
                capture_output=True, text=True, timeout=120,
            )
            data = json.loads(result.stdout)
            return self._parse_matches(data.get("matches", []))
        except FileNotFoundError:
            print(_("Warning: grype not installed, skipped"), file=sys.stderr)
            return []
        except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
            print(_("Warning: grype failed: {}").format(e), file=sys.stderr)
            return []

    @staticmethod
    def _parse_matches(matches: list[dict]) -> list[dict]:
        vulns = []
        for m in matches:
            vuln = m.get("vulnerability", {})
            artifact = m.get("artifact", {})
            vulns.append({
                "id": vuln.get("id", ""),
                "summary": vuln.get("description", "")[:200],
                "package": artifact.get("name", ""),
                "version": artifact.get("version", ""),
                "severity": vuln.get("severity", "Unknown"),
                "fix_versions": vuln.get("fix", {}).get("versions", []),
                "references": vuln.get("urls", [])[:2],
            })
        return vulns
