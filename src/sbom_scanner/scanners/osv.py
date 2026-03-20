"""OSV scanner — scans lockfiles against the OSV database."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from .base import Scanner


class OsvScanner(Scanner):
    name = "osv"
    targets = ["*"]

    def is_available(self) -> bool:
        try:
            subprocess.run(["osv-scanner", "--version"], capture_output=True, timeout=10)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def scan(self, sbom_path: Path, lockfiles: list[tuple[str, Path]],
             project_dir: Path) -> list[dict]:
        vulns = []
        for lock_type, full_path in lockfiles:
            if not full_path.exists():
                continue
            try:
                cmd = ["osv-scanner", "scan", "--format", "json",
                       "--lockfile", f"{lock_type}:{full_path}"]
                result = subprocess.run(
                    cmd, capture_output=True, text=True,
                    cwd=project_dir, timeout=120,
                )
                data = json.loads(result.stdout) if result.stdout.strip() else {}
                vulns.extend(self._parse_results(data))
            except FileNotFoundError:
                pass
            except (subprocess.TimeoutExpired, json.JSONDecodeError):
                pass
        return vulns

    @staticmethod
    def _parse_results(data: dict) -> list[dict]:
        vulns = []
        for res in data.get("results", []):
            for pkg in res.get("packages", []):
                pkg_info = pkg.get("package", {})
                for v in pkg.get("vulnerabilities", []):
                    severity = ""
                    for s in v.get("severity", []):
                        if s.get("type") == "CVSS_V3":
                            severity = s.get("score", "")
                            break

                    vulns.append({
                        "id": v.get("id", ""),
                        "summary": v.get("summary", ""),
                        "package": pkg_info.get("name", ""),
                        "version": pkg_info.get("version", ""),
                        "severity": severity,
                        "references": [r.get("url", "") for r in v.get("references", [])[:2]],
                    })
        return vulns
