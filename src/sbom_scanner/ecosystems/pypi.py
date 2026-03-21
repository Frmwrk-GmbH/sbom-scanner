"""PyPI ecosystem (requirements.txt / pip-compile)."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

from .base import Ecosystem
from ..i18n import _


def _normalize_pkg_name(name: str) -> str:
    """Normalize package names per PEP 503."""
    return re.sub(r"[-_.]+", "-", name).lower()


class PypiEcosystem(Ecosystem):
    name = "pypi"
    display_name = "Python/PyPI"
    cdx_prefix = "cdx:pypi"
    package_url_template = "https://pypi.org/project/{name}/"
    dep_property = "cdx:pip:dependency"
    latest_property = "cdx:pypi:latestVersion"
    dep_labels = {
        "direct main": "direct",
        "transitive": "transitiv",
    }
    has_group_column = False
    purl_type = "pypi"

    def scan_pattern(self) -> dict | None:
        return {
            "detect_files": ["requirements.txt"],
            "companion_files": [],
            "config_keys": {"requirements.txt": "requirements"},
            "icon": "🐍",
        }

    def config_options(self) -> list[dict]:
        return [
            {"key": "dep_tree_method", "label": "Dependency tree method", "type": "enum", "default": "auto",
             "choices": ["auto", "pipdeptree", "pip-compile", "flat"],
             "description": "How to resolve transitive dependencies"},
        ]

    def detect(self, project_dir: Path, config: dict) -> bool:
        req = project_dir / config.get("requirements", "requirements.txt")
        return req.exists()

    def parse(self, project_dir: Path, config: dict) -> list[dict]:
        req_path = project_dir / config.get("requirements", "requirements.txt")
        packages = self._parse_requirements_txt(req_path)

        dep_tree_method = config.get("dep_tree_method", "auto")

        if dep_tree_method == "flat":
            # No transitive dependency resolution
            pass
        elif dep_tree_method == "pipdeptree":
            tree = self._run_pipdeptree([p["name"] for p in packages])
            if tree:
                packages = self._merge_pipdeptree(packages, tree)
        elif dep_tree_method == "pip-compile":
            # Use pip-compile via comments only (no pipdeptree fallback)
            pass
        else:
            # "auto": original behavior — use pipdeptree if no pip-compile via comments
            has_via = any(p.get("via") is not None for p in packages)
            if not has_via:
                tree = self._run_pipdeptree([p["name"] for p in packages])
                if tree:
                    packages = self._merge_pipdeptree(packages, tree)

        return packages

    def fetch_latest_versions(self, packages: list[dict], workers: int = 20) -> dict[str, str]:
        results: dict[str, str] = {}

        def lookup(pkg: dict) -> tuple[str, str | None]:
            return pkg["name"], self._fetch_latest(pkg["name"])

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(lookup, pkg): pkg for pkg in packages}
            done = 0
            for future in as_completed(futures):
                done += 1
                if done % 25 == 0:
                    print(_("  PyPI versions: {}/{} ...").format(done, len(packages)))
                key, version = future.result()
                if version:
                    results[key] = version

        return results

    def build_component(self, pkg: dict, latest: str | None) -> dict:
        name = pkg["name"]
        version = pkg["version"] or "unknown"
        purl = f"pkg:pypi/{name}@{version}"
        dep_type = "direct main" if pkg["direct"] else "transitive"

        properties = [
            {"name": "cdx:ecosystem", "value": "pypi"},
            {"name": "cdx:pip:dependency", "value": dep_type},
        ]
        if latest:
            properties.append({"name": "cdx:pypi:latestVersion", "value": latest})

        return {
            "type": "library",
            "group": "pypi",
            "name": name,
            "version": version,
            "scope": "required",
            "purl": purl,
            "bom-ref": purl,
            "externalReferences": [
                {"type": "distribution", "url": f"https://pypi.org/project/{name}/"}
            ],
            "properties": properties,
        }

    def get_direct_purls(self, packages: list[dict]) -> list[str]:
        return [
            f"pkg:pypi/{p['name']}@{p['version'] or 'unknown'}"
            for p in packages if p["direct"]
        ]

    def parse_dependency_graph(self, project_dir: Path, config: dict, packages: list[dict]) -> list[dict]:
        """Build dependency graph from pipdeptree or pip-compile `# via` comments."""
        pkg_versions = {p["name"]: p["version"] or "unknown" for p in packages}

        # 1. Try pipdeptree (provides a complete tree)
        direct_names = [p["name"] for p in packages if p["direct"]]
        tree = self._run_pipdeptree(direct_names) if direct_names else None
        if tree:
            return self._tree_to_graph(tree, pkg_versions)

        # 2. Fallback: pip-compile `# via` comments
        parent_to_children: dict[str, set[str]] = {}
        for pkg in packages:
            via = pkg.get("via")
            if via and not pkg["direct"]:
                for parent_name in re.split(r"[,\s]+", via):
                    parent_name = _normalize_pkg_name(parent_name.strip())
                    if parent_name and parent_name in pkg_versions:
                        parent_to_children.setdefault(parent_name, set()).add(pkg["name"])

        graph = []
        for parent, children in parent_to_children.items():
            parent_version = pkg_versions.get(parent, "unknown")
            ref = f"pkg:pypi/{parent}@{parent_version}"
            depends_on = sorted(
                f"pkg:pypi/{c}@{pkg_versions.get(c, 'unknown')}" for c in children
            )
            graph.append({"ref": ref, "dependsOn": depends_on})
        return graph

    def get_osv_lockfiles(self, project_dir: Path, config: dict) -> list[tuple[str, Path]]:
        req = project_dir / config.get("requirements", "requirements.txt")
        if req.exists():
            return [("requirements.txt", req)]
        return []

    @staticmethod
    def _parse_requirements_txt(path: Path) -> list[dict]:
        seen: dict[str, dict] = {}
        current_pkg = None

        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    if current_pkg and "via" in line:
                        via = line.replace("#", "").strip()
                        if via.startswith("via"):
                            via_text = via.replace("via", "").strip()
                            if "-r requirements.in" in via_text:
                                current_pkg["direct"] = True
                            elif current_pkg.get("via") is None:
                                current_pkg["via"] = via_text
                    continue

                m = re.match(r"^([a-zA-Z0-9_.-]+)(?:\[.*?\])?\s*==\s*([^\s;#]+)", line)
                if m:
                    name = _normalize_pkg_name(m.group(1))
                    if name in seen:
                        current_pkg = seen[name]
                        continue
                    current_pkg = {
                        "name": name,
                        "version": m.group(2),
                        "direct": False,
                        "via": None,
                    }
                    seen[name] = current_pkg
                    continue

                m2 = re.match(r"^([a-zA-Z0-9_.-]+)\s*$", line)
                if m2:
                    name = _normalize_pkg_name(m2.group(1))
                    if name in seen:
                        current_pkg = seen[name]
                        continue
                    current_pkg = {
                        "name": name,
                        "version": None,
                        "direct": True,
                        "via": None,
                    }
                    seen[name] = current_pkg

        packages = list(seen.values())

        # No "via" comments found → plain requirements.txt → all packages are direct
        has_via = any(p.get("via") is not None or p["direct"] for p in packages)
        if not has_via:
            for p in packages:
                p["direct"] = True

        return packages

    @staticmethod
    def _run_pipdeptree(package_names: list[str]) -> list[dict] | None:
        """Run pipdeptree and return the JSON tree."""
        try:
            cmd = [sys.executable, "-m", "pipdeptree", "--json-tree",
                   "--packages", ",".join(package_names)]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0 and result.stdout.strip():
                return json.loads(result.stdout)
        except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
            pass
        return None

    @staticmethod
    def _merge_pipdeptree(packages: list[dict], tree: list[dict]) -> list[dict]:
        """Augment the package list with transitive deps from pipdeptree."""
        seen = {p["name"]: p for p in packages}

        def _walk(nodes: list[dict], is_direct: bool = False) -> None:
            for node in nodes:
                name = _normalize_pkg_name(node["package_name"])
                version = node.get("installed_version", "unknown")
                if name not in seen:
                    seen[name] = {
                        "name": name,
                        "version": version,
                        "direct": False,
                        "via": None,
                    }
                _walk(node.get("dependencies", []))

        # Top-level = direct packages
        _walk(tree, is_direct=True)
        return list(seen.values())

    @staticmethod
    def _tree_to_graph(tree: list[dict], pkg_versions: dict[str, str]) -> list[dict]:
        """Convert pipdeptree JSON tree to CycloneDX dependency graph."""
        graph: dict[str, set[str]] = {}

        def _walk(nodes: list[dict]) -> None:
            for node in nodes:
                name = _normalize_pkg_name(node["package_name"])
                version = pkg_versions.get(name, node.get("installed_version", "unknown"))
                purl = f"pkg:pypi/{name}@{version}"
                children = node.get("dependencies", [])
                if children:
                    child_purls = set()
                    for child in children:
                        cname = _normalize_pkg_name(child["package_name"])
                        cversion = pkg_versions.get(cname, child.get("installed_version", "unknown"))
                        child_purls.add(f"pkg:pypi/{cname}@{cversion}")
                    existing = graph.get(purl, set())
                    graph[purl] = existing | child_purls
                    _walk(children)

        _walk(tree)
        return [
            {"ref": ref, "dependsOn": sorted(deps)}
            for ref, deps in graph.items()
        ]

    @staticmethod
    def _fetch_latest(name: str) -> str | None:
        url = f"https://pypi.org/pypi/{name}/json"
        req = Request(url, headers={"Accept": "application/json"})
        try:
            with urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
                return data.get("info", {}).get("version")
        except (URLError, json.JSONDecodeError, TimeoutError):
            pass
        return None
