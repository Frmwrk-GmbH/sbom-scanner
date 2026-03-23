"""Dart/Flutter pub ecosystem (pubspec.yaml + pubspec.lock)."""

from __future__ import annotations

import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .base import Ecosystem
from ..i18n import _


class PubEcosystem(Ecosystem):
    name = "pub"
    display_name = "Dart/Flutter"
    cdx_prefix = "cdx:pub"
    package_url_template = "https://pub.dev/packages/{name}"
    dep_property = "cdx:pub:dependency"
    latest_property = "cdx:pub:latestVersion"
    dep_labels = {
        "direct main": "direct",
        "direct dev": "dev",
        "transitive": "transitiv",
    }
    has_group_column = False
    purl_type = "pub"
    license_property = "cdx:pub:license"
    extra_properties = {
        "upgradable": "cdx:pub:upgradableVersion",
        "discontinued": "cdx:pub:discontinued",
        "advisory": "cdx:pub:affectedByAdvisory",
    }

    def scan_pattern(self) -> dict | None:
        return {
            "detect_files": ["pubspec.lock"],
            "companion_files": ["pubspec.yaml"],
            "config_keys": {
                "pubspec.lock": "pubspec_lock",
                "pubspec.yaml": "pubspec_yaml",
            },
            "icon": "🎯",
        }

    def config_options(self) -> list[dict]:
        return [
            {"key": "include_dev", "label": "Include dev dependencies", "type": "bool", "default": True,
             "description": "Include dev_dependencies in the scan"},
        ]

    def read_project_info(self, project_dir: Path) -> tuple[str, str] | None:
        pubspec = project_dir / "pubspec.yaml"
        if not pubspec.exists():
            return None
        try:
            yaml = self._load_yaml()
            with open(pubspec) as f:
                data = yaml.safe_load(f)
            name = data.get("name", "")
            version = data.get("version", "")
            return (name, version) if name else None
        except Exception:
            return None

    def fetch_licenses(self, packages: list[dict], workers: int = 20) -> dict[str, str]:
        """Fetch licenses from pub.dev score API tags."""
        from urllib.error import URLError
        from urllib.request import Request, urlopen

        results: dict[str, str] = {}
        unique = {p["name"]: p for p in packages}

        def lookup(name: str) -> tuple[str, str]:
            url = f"https://pub.dev/api/packages/{name}/score"
            req = Request(url, headers={"Accept": "application/json"})
            try:
                with urlopen(req, timeout=10) as resp:
                    data = json.loads(resp.read())
                    tags = data.get("tags", [])
                    for tag in tags:
                        if tag.startswith("license:") and tag not in ("license:fsf-libre", "license:osi-approved"):
                            return name, tag.split(":", 1)[1].upper()
            except (URLError, json.JSONDecodeError, TimeoutError):
                pass
            return name, ""

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(lookup, name): name for name in unique}
            for future in as_completed(futures):
                name, lic = future.result()
                if lic:
                    results[name] = lic

        return results

    def detect(self, project_dir: Path, config: dict) -> bool:
        yaml_path = project_dir / config.get("pubspec_yaml", "pubspec.yaml")
        lock_path = project_dir / config.get("pubspec_lock", "pubspec.lock")
        return yaml_path.exists() and lock_path.exists()

    def parse(self, project_dir: Path, config: dict) -> list[dict]:
        yaml_path = project_dir / config.get("pubspec_yaml", "pubspec.yaml")
        lock_path = project_dir / config.get("pubspec_lock", "pubspec.lock")

        yaml = self._load_yaml()
        with open(yaml_path) as f:
            pubspec_yaml = yaml.safe_load(f)
        with open(lock_path) as f:
            pubspec_lock = yaml.safe_load(f)

        # Outdated info from `dart pub outdated`
        outdated_info = self._get_outdated_info(project_dir)

        packages = []
        for name, pkg_data in sorted(pubspec_lock.get("packages", {}).items()):
            source = pkg_data.get("source", "unknown")
            if source == "sdk":
                continue

            dep_type = pkg_data.get("dependency", "transitive")
            version = pkg_data.get("version", "0.0.0")
            description = pkg_data.get("description", {})

            pkg = {
                "name": name,
                "version": version,
                "dep_type": dep_type,
                "source": source,
                "description": description if isinstance(description, dict) else {},
                "sha256": None,
            }

            # SHA-256 hash
            if isinstance(description, dict):
                pkg["sha256"] = description.get("sha256")
            if not pkg["sha256"]:
                pkg["sha256"] = pkg_data.get("sha256")

            # Append outdated info
            outdated = outdated_info.get(name, {})
            pkg["latest"] = (outdated.get("latest") or {}).get("version")
            pkg["upgradable"] = (outdated.get("upgradable") or {}).get("version")
            pkg["resolvable"] = (outdated.get("resolvable") or {}).get("version")
            pkg["is_discontinued"] = outdated.get("isDiscontinued", False)
            pkg["is_retracted"] = outdated.get("isCurrentRetracted", False)
            pkg["is_advisory"] = outdated.get("isCurrentAffectedByAdvisory", False)

            packages.append(pkg)

        if not config.get("include_dev", True):
            packages = [p for p in packages if p["dep_type"] != "direct dev"]

        # Store pubspec_yaml data for get_direct_purls and metadata
        self._last_pubspec_yaml = pubspec_yaml
        self._last_pubspec_lock = pubspec_lock

        return packages

    def fetch_latest_versions(self, packages: list[dict], workers: int = 20) -> dict[str, str]:
        # Latest versions already come from `dart pub outdated`
        return {p["name"]: p["latest"] for p in packages if p.get("latest")}

    def build_component(self, pkg: dict, latest: str | None) -> dict:
        name = pkg["name"]
        version = pkg["version"]
        source = pkg["source"]
        dep_type = pkg["dep_type"]
        description = pkg["description"]

        purl = self._build_purl(name, version, source, description)

        scope = "optional" if dep_type == "direct dev" else "required"

        component = {
            "type": "library",
            "group": "pub.dev",
            "name": name,
            "version": version,
            "scope": scope,
            "purl": purl,
            "bom-ref": purl,
        }

        if pkg.get("sha256"):
            component["hashes"] = [{"alg": "SHA-256", "content": pkg["sha256"]}]

        if source == "hosted":
            url = description.get("url", "https://pub.dev")
            component["externalReferences"] = [
                {"type": "distribution", "url": f"{url}/packages/{name}"}
            ]
        elif source == "git":
            git_url = description.get("url", "")
            if git_url:
                ref = {"type": "vcs", "url": git_url}
                resolved_ref = description.get("resolved-ref")
                if resolved_ref:
                    ref["comment"] = f"ref: {resolved_ref}"
                component["externalReferences"] = [ref]

        properties = [
            {"name": "cdx:ecosystem", "value": "pub"},
            {"name": "cdx:pub:dependency", "value": dep_type},
            {"name": "cdx:pub:source", "value": source},
        ]

        if latest:
            properties.append({"name": "cdx:pub:latestVersion", "value": latest})
        if pkg.get("upgradable"):
            properties.append({"name": "cdx:pub:upgradableVersion", "value": pkg["upgradable"]})
        if pkg.get("resolvable"):
            properties.append({"name": "cdx:pub:resolvableVersion", "value": pkg["resolvable"]})
        if pkg.get("is_discontinued"):
            properties.append({"name": "cdx:pub:discontinued", "value": "true"})
        if pkg.get("is_retracted"):
            properties.append({"name": "cdx:pub:retracted", "value": "true"})
        if pkg.get("is_advisory"):
            properties.append({"name": "cdx:pub:affectedByAdvisory", "value": "true"})

        component["properties"] = properties
        return component

    def get_direct_purls(self, packages: list[dict]) -> list[str]:
        return [
            self._build_purl(p["name"], p["version"], p["source"], p["description"])
            for p in packages if p["dep_type"] in ("direct main", "direct dev")
        ]

    def parse_dependency_graph(self, project_dir: Path, config: dict, packages: list[dict]) -> list[dict]:
        """Build dependency graph from `dart pub deps --json`."""
        try:
            result = subprocess.run(
                ["dart", "pub", "deps", "--json"],
                capture_output=True, text=True, cwd=project_dir, timeout=120,
            )
            if result.returncode != 0:
                return []
            data = json.loads(result.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            return []

        known = {p["name"]: p["version"] for p in packages}
        graph = []

        for pkg in data.get("packages", []):
            name = pkg.get("name", "")
            if name not in known or pkg.get("kind") == "root":
                continue
            version = known[name]
            ref = f"pkg:pub/{name}@{version}"
            deps = pkg.get("dependencies", [])
            depends_on = []
            for dep_name in deps:
                dep_ver = known.get(dep_name)
                if dep_ver:
                    depends_on.append(f"pkg:pub/{dep_name}@{dep_ver}")
            if depends_on:
                graph.append({"ref": ref, "dependsOn": sorted(depends_on)})

        return graph

    def get_osv_lockfiles(self, project_dir: Path, config: dict) -> list[tuple[str, Path]]:
        lock = project_dir / config.get("pubspec_lock", "pubspec.lock")
        if lock.exists():
            return [("pubspec.lock", lock)]
        return []

    @staticmethod
    def _build_purl(name: str, version: str, source: str, description: dict) -> str:
        base = f"pkg:pub/{name}@{version}"
        if source == "hosted":
            url = description.get("url", "")
            if url and "pub.dev" not in url:
                base += f"?repository_url={url}"
        return base

    @staticmethod
    def _load_yaml():
        try:
            import yaml
            return yaml
        except ImportError:
            print(_("Error: PyYAML is required for Dart/Flutter: pip install pyyaml"), file=sys.stderr)
            sys.exit(1)

    @staticmethod
    def _get_outdated_info(project_dir: Path) -> dict[str, dict]:
        try:
            result = subprocess.run(
                ["dart", "pub", "outdated", "--json", "--show-all"],
                capture_output=True, text=True, cwd=project_dir, timeout=120,
            )
            data = json.loads(result.stdout)
            return {pkg["package"]: pkg for pkg in data.get("packages", [])}
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as e:
            print(_("Warning: dart pub outdated failed: {}").format(e), file=sys.stderr)
            return {}
