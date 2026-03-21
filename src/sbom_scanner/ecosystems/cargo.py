"""Rust/Cargo ecosystem (Cargo.lock + Cargo.toml)."""

from __future__ import annotations

import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

from .base import Ecosystem


class CargoEcosystem(Ecosystem):
    name = "cargo"
    display_name = "Rust/Cargo"
    cdx_prefix = "cdx:cargo"
    package_url_template = "https://crates.io/crates/{name}"
    dep_property = "cdx:cargo:dependency"
    latest_property = "cdx:cargo:latestVersion"
    dep_labels = {
        "direct main": "direct",
        "direct dev": "dev",
        "transitive": "transitiv",
    }
    has_group_column = False
    purl_type = "cargo"

    def scan_pattern(self) -> dict | None:
        return {
            "detect_files": ["Cargo.lock"],
            "companion_files": ["Cargo.toml"],
            "config_keys": {
                "Cargo.lock": "lockfile",
                "Cargo.toml": "cargo_toml",
            },
            "icon": "🦀",
        }

    def config_options(self) -> list[dict]:
        return [
            {"key": "include_dev", "label": "Include dev dependencies", "type": "bool", "default": True,
             "description": "Include [dev-dependencies] in the scan"},
            {"key": "include_build", "label": "Include build dependencies", "type": "bool", "default": False,
             "description": "Include [build-dependencies] in the scan"},
        ]

    def read_project_info(self, project_dir: Path) -> tuple[str, str] | None:
        toml = project_dir / "Cargo.toml"
        if not toml.exists():
            return None
        name = version = ""
        try:
            with open(toml) as f:
                for line in f:
                    m = re.match(r'^name\s*=\s*"([^"]+)"', line.strip())
                    if m:
                        name = m.group(1)
                    m = re.match(r'^version\s*=\s*"([^"]+)"', line.strip())
                    if m:
                        version = m.group(1)
            return (name, version) if name else None
        except OSError:
            return None

    def detect(self, project_dir: Path, config: dict) -> bool:
        lock = project_dir / config.get("lockfile", "Cargo.lock")
        toml = project_dir / config.get("cargo_toml", "Cargo.toml")
        return lock.exists() and toml.exists()

    def parse(self, project_dir: Path, config: dict) -> list[dict]:
        lock_path = project_dir / config.get("lockfile", "Cargo.lock")
        toml_path = project_dir / config.get("cargo_toml", "Cargo.toml")

        direct_deps = self._parse_cargo_toml(toml_path)
        packages = self._parse_cargo_lock(lock_path, direct_deps)

        if not config.get("include_dev", True):
            packages = [p for p in packages if p["dep_type"] != "direct dev"]

        return packages

    def fetch_latest_versions(self, packages: list[dict], workers: int = 20) -> dict[str, str]:
        results: dict[str, str] = {}
        unique = {p["name"]: p for p in packages}

        def lookup(name: str) -> tuple[str, str | None]:
            return name, self._fetch_latest(name)

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(lookup, name): name for name in unique}
            done = 0
            for future in as_completed(futures):
                done += 1
                if done % 25 == 0:
                    print(f"  Cargo-Versionen: {done}/{len(unique)} ...")
                key, version = future.result()
                if version:
                    results[key] = version

        return results

    def build_component(self, pkg: dict, latest: str | None) -> dict:
        name = pkg["name"]
        version = pkg["version"]
        purl = f"pkg:cargo/{name}@{version}"
        dep_type = pkg["dep_type"]

        scope = "optional" if dep_type in ("direct dev", "dev transitive") else "required"

        properties = [
            {"name": "cdx:ecosystem", "value": "cargo"},
            {"name": "cdx:cargo:dependency", "value": dep_type},
        ]
        if latest:
            properties.append({"name": "cdx:cargo:latestVersion", "value": latest})

        component = {
            "type": "library",
            "group": "crates.io",
            "name": name,
            "version": version,
            "scope": scope,
            "purl": purl,
            "bom-ref": purl,
            "externalReferences": [
                {"type": "distribution", "url": f"https://crates.io/crates/{name}"}
            ],
            "properties": properties,
        }

        checksum = pkg.get("checksum")
        if checksum:
            component["hashes"] = [{"alg": "SHA-256", "content": checksum}]

        return component

    def get_direct_purls(self, packages: list[dict]) -> list[str]:
        return [
            f"pkg:cargo/{p['name']}@{p['version']}"
            for p in packages if p["dep_type"] in ("direct main", "direct dev")
        ]

    def parse_dependency_graph(self, project_dir: Path, config: dict, packages: list[dict]) -> list[dict]:
        lock_path = project_dir / config.get("lockfile", "Cargo.lock")
        # Version lookup for known packages
        known = {p["name"]: p["version"] for p in packages}
        graph = []
        current_name = None
        current_version = None
        current_deps: list[str] = []

        with open(lock_path) as f:
            for line in f:
                line = line.strip()
                if line == "[[package]]":
                    if current_name and current_deps and current_name in known:
                        ref = f"pkg:cargo/{current_name}@{current_version}"
                        graph.append({"ref": ref, "dependsOn": sorted(current_deps)})
                    current_name = None
                    current_version = None
                    current_deps = []
                    continue

                m = re.match(r'^name\s*=\s*"([^"]*)"', line)
                if m:
                    current_name = m.group(1)
                    continue
                m = re.match(r'^version\s*=\s*"([^"]*)"', line)
                if m:
                    current_version = m.group(1)
                    continue
                # dependencies = ["name version", ...]
                if line.startswith("dependencies"):
                    # Parse multiline array
                    deps_text = line.split("=", 1)[1].strip()
                    if deps_text.startswith("["):
                        # Could be single-line or multi-line
                        all_text = deps_text
                        if "]" not in all_text:
                            for next_line in f:
                                all_text += next_line
                                if "]" in next_line:
                                    break
                        for dep_match in re.finditer(r'"([^"]+)"', all_text):
                            parts = dep_match.group(1).split()
                            dep_name = parts[0]
                            dep_version = parts[1] if len(parts) > 1 else known.get(dep_name, "")
                            if dep_name in known:
                                current_deps.append(f"pkg:cargo/{dep_name}@{dep_version}")

        # Last package
        if current_name and current_deps and current_name in known:
            ref = f"pkg:cargo/{current_name}@{current_version}"
            graph.append({"ref": ref, "dependsOn": sorted(current_deps)})

        return graph

    def get_osv_lockfiles(self, project_dir: Path, config: dict) -> list[tuple[str, Path]]:
        lock = project_dir / config.get("lockfile", "Cargo.lock")
        if lock.exists():
            return [("Cargo.lock", lock)]
        return []

    @staticmethod
    def _parse_cargo_toml(path: Path) -> dict[str, str]:
        """Parse Cargo.toml and return direct dependencies.

        Simple TOML parser for [dependencies] and [dev-dependencies].
        No external TOML package required.
        """
        direct: dict[str, str] = {}  # name -> "main" | "dev"
        current_section = ""

        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # Section header
                m = re.match(r"^\[([^\]]+)\]", line)
                if m:
                    current_section = m.group(1).strip()
                    continue

                if current_section in ("dependencies", "dev-dependencies"):
                    # name = "version" oder name = { version = "...", ... }
                    m = re.match(r'^([a-zA-Z0-9_-]+)\s*=', line)
                    if m:
                        dep_name = m.group(1)
                        dep_kind = "dev" if "dev" in current_section else "main"
                        direct[dep_name] = dep_kind

                # workspace dependencies: [workspace.dependencies]
                if current_section == "workspace.dependencies":
                    m = re.match(r'^([a-zA-Z0-9_-]+)\s*=', line)
                    if m:
                        direct[m.group(1)] = "main"

        return direct

    @staticmethod
    def _parse_cargo_lock(path: Path, direct_deps: dict[str, str]) -> list[dict]:
        """Parse Cargo.lock (TOML format)."""
        packages = []
        current: dict[str, str] = {}

        with open(path) as f:
            for line in f:
                line = line.strip()

                if line == "[[package]]":
                    if current.get("name"):
                        packages.append(current)
                    current = {}
                    continue

                m = re.match(r'^(\w+)\s*=\s*"([^"]*)"', line)
                if m:
                    current[m.group(1)] = m.group(2)

        # Last package
        if current.get("name"):
            packages.append(current)

        # Determine dependency type
        result = []
        for pkg in packages:
            name = pkg.get("name", "")
            version = pkg.get("version", "0.0.0")
            source = pkg.get("source", "")
            checksum = pkg.get("checksum", "")

            # Only packages from crates.io or without source (skip local crates)
            if source and "crates.io" not in source:
                continue

            if name in direct_deps:
                dep_kind = direct_deps[name]
                dep_type = f"direct {dep_kind}"
            else:
                dep_type = "transitive"

            result.append({
                "name": name,
                "version": version,
                "dep_type": dep_type,
                "checksum": checksum,
            })

        return result

    @staticmethod
    def _fetch_latest(name: str) -> str | None:
        """Fetch the latest version from crates.io."""
        url = f"https://crates.io/api/v1/crates/{name}"
        req = Request(url, headers={
            "Accept": "application/json",
            "User-Agent": "sbom-scanner/1.0",
        })
        try:
            with urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
                crate = data.get("crate", {})
                return crate.get("max_stable_version") or crate.get("max_version")
        except (URLError, json.JSONDecodeError, TimeoutError):
            pass
        return None
