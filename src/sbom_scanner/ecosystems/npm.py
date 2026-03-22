"""npm/yarn ecosystem (package-lock.json, yarn.lock + package.json)."""

from __future__ import annotations

import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .base import Ecosystem
from ..i18n import _

_npm_license_cache: dict[str, str] = {}


class NpmEcosystem(Ecosystem):
    name = "npm"
    display_name = "JavaScript/npm"
    cdx_prefix = "cdx:npm"
    package_url_template = "https://www.npmjs.com/package/{name}"
    dep_property = "cdx:npm:dependency"
    latest_property = "cdx:npm:latestVersion"
    dep_labels = {
        "direct main": "direct",
        "direct dev": "dev",
        "transitive": "transitiv",
        "dev transitive": "dev-trans",
    }
    has_group_column = False
    purl_type = "npm"
    license_property = "cdx:npm:license"

    def scan_pattern(self) -> dict | None:
        return {
            "detect_files": ["package-lock.json", "yarn.lock"],
            "companion_files": ["package.json"],
            "config_keys": {
                "package-lock.json": "lockfile",
                "yarn.lock": "lockfile",
                "package.json": "package_json",
            },
            "icon": "📦",
        }

    def config_options(self) -> list[dict]:
        return [
            {"key": "include_dev", "label": "Include dev dependencies", "type": "bool", "default": True,
             "description": "Include devDependencies in the scan"},
            {"key": "include_optional", "label": "Include optional dependencies", "type": "bool", "default": True,
             "description": "Include optionalDependencies in the scan"},
        ]

    def read_project_info(self, project_dir: Path) -> tuple[str, str] | None:
        pkg = project_dir / "package.json"
        if not pkg.exists():
            return None
        try:
            with open(pkg) as f:
                data = json.load(f)
            name = data.get("name", "")
            version = data.get("version", "")
            return (name, version) if name else None
        except (json.JSONDecodeError, OSError):
            return None

    def detect(self, project_dir: Path, config: dict) -> bool:
        pkg = project_dir / config.get("package_json", "package.json")
        if not pkg.exists():
            return False
        # package-lock.json or yarn.lock
        lock = project_dir / config.get("lockfile", "package-lock.json")
        yarn = project_dir / config.get("lockfile", "yarn.lock")
        return lock.exists() or yarn.exists()

    def parse(self, project_dir: Path, config: dict) -> list[dict]:
        pkg_path = project_dir / config.get("package_json", "package.json")

        # Determine lockfile
        explicit_lock = config.get("lockfile")
        if explicit_lock:
            lock_path = project_dir / explicit_lock
        else:
            npm_lock = project_dir / "package-lock.json"
            yarn_lock = project_dir / "yarn.lock"
            lock_path = npm_lock if npm_lock.exists() else yarn_lock

        with open(pkg_path) as f:
            pkg_json = json.load(f)

        direct_deps = set(pkg_json.get("dependencies", {}).keys())
        dev_deps = set(pkg_json.get("devDependencies", {}).keys())
        include_dev = config.get("include_dev", True)
        include_optional = config.get("include_optional", True)

        if lock_path.name == "yarn.lock":
            packages = self._parse_yarn_lock(lock_path, direct_deps, dev_deps)
        else:
            packages = self._parse_package_lock(lock_path, direct_deps, dev_deps)

        if not include_dev:
            packages = [p for p in packages if p["dep_type"] not in ("direct dev", "dev transitive")]

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
                if done % 50 == 0:
                    print(_("  npm versions: {}/{} ...").format(done, len(unique)))
                key, version = future.result()
                if version:
                    results[key] = version

        return results

    def build_component(self, pkg: dict, latest: str | None) -> dict:
        name = pkg["name"]
        version = pkg["version"]
        purl = f"pkg:npm/{name}@{version}"
        dep_type = pkg["dep_type"]

        scope = "optional" if dep_type in ("direct dev", "dev transitive") else "required"

        properties = [
            {"name": "cdx:ecosystem", "value": "npm"},
            {"name": "cdx:npm:dependency", "value": dep_type},
        ]
        if latest:
            properties.append({"name": "cdx:npm:latestVersion", "value": latest})

        component = {
            "type": "library",
            "group": "npmjs",
            "name": name,
            "version": version,
            "scope": scope,
            "purl": purl,
            "bom-ref": purl,
            "externalReferences": [
                {"type": "distribution", "url": f"https://www.npmjs.com/package/{name}"}
            ],
            "properties": properties,
        }

        integrity = pkg.get("integrity", "")
        if integrity.startswith("sha512-"):
            component["hashes"] = [{"alg": "SHA-512", "content": integrity[7:]}]
        elif integrity.startswith("sha256-"):
            component["hashes"] = [{"alg": "SHA-256", "content": integrity[7:]}]

        return component

    def get_direct_purls(self, packages: list[dict]) -> list[str]:
        return [
            f"pkg:npm/{p['name']}@{p['version']}"
            for p in packages if p["dep_type"] in ("direct main", "direct dev")
        ]

    def parse_dependency_graph(self, project_dir: Path, config: dict, packages: list[dict]) -> list[dict]:
        explicit_lock = config.get("lockfile")
        if explicit_lock:
            lock_path = project_dir / explicit_lock
        else:
            npm_lock = project_dir / "package-lock.json"
            yarn_lock = project_dir / "yarn.lock"
            lock_path = npm_lock if npm_lock.exists() else yarn_lock

        pkg_versions = {p["name"]: p["version"] for p in packages}

        if lock_path.name == "yarn.lock":
            return self._parse_yarn_dep_graph(lock_path, pkg_versions)

        # package-lock.json
        with open(lock_path) as f:
            lockfile = json.load(f)

        graph = []
        pkgs_dict = lockfile.get("packages", {})
        for key, info in pkgs_dict.items():
            if not key:
                continue
            name = key.split("node_modules/")[-1]
            version = pkg_versions.get(name, info.get("version", "unknown"))
            ref = f"pkg:npm/{name}@{version}"

            deps = list(info.get("dependencies", {}).keys()) + list(info.get("optionalDependencies", {}).keys())
            depends_on = []
            for dep_name in deps:
                dep_version = pkg_versions.get(dep_name)
                if dep_version:
                    depends_on.append(f"pkg:npm/{dep_name}@{dep_version}")

            if depends_on:
                graph.append({"ref": ref, "dependsOn": sorted(depends_on)})

        return graph

    def get_osv_lockfiles(self, project_dir: Path, config: dict) -> list[tuple[str, Path]]:
        explicit_lock = config.get("lockfile")
        if explicit_lock:
            lock = project_dir / explicit_lock
            lock_type = "yarn.lock" if "yarn" in explicit_lock else "package-lock.json"
            return [(lock_type, lock)] if lock.exists() else []

        for name in ["package-lock.json", "yarn.lock"]:
            lock = project_dir / name
            if lock.exists():
                return [(name, lock)]
        return []

    # ── package-lock.json parser ──

    @staticmethod
    def _parse_package_lock(lock_path: Path, direct_deps: set, dev_deps: set) -> list[dict]:
        with open(lock_path) as f:
            lockfile = json.load(f)

        packages = []

        # lockfileVersion 2/3
        pkgs_dict = lockfile.get("packages", {})
        if pkgs_dict:
            for key, info in pkgs_dict.items():
                if not key:
                    continue
                name = key.split("node_modules/")[-1]
                version = info.get("version", "unknown")
                is_dev = info.get("dev", False)

                if name in direct_deps:
                    dep_type = "direct main"
                elif name in dev_deps:
                    dep_type = "direct dev"
                elif is_dev:
                    dep_type = "dev transitive"
                else:
                    dep_type = "transitive"

                packages.append({
                    "name": name,
                    "version": version,
                    "dep_type": dep_type,
                    "resolved": info.get("resolved", ""),
                    "integrity": info.get("integrity", ""),
                })
        else:
            # lockfileVersion 1
            deps = lockfile.get("dependencies", {})
            for name, info in deps.items():
                version = info.get("version", "unknown")
                is_dev = info.get("dev", False)

                if name in direct_deps:
                    dep_type = "direct main"
                elif name in dev_deps:
                    dep_type = "direct dev"
                elif is_dev:
                    dep_type = "dev transitive"
                else:
                    dep_type = "transitive"

                packages.append({
                    "name": name,
                    "version": version,
                    "dep_type": dep_type,
                    "resolved": info.get("resolved", ""),
                    "integrity": info.get("integrity", ""),
                })

        return packages

    # ── yarn.lock parser ──

    @staticmethod
    def _parse_yarn_lock(lock_path: Path, direct_deps: set, dev_deps: set) -> list[dict]:
        """Parse yarn.lock (v1 format)."""
        packages = []
        seen: dict[str, dict] = {}  # name -> pkg (dedupliziert)

        current_names: list[str] = []
        current: dict[str, str] = {}

        with open(lock_path) as f:
            for line in f:
                # New block
                if not line.startswith(" ") and not line.startswith("#") and line.strip():
                    # Save previous block
                    if current_names and current.get("version"):
                        for name in current_names:
                            if name not in seen:
                                if name in direct_deps:
                                    dep_type = "direct main"
                                elif name in dev_deps:
                                    dep_type = "direct dev"
                                else:
                                    dep_type = "transitive"
                                seen[name] = {
                                    "name": name,
                                    "version": current["version"],
                                    "dep_type": dep_type,
                                    "resolved": current.get("resolved", ""),
                                    "integrity": current.get("integrity", ""),
                                }

                    # Parse new entries: "@scope/name@range, @scope/name@range:"
                    current_names = []
                    current = {}
                    # Remove trailing ":"
                    header = line.rstrip().rstrip(":")
                    for part in header.split(","):
                        part = part.strip().strip('"')
                        # "@scope/name@range" oder "name@range"
                        if "@" in part:
                            # Last @ is the version separator
                            at_idx = part.rfind("@")
                            if at_idx > 0:
                                name = part[:at_idx]
                                if name not in current_names:
                                    current_names.append(name)
                    continue

                # Properties within a block
                stripped = line.strip()
                if stripped.startswith("version "):
                    current["version"] = stripped.split('"')[1] if '"' in stripped else stripped.split()[1]
                elif stripped.startswith("resolved "):
                    current["resolved"] = stripped.split('"')[1] if '"' in stripped else ""
                elif stripped.startswith("integrity "):
                    current["integrity"] = stripped.split()[1] if len(stripped.split()) > 1 else ""

        # Save last block
        if current_names and current.get("version"):
            for name in current_names:
                if name not in seen:
                    if name in direct_deps:
                        dep_type = "direct main"
                    elif name in dev_deps:
                        dep_type = "direct dev"
                    else:
                        dep_type = "transitive"
                    seen[name] = {
                        "name": name,
                        "version": current["version"],
                        "dep_type": dep_type,
                        "resolved": current.get("resolved", ""),
                        "integrity": current.get("integrity", ""),
                    }

        return list(seen.values())

    @staticmethod
    def _parse_yarn_dep_graph(lock_path: Path, pkg_versions: dict[str, str]) -> list[dict]:
        """Parse the dependency graph from yarn.lock."""
        graph: dict[str, set[str]] = {}

        current_names: list[str] = []
        in_deps = False
        current_deps: list[str] = []

        with open(lock_path) as f:
            for line in f:
                if not line.startswith(" ") and not line.startswith("#") and line.strip():
                    # Finalize previous block
                    if current_names and current_deps:
                        for name in current_names:
                            version = pkg_versions.get(name)
                            if version:
                                ref = f"pkg:npm/{name}@{version}"
                                dep_purls = set()
                                for dep_name in current_deps:
                                    dep_ver = pkg_versions.get(dep_name)
                                    if dep_ver:
                                        dep_purls.add(f"pkg:npm/{dep_name}@{dep_ver}")
                                if dep_purls:
                                    existing = graph.get(ref, set())
                                    graph[ref] = existing | dep_purls

                    current_names = []
                    current_deps = []
                    in_deps = False
                    header = line.rstrip().rstrip(":")
                    for part in header.split(","):
                        part = part.strip().strip('"')
                        if "@" in part:
                            at_idx = part.rfind("@")
                            if at_idx > 0:
                                name = part[:at_idx]
                                if name not in current_names:
                                    current_names.append(name)
                    continue

                stripped = line.strip()
                if stripped == "dependencies:":
                    in_deps = True
                    continue
                elif in_deps and stripped and not stripped.startswith("#"):
                    # "dep-name" "^1.0.0"
                    dep_match = re.match(r'^"?([^"\s]+)"?\s', stripped)
                    if dep_match:
                        current_deps.append(dep_match.group(1))
                    else:
                        in_deps = False

        # Last block
        if current_names and current_deps:
            for name in current_names:
                version = pkg_versions.get(name)
                if version:
                    ref = f"pkg:npm/{name}@{version}"
                    dep_purls = set()
                    for dep_name in current_deps:
                        dep_ver = pkg_versions.get(dep_name)
                        if dep_ver:
                            dep_purls.add(f"pkg:npm/{dep_name}@{dep_ver}")
                    if dep_purls:
                        existing = graph.get(ref, set())
                        graph[ref] = existing | dep_purls

        return [
            {"ref": ref, "dependsOn": sorted(deps)}
            for ref, deps in graph.items()
        ]

    # ── npm Registry ──

    def fetch_licenses(self, packages: list[dict], workers: int = 20) -> dict[str, str]:
        # Licenses are populated as a side-effect of _fetch_latest() during fetch_latest_versions()
        return dict(_npm_license_cache)

    @staticmethod
    def _fetch_latest(name: str, retries: int = 3) -> str | None:
        url = f"https://registry.npmjs.org/{name}/latest"
        for attempt in range(retries):
            req = Request(url, headers={"Accept": "application/json"})
            try:
                with urlopen(req, timeout=10) as resp:
                    data = json.loads(resp.read())
                    # Cache license for later
                    lic = data.get("license", "")
                    if lic and isinstance(lic, str):
                        _npm_license_cache[name] = lic
                    return data.get("version")
            except HTTPError as e:
                if e.code == 429 and attempt < retries - 1:
                    import time
                    time.sleep(2 ** attempt)
                    continue
                return None
            except (URLError, json.JSONDecodeError, TimeoutError):
                return None
        return None
