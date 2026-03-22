"""C#/NuGet ecosystem (.sln, .csproj, packages.config)."""

from __future__ import annotations

import json
import re
import sys
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

from .base import Ecosystem

_PRERELEASE_RE = re.compile(r"-(alpha|beta|rc|preview|dev|pre)", re.IGNORECASE)

# .sln project line: Project("{GUID}") = "Name", "Path\To\Project.csproj", "{GUID}"
_SLN_PROJECT_RE = re.compile(
    r'Project\(".*?"\)\s*=\s*"(.*?)",\s*"(.*?\.csproj)"', re.IGNORECASE
)


class NugetEcosystem(Ecosystem):
    name = "nuget"
    display_name = "C#/NuGet"
    cdx_prefix = "cdx:nuget"
    purl_type = "nuget"
    package_url_template = "https://www.nuget.org/packages/{name}"
    dep_property = "cdx:nuget:dependency"
    latest_property = "cdx:nuget:latestVersion"
    dep_labels = {"direct": "direct", "transitive": "transitive"}
    has_group_column = False
    module_property = "cdx:nuget:project"

    def scan_pattern(self) -> dict | None:
        return {
            "detect_files": ["*.sln"],
            "companion_files": [],
            "config_keys": {"*.sln": "solution"},
            "icon": "🔷",
        }

    def config_options(self) -> list[dict]:
        return [
            {"key": "include_dev", "label": "Include test projects", "type": "bool", "default": True,
             "description": "Include test project dependencies in the scan"},
            {"key": "include_transitive", "label": "Include transitive deps", "type": "bool", "default": True,
             "description": "Include transitive dependencies (from project.assets.json)"},
        ]

    def read_project_info(self, project_dir: Path) -> tuple[str, str] | None:
        # Try .sln name
        for sln in project_dir.glob("*.sln"):
            name = sln.stem
            # Try to find version from first .csproj
            for csproj in project_dir.rglob("*.csproj"):
                version = self._read_csproj_version(csproj)
                if version:
                    return name, version
            return name, "0.0.0"
        return None

    def detect(self, project_dir: Path, config: dict) -> bool:
        # Explicit solution path
        sln = config.get("solution")
        if sln:
            sln_path = project_dir / sln
            return sln_path.exists()
        # Auto-detect: any .sln or .csproj
        if list(project_dir.glob("*.sln")):
            return True
        if list(project_dir.glob("*.csproj")):
            return True
        if (project_dir / "packages.config").exists():
            return True
        return False

    def parse(self, project_dir: Path, config: dict) -> list[dict]:
        include_dev = config.get("include_dev", True)
        include_transitive = config.get("include_transitive", True)

        # Discover projects
        projects = self._discover_projects(project_dir, config)
        if not projects:
            return []

        all_deps: dict[str, dict] = {}  # name -> pkg dict (deduplicated)

        for proj_name, csproj_path in projects:
            is_test = "test" in proj_name.lower()
            if is_test and not include_dev:
                continue

            # Parse direct deps from .csproj
            direct_deps = self._parse_csproj(csproj_path)

            # Parse transitive deps from project.assets.json
            transitive_deps = []
            if include_transitive:
                assets_path = csproj_path.parent / "obj" / "project.assets.json"
                if assets_path.exists():
                    transitive_deps = self._parse_assets_json(assets_path, direct_deps)

            # Legacy: packages.config
            pkg_config = csproj_path.parent / "packages.config"
            if pkg_config.exists() and not direct_deps:
                direct_deps = self._parse_packages_config(pkg_config)

            # Merge into all_deps
            direct_names = {d["name"].lower() for d in direct_deps}
            for dep in direct_deps:
                key = dep["name"].lower()
                if key not in all_deps:
                    dep["dep_type"] = "direct"
                    dep["module"] = proj_name
                    all_deps[key] = dep
                else:
                    existing = all_deps[key]
                    if proj_name not in existing.get("module", ""):
                        existing["module"] = f"{existing['module']}, {proj_name}"
                    if existing["dep_type"] != "direct":
                        existing["dep_type"] = "direct"

            for dep in transitive_deps:
                key = dep["name"].lower()
                if key not in all_deps:
                    dep["dep_type"] = "transitive"
                    dep["module"] = proj_name
                    all_deps[key] = dep
                elif proj_name not in all_deps[key].get("module", ""):
                    all_deps[key]["module"] = f"{all_deps[key]['module']}, {proj_name}"

        return list(all_deps.values())

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
                    print(f"  NuGet versions: {done}/{len(unique)} ...")
                key, version = future.result()
                if version:
                    results[key] = version

        return results

    def build_component(self, pkg: dict, latest: str | None) -> dict:
        name = pkg["name"]
        version = pkg["version"]
        purl = f"pkg:nuget/{name}@{version}"
        dep_type = pkg.get("dep_type", "transitive")
        module = pkg.get("module", "")

        properties = [
            {"name": "cdx:ecosystem", "value": "nuget"},
            {"name": "cdx:nuget:dependency", "value": dep_type},
        ]
        if module:
            properties.append({"name": "cdx:nuget:project", "value": module})
        if latest:
            properties.append({"name": "cdx:nuget:latestVersion", "value": latest})

        return {
            "type": "library",
            "group": "nuget",
            "name": name,
            "version": version,
            "scope": "required",
            "purl": purl,
            "bom-ref": purl,
            "externalReferences": [
                {"type": "distribution", "url": f"https://www.nuget.org/packages/{name}/{version}"}
            ],
            "properties": properties,
        }

    def get_direct_purls(self, packages: list[dict]) -> list[str]:
        return [
            f"pkg:nuget/{p['name']}@{p['version']}"
            for p in packages if p.get("dep_type") == "direct"
        ]

    def parse_dependency_graph(self, project_dir: Path, config: dict, packages: list[dict]) -> list[dict]:
        """Build dependency graph from project.assets.json files."""
        projects = self._discover_projects(project_dir, config)
        known = {p["name"].lower(): p["version"] for p in packages}
        graph: dict[str, set[str]] = {}

        for proj_name, csproj_path in projects:
            assets_path = csproj_path.parent / "obj" / "project.assets.json"
            if not assets_path.exists():
                continue

            try:
                with open(assets_path) as f:
                    assets = json.load(f)
            except (json.JSONDecodeError, OSError):
                continue

            targets = assets.get("targets", {})
            for framework, libs in targets.items():
                for lib_key, lib_info in libs.items():
                    if lib_info.get("type") != "package":
                        continue
                    parts = lib_key.split("/")
                    if len(parts) != 2:
                        continue
                    name, version = parts
                    if name.lower() not in known:
                        continue

                    ref = f"pkg:nuget/{name}@{version}"
                    deps = lib_info.get("dependencies", {})
                    depends_on = set()
                    for dep_name, dep_ver_range in deps.items():
                        dep_version = known.get(dep_name.lower(), "")
                        if dep_version:
                            depends_on.add(f"pkg:nuget/{dep_name}@{dep_version}")

                    if depends_on:
                        existing = graph.get(ref, set())
                        graph[ref] = existing | depends_on

        return [
            {"ref": ref, "dependsOn": sorted(deps)}
            for ref, deps in graph.items()
        ]

    def get_osv_lockfiles(self, project_dir: Path, config: dict) -> list[tuple[str, Path]]:
        lockfiles = []
        projects = self._discover_projects(project_dir, config)
        for proj_name, csproj_path in projects:
            # packages.lock.json (NuGet lock file, if enabled)
            lock = csproj_path.parent / "packages.lock.json"
            if lock.exists():
                lockfiles.append(("packages.lock.json", lock))
        return lockfiles

    # ── Project discovery ──

    def _discover_projects(self, project_dir: Path, config: dict) -> list[tuple[str, Path]]:
        """Discover all .csproj files. Returns [(project_name, csproj_path), ...]."""
        # Explicit solution
        sln = config.get("solution")
        if sln:
            sln_path = project_dir / sln
            if sln_path.exists():
                return self._parse_sln(sln_path)

        # Auto-detect .sln
        for sln_path in sorted(project_dir.glob("*.sln")):
            projects = self._parse_sln(sln_path)
            if projects:
                return projects

        # Fallback: find all .csproj
        projects = []
        for csproj in sorted(project_dir.rglob("*.csproj")):
            # Skip obj/bin directories
            if "obj" in csproj.parts or "bin" in csproj.parts:
                continue
            projects.append((csproj.stem, csproj))
        return projects

    @staticmethod
    def _parse_sln(sln_path: Path) -> list[tuple[str, Path]]:
        """Parse .sln file to discover project references."""
        projects = []
        sln_dir = sln_path.parent
        with open(sln_path, encoding="utf-8-sig") as f:
            for line in f:
                m = _SLN_PROJECT_RE.search(line)
                if m:
                    proj_name = m.group(1)
                    # Normalize path separators
                    proj_rel = m.group(2).replace("\\", "/")
                    proj_path = (sln_dir / proj_rel).resolve()
                    if proj_path.exists():
                        projects.append((proj_name, proj_path))
        return projects

    # ── .csproj parsing ──

    @staticmethod
    def _parse_csproj(csproj_path: Path) -> list[dict]:
        """Parse PackageReference entries from a .csproj file."""
        packages = []
        try:
            tree = ET.parse(csproj_path)
            root = tree.getroot()
            # Handle MSBuild namespace
            ns = ""
            if root.tag.startswith("{"):
                ns = root.tag.split("}")[0] + "}"

            for ref in root.iter(f"{ns}PackageReference"):
                name = ref.get("Include") or ref.get("include") or ""
                version = ref.get("Version") or ref.get("version") or ""
                # Version can also be a child element
                if not version:
                    ver_el = ref.find(f"{ns}Version")
                    if ver_el is not None and ver_el.text:
                        version = ver_el.text

                if name:
                    # Clean version (remove wildcards like 8.*)
                    version = version.rstrip("*").rstrip(".")
                    packages.append({"name": name, "version": version or "0.0.0"})
        except ET.ParseError:
            pass
        return packages

    @staticmethod
    def _read_csproj_version(csproj_path: Path) -> str:
        """Try to read <Version> or <PackageVersion> from a .csproj."""
        try:
            tree = ET.parse(csproj_path)
            root = tree.getroot()
            ns = ""
            if root.tag.startswith("{"):
                ns = root.tag.split("}")[0] + "}"
            for tag in [f"{ns}Version", f"{ns}PackageVersion", f"{ns}AssemblyVersion"]:
                el = root.find(f".//{tag}")
                if el is not None and el.text:
                    return el.text
        except ET.ParseError:
            pass
        return ""

    # ── project.assets.json parsing ──

    @staticmethod
    def _parse_assets_json(assets_path: Path, direct_deps: list[dict]) -> list[dict]:
        """Parse transitive deps from project.assets.json."""
        direct_names = {d["name"].lower() for d in direct_deps}
        transitive = []
        try:
            with open(assets_path) as f:
                assets = json.load(f)

            # Use first target framework
            targets = assets.get("targets", {})
            if not targets:
                return []
            framework = next(iter(targets))
            libs = targets[framework]

            for lib_key, lib_info in libs.items():
                if lib_info.get("type") != "package":
                    continue
                parts = lib_key.split("/")
                if len(parts) != 2:
                    continue
                name, version = parts
                if name.lower() in direct_names:
                    continue  # Already parsed as direct
                transitive.append({"name": name, "version": version})
        except (json.JSONDecodeError, OSError):
            pass
        return transitive

    # ── packages.config parsing (legacy) ──

    @staticmethod
    def _parse_packages_config(path: Path) -> list[dict]:
        """Parse legacy packages.config XML."""
        packages = []
        try:
            tree = ET.parse(path)
            for pkg in tree.findall(".//package"):
                name = pkg.get("id", "")
                version = pkg.get("version", "")
                if name:
                    packages.append({"name": name, "version": version or "0.0.0"})
        except ET.ParseError:
            pass
        return packages

    # ── NuGet registry ──

    @staticmethod
    def _fetch_latest(name: str) -> str | None:
        """Fetch the latest stable version from nuget.org."""
        url = f"https://api.nuget.org/v3-flatcontainer/{name.lower()}/index.json"
        req = Request(url, headers={"Accept": "application/json"})
        try:
            with urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
                versions = data.get("versions", [])
                # Find latest stable (no prerelease)
                for v in reversed(versions):
                    if not _PRERELEASE_RE.search(v):
                        return v
                if versions:
                    return versions[-1]
        except (URLError, json.JSONDecodeError, TimeoutError):
            pass
        return None
