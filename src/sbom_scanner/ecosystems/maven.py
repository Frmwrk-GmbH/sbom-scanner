"""Maven/Gradle ecosystem (Gradle dependencies or gradle-dependencies.json)."""

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

_PRERELEASE_RE = re.compile(
    r"(alpha|beta|rc|cr|preview|dev|eap|snapshot|incubating|m\d)", re.IGNORECASE
)

_GOOGLE_GROUPS = {"androidx.", "com.google.", "com.android."}

# Gradle dependency tree line: "+--- group:name:version" oder "\--- group:name:version"
_GRADLE_DEP_RE = re.compile(
    r"^[\s|+\\-]+\s*(\S+):(\S+):(\S+?)(?:\s.*)?$"
)


class MavenEcosystem(Ecosystem):
    name = "maven"
    display_name = "Maven/Gradle"
    cdx_prefix = "cdx:maven"
    package_url_template = "https://search.maven.org/artifact/{group}/{name}"
    dep_property = "cdx:maven:dependency"
    latest_property = "cdx:maven:latestVersion"
    dep_labels = {
        "direct": "direct",
        "transitive": "transitiv",
    }
    has_group_column = True
    purl_type = "maven"
    module_property = "cdx:maven:module"

    def scan_pattern(self) -> dict | None:
        return {
            "detect_files": ["gradle-dependencies.json"],
            "companion_files": [],
            "config_keys": {"gradle-dependencies.json": "deps_file"},
            "detect_dir_marker": "gradlew",
            "config_dir_key": "gradle_dir",
            "icon": "☕",
        }

    def config_options(self) -> list[dict]:
        return [
            {"key": "configurations", "label": "Gradle configurations", "type": "multi-select",
             "default": ["runtimeClasspath"],
             "choices": ["runtimeClasspath", "compileClasspath", "testRuntimeClasspath", "testCompileClasspath"],
             "description": "Which Gradle configurations to scan"},
            {"key": "include_subprojects", "label": "Include subprojects", "type": "bool", "default": True,
             "description": "Scan Gradle subprojects"},
        ]

    def detect(self, project_dir: Path, config: dict) -> bool:
        gradle_dir = project_dir / config.get("gradle_dir", ".")
        # Supports: build.gradle, build.gradle.kts, gradle-dependencies.json
        for f in ["build.gradle", "build.gradle.kts", "gradle-dependencies.json"]:
            if (gradle_dir / f).exists():
                # gradlew must be reachable somewhere up the directory tree
                if f == "gradle-dependencies.json":
                    return True
                gradlew = self._find_gradlew(gradle_dir)
                return gradlew is not None
        # Legacy: android_dir Config
        android_dir = project_dir / config.get("android_dir", "android")
        if android_dir != gradle_dir:
            return (android_dir / "gradle-dependencies.json").exists() or (android_dir / "gradlew").exists()
        return False

    def parse(self, project_dir: Path, config: dict) -> list[dict]:
        # gradle_dir takes precedence over android_dir (legacy)
        if "gradle_dir" in config:
            gradle_dir = project_dir / config["gradle_dir"]
        elif "android_dir" in config:
            gradle_dir = project_dir / config["android_dir"]
        else:
            # Auto-detect: build.gradle in root or android/
            if (project_dir / "build.gradle").exists() or (project_dir / "build.gradle.kts").exists():
                gradle_dir = project_dir
            else:
                gradle_dir = project_dir / "android"

        configurations = config.get("configurations", [config.get("configuration", "runtimeClasspath")])
        if isinstance(configurations, str):
            configurations = [configurations]
        include_subprojects = config.get("include_subprojects", True)

        all_packages: dict[str, dict] = {}
        for configuration in configurations:
            deps = self._get_gradle_dependencies(gradle_dir, configuration, include_subprojects=include_subprojects)
            for dep in deps:
                key = f"{dep['group']}:{dep['name']}"
                if key not in all_packages:
                    all_packages[key] = dep
                else:
                    existing = all_packages[key]
                    if dep.get("dep_type") == "direct" and existing.get("dep_type") != "direct":
                        existing["dep_type"] = "direct"

        return list(all_packages.values())

    def fetch_latest_versions(self, packages: list[dict], workers: int = 20) -> dict[str, str]:
        results: dict[str, str] = {}

        def lookup(dep: dict) -> tuple[str, str | None]:
            key = f"{dep['group']}:{dep['name']}"
            group, name = dep["group"], dep["name"]

            if any(group.startswith(prefix) for prefix in _GOOGLE_GROUPS):
                version = self._fetch_google_maven_latest(group, name)
                if version:
                    return key, version

            return key, self._fetch_maven_central_latest(group, name)

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(lookup, dep): dep for dep in packages}
            done = 0
            for future in as_completed(futures):
                done += 1
                if done % 25 == 0:
                    print(_("  Maven versions: {}/{} ...").format(done, len(packages)))
                key, version = future.result()
                if version:
                    results[key] = version

        return results

    def build_component(self, pkg: dict, latest: str | None) -> dict:
        group = pkg["group"]
        name = pkg["name"]
        version = pkg["version"]
        dep_type = pkg.get("dep_type", "transitive")
        purl = f"pkg:maven/{group}/{name}@{version}"

        module = pkg.get("module", "")

        properties = [
            {"name": "cdx:ecosystem", "value": "maven"},
            {"name": "cdx:maven:dependency", "value": dep_type},
        ]
        if module:
            properties.append({"name": "cdx:maven:module", "value": module})
        if latest:
            properties.append({"name": "cdx:maven:latestVersion", "value": latest})

        return {
            "type": "library",
            "group": group,
            "name": name,
            "version": version,
            "scope": "required",
            "purl": purl,
            "bom-ref": purl,
            "externalReferences": [
                {"type": "distribution", "url": f"https://search.maven.org/artifact/{group}/{name}/{version}/jar"}
            ],
            "properties": properties,
        }

    def get_direct_purls(self, packages: list[dict]) -> list[str]:
        return [
            f"pkg:maven/{p['group']}/{p['name']}@{p['version']}"
            for p in packages if p.get("dep_type") == "direct"
        ]

    def parse_dependency_graph(self, project_dir: Path, config: dict, packages: list[dict]) -> list[dict]:
        """Parse the Gradle dependency tree."""
        if "gradle_dir" in config:
            gradle_dir = project_dir / config["gradle_dir"]
        elif "android_dir" in config:
            gradle_dir = project_dir / config["android_dir"]
        elif (project_dir / "build.gradle").exists() or (project_dir / "build.gradle.kts").exists():
            gradle_dir = project_dir
        else:
            gradle_dir = project_dir / "android"

        configuration = config.get("configuration", "runtimeClasspath")
        return self._parse_gradle_tree(gradle_dir, configuration, packages)

    def package_key(self, pkg: dict) -> str:
        return f"{pkg['group']}:{pkg['name']}"

    @staticmethod
    def _find_gradlew(start_dir: Path) -> Path | None:
        """Search for gradlew in the directory and upward."""
        current = start_dir.resolve()
        for _ in range(10):
            gradlew = current / "gradlew"
            if gradlew.exists():
                return gradlew
            parent = current.parent
            if parent == current:
                break
            current = parent
        return None

    @classmethod
    def _get_gradle_dependencies(cls, gradle_dir: Path, configuration: str = "runtimeClasspath",
                                 include_subprojects: bool = True) -> list[dict]:
        # 1. Pre-existing JSON file (custom Gradle task)
        deps_file = gradle_dir / "gradle-dependencies.json"
        if deps_file.exists():
            with open(deps_file) as f:
                return json.load(f)

        # 2. Standard Gradle dependencies task
        gradlew = cls._find_gradlew(gradle_dir)
        if not gradlew:
            print(_("Warning: no gradlew found, skipping Gradle dependencies"), file=sys.stderr)
            return []

        # Discover subprojects
        tasks = [":dependencies"]  # Root
        if include_subprojects:
            subprojects = cls._get_gradle_subprojects(gradlew, gradle_dir)
            for sp in subprojects:
                tasks.append(f":{sp}:dependencies")

        all_deps: dict[str, dict] = {}  # key -> dep dict (dedupliziert)

        for task in tasks:
            module = task.replace(":dependencies", "").lstrip(":") or "root"
            try:
                print(f"  Gradle :{module} ({configuration}) ...")
                result = subprocess.run(
                    [str(gradlew), task, "--configuration", configuration],
                    capture_output=True, text=True, cwd=gradle_dir, timeout=300,
                )
                if result.returncode != 0:
                    continue

                for dep in cls._parse_gradle_text_output(result.stdout):
                    key = f"{dep['group']}:{dep['name']}"
                    if key not in all_deps:
                        dep["module"] = module
                        all_deps[key] = dep
                    else:
                        existing = all_deps[key]
                        # Module ergänzen
                        existing_modules = existing.get("module", "root")
                        if module not in existing_modules:
                            existing["module"] = f"{existing_modules}, {module}"
                        # direct beats transitive
                        if dep["dep_type"] == "direct" and existing["dep_type"] != "direct":
                            existing["dep_type"] = "direct"

            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue

        if not all_deps:
            print(_("Warning: No Gradle dependencies found"), file=sys.stderr)

        return list(all_deps.values())

    @staticmethod
    def _get_gradle_subprojects(gradlew: Path, gradle_dir: Path) -> list[str]:
        """Discover all Gradle subprojects."""
        try:
            result = subprocess.run(
                [str(gradlew), "projects", "-q"],
                capture_output=True, text=True, cwd=gradle_dir, timeout=60,
            )
            projects = []
            for line in result.stdout.splitlines():
                m = re.match(r"^[+\\|]\s*---\s*Project\s+['\"]:([\w:.-]+)['\"]", line)
                if m:
                    projects.append(m.group(1))
            return projects
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

    @staticmethod
    def _parse_gradle_text_output(output: str) -> list[dict]:
        """Parse the text output of `gradle dependencies`."""
        seen: dict[str, dict] = {}  # "group:name" -> dep dict
        in_tree = False
        first_level_deps: set[str] = set()

        for line in output.splitlines():
            # Detect dependency blocks (after "--- configuration" header)
            if line.strip().startswith("+---") or line.strip().startswith("\\---"):
                in_tree = True

            if not in_tree:
                continue

            # Empty line = end of block
            if not line.strip():
                in_tree = False
                continue

            m = _GRADLE_DEP_RE.match(line)
            if not m:
                continue

            group, name, version = m.group(1), m.group(2), m.group(3)

            # Version bereinigen: "1.9.0 -> 1.9.1" (Gradle conflict resolution)
            if " -> " in version:
                version = version.split(" -> ")[-1]
            # "(c)" oder "(*)" entfernen
            version = version.rstrip("(*)").strip()

            key = f"{group}:{name}"
            if key in seen:
                continue

            # Indentation depth: direct = line starts with +--- or \---
            is_direct = line.startswith("+---") or line.startswith("\\---")

            if is_direct:
                first_level_deps.add(key)

            seen[key] = {
                "group": group,
                "name": name,
                "version": version,
                "dep_type": "direct" if is_direct else "transitive",
            }

        return list(seen.values())

    @classmethod
    def _parse_gradle_tree(cls, gradle_dir: Path, configuration: str,
                           packages: list[dict]) -> list[dict]:
        """Parse the Gradle dependency tree for all subprojects."""
        gradlew = cls._find_gradlew(gradle_dir)
        if not gradlew:
            return []

        subprojects = cls._get_gradle_subprojects(gradlew, gradle_dir)
        tasks = [":dependencies"]
        for sp in subprojects:
            tasks.append(f":{sp}:dependencies")

        known = {f"{p['group']}:{p['name']}": p["version"] for p in packages}
        graph: dict[str, set[str]] = {}

        for task in tasks:
            try:
                result = subprocess.run(
                    [str(gradlew), task, "--configuration", configuration],
                    capture_output=True, text=True, cwd=gradle_dir, timeout=300,
                )
                if result.returncode != 0:
                    continue
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue

            module = task.replace(":dependencies", "").lstrip(":") or "root"
            # Use module name as virtual parent for top-level deps
            module_purl = f"pkg:maven/_module/{module}@0"
            cls._parse_tree_output(result.stdout, known, graph, top_level_parent=module_purl)

        return [
            {"ref": ref, "dependsOn": sorted(deps)}
            for ref, deps in graph.items()
        ]

    @staticmethod
    def _parse_tree_output(output: str, known: dict[str, str],
                           graph: dict[str, set[str]],
                           top_level_parent: str | None = None) -> None:
        """Parse a single Gradle dependency-tree output into the graph.

        Args:
            top_level_parent: PURL to assign top-level deps to (e.g. app PURL).
                              If None, top-level deps are not assigned.
        """
        stack: list[tuple[int, str]] = []

        for line in output.splitlines():
            m = _GRADLE_DEP_RE.match(line)
            if not m:
                continue

            group, name, version = m.group(1), m.group(2), m.group(3)
            omitted = "(*)" in line
            if " -> " in version:
                version = version.split(" -> ")[-1]
            version = version.rstrip("(*)").strip()

            key = f"{group}:{name}"
            actual_version = known.get(key, version)
            purl = f"pkg:maven/{group}/{name}@{actual_version}"

            indent = len(line) - len(line.lstrip())

            while stack and stack[-1][0] >= indent:
                stack.pop()

            if stack:
                parent_purl = stack[-1][1]
                graph.setdefault(parent_purl, set()).add(purl)
            elif top_level_parent:
                # Top-level dep -> register as child of root package
                graph.setdefault(top_level_parent, set()).add(purl)

            if not omitted:
                stack.append((indent, purl))

    @staticmethod
    def _fetch_maven_central_latest(group: str, name: str) -> str | None:
        url = (
            f"https://search.maven.org/solrsearch/select"
            f"?q=g:%22{group}%22+AND+a:%22{name}%22&rows=20&core=gav&wt=json"
        )
        req = Request(url, headers={"Accept": "application/json"})
        try:
            with urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
                docs = data.get("response", {}).get("docs", [])
                for doc in docs:
                    v = doc.get("v", "")
                    if not _PRERELEASE_RE.search(v):
                        return v
                if docs:
                    return docs[0].get("v")
        except (URLError, json.JSONDecodeError, TimeoutError):
            pass
        return None

    @staticmethod
    def _fetch_google_maven_latest(group: str, name: str) -> str | None:
        group_path = group.replace(".", "/")
        url = f"https://dl.google.com/dl/android/maven2/{group_path}/{name}/maven-metadata.xml"
        req = Request(url)
        try:
            with urlopen(req, timeout=10) as resp:
                xml = resp.read().decode()
                versions = re.findall(r"<version>([^<]+)</version>", xml)
                for v in reversed(versions):
                    if not _PRERELEASE_RE.search(v):
                        return v
                if versions:
                    return versions[-1]
        except (URLError, TimeoutError):
            pass
        return None
