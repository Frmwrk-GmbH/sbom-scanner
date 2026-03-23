#!/usr/bin/env python3
"""
Generic CycloneDX 1.6 SBOM generator.

Auto-detects ecosystems (npm, PyPI, pub, Maven, Cargo) and produces
a unified SBOM.  No external dependencies required except PyYAML for
configuration and Dart/Flutter.

Usage:
    python3 generate_sbom.py                           # auto-detect, sbom.config.yaml
    python3 generate_sbom.py --config sbom.config.yaml # explicit config
    python3 generate_sbom.py --project-dir ../my-app   # different project directory
"""

import argparse
import json
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import __version__ as SCRIPT_VERSION
from .i18n import _


def load_config(config_path: Path) -> dict:
    """Load YAML configuration from disk."""
    if not config_path.exists():
        return {}
    try:
        import yaml
    except ImportError:
        # Fallback: support JSON config when PyYAML is unavailable
        if config_path.suffix == ".json":
            with open(config_path) as f:
                return json.load(f)
        print(_("Warning: PyYAML not installed, using defaults"), file=sys.stderr)
        return {}
    with open(config_path) as f:
        return yaml.safe_load(f) or {}


def _run_version_script(project_dir: Path, script: str) -> str:
    """Run a version script and return its stdout as version string."""
    script_path = project_dir / script
    try:
        result = subprocess.run(
            [str(script_path)],
            capture_output=True, text=True, cwd=project_dir, timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        pass
    return ""


def generate_sbom(project_dir: Path, config: dict, output_path: Path) -> None:
    # Lazy import so the module can be loaded even without ecosystem packages installed
    from .ecosystems import REGISTRY

    project_config = config.get("project", {})
    sources_config = config.get("sources", {})
    options = config.get("options", {})
    workers = options.get("workers", 20)

    app_name = project_config.get("name", "")
    app_version = project_config.get("version", "")
    app_description = project_config.get("description", "")

    # Auto-detect version: custom script > ecosystem manifest > fallback
    if not app_version:
        version_script = project_config.get("version_script", "")
        if version_script:
            app_version = _run_version_script(project_dir, version_script)
        else:
            # Try well-known script name
            script_path = project_dir / ".sbom-version"
            if script_path.exists():
                app_version = _run_version_script(project_dir, ".sbom-version")

    # Auto-detect name/version from ecosystem manifests
    if not app_name or not app_version:
        for eco in REGISTRY:
            info = eco.read_project_info(project_dir)
            if info:
                if not app_name:
                    app_name = info[0]
                if not app_version:
                    app_version = info[1] or "0.0.0"
                break
    if not app_name:
        app_name = project_dir.name
    if not app_version:
        app_version = "0.0.0"

    # Detect ecosystems — config value can be a dict (single) or a list (multi)
    # If sources section exists in config, only scan listed ecosystems (explicit mode).
    # If no sources section, auto-detect all ecosystems (implicit mode).
    explicit_sources = bool(sources_config)
    active_ecosystems: list[tuple] = []  # (eco, eco_config, label)
    for eco in REGISTRY:
        raw = sources_config.get(eco.name)
        if raw is None:
            if explicit_sources:
                continue  # Not listed in config → skip
            eco_configs = [{}]  # No config → auto-detect
        elif isinstance(raw, list):
            eco_configs = raw
        else:
            eco_configs = [raw]

        for idx, eco_config in enumerate(eco_configs):
            if eco.detect(project_dir, eco_config):
                label = eco_config.get("label", "")
                if not label and len(eco_configs) > 1:
                    # Derive auto-label from first config value that's a path
                    for value in eco_config.values():
                        if isinstance(value, str) and ("/" in value or "." in value):
                            label = str(Path(value).parent)
                            if label == ".":
                                label = value
                            break
                    if not label:
                        label = f"#{idx + 1}"
                active_ecosystems.append((eco, eco_config, label))
                suffix = f" ({label})" if label else ""
                print(_("Detected: {}{}").format(eco.display_name, suffix))

    if not active_ecosystems:
        print(_("Error: No supported ecosystems found in project."), file=sys.stderr)
        print(_("Checked in: {}").format(project_dir), file=sys.stderr)
        print(_("Supported: {}").format(', '.join(e.name for e in REGISTRY)), file=sys.stderr)
        sys.exit(1)

    components = []
    all_direct_purls = []
    all_dep_graph = []
    stats = {}

    for eco, eco_config, label in active_ecosystems:
        suffix = f" ({label})" if label else ""
        print(f"\n--- {eco.display_name}{suffix} ---")

        print(_("Reading {} dependencies ...").format(eco.display_name))
        packages = eco.parse(project_dir, eco_config)
        if not packages:
            print("  " + _("No packages found."))
            continue

        # Fetch latest versions (deduplicated across all instances)
        print(_("Loading latest versions for {} packages ...").format(len(packages)))
        latest_versions = eco.fetch_latest_versions(packages, workers)

        # Fetch licenses if enabled
        fetch_licenses = options.get("fetch_licenses", False)
        licenses: dict[str, str] = {}
        if fetch_licenses:
            print(_("Fetching licenses for {} packages ...").format(len(packages)))
            licenses = eco.fetch_licenses(packages, workers)

        # Tags from config + label + ecosystem name
        tags = list(eco_config.get("tags", []))
        if label:
            tags.append(label)

        # Build components
        outdated_count = 0
        for pkg in packages:
            key = eco.package_key(pkg)
            latest = latest_versions.get(key)
            component = eco.build_component(pkg, latest)
            # Add license if available
            lic = licenses.get(key, "")
            if lic:
                component["licenses"] = [{"license": {"id": lic}}]
            # CycloneDX 1.6 tags (for multiroot filtering in the report)
            if tags:
                component["tags"] = tags
            components.append(component)
            if latest and latest != pkg.get("version"):
                outdated_count += 1

        # Direct dependencies for graph
        all_direct_purls.extend(eco.get_direct_purls(packages))

        # Parse dependency graph (optional)
        dep_graph = eco.parse_dependency_graph(project_dir, eco_config, packages)
        if dep_graph:
            all_dep_graph.extend(dep_graph)

        stats_key = f"{eco.name}:{label}" if label else eco.name
        stats[stats_key] = {
            "total": len(packages),
            "outdated": outdated_count,
            "display_name": f"{eco.display_name}{suffix}",
        }

        print(_("  {} packages, {} outdated").format(len(packages), outdated_count))

    # Assemble SBOM
    app_purl = f"pkg:generic/{app_name}@{app_version}"
    dependencies = [{
        "ref": app_purl,
        "dependsOn": sorted(set(all_direct_purls)),
    }]
    # Deduplicate dep graph (merge same ref from different sources)
    merged_graph: dict[str, set[str]] = {}
    for entry in all_dep_graph:
        ref = entry["ref"]
        merged_graph.setdefault(ref, set()).update(entry["dependsOn"])
    dependencies.extend(
        {"ref": ref, "dependsOn": sorted(deps)}
        for ref, deps in merged_graph.items()
    )

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {
                "components": [{
                    "type": "application",
                    "name": "sbom-scanner",
                    "version": SCRIPT_VERSION,
                }]
            },
            "component": {
                "type": "application",
                "name": app_name,
                "version": app_version,
                "description": app_description,
                "bom-ref": app_purl,
                "purl": app_purl,
            },
        },
        "components": components,
        "dependencies": dependencies,
    }

    with open(output_path, "w") as f:
        json.dump(bom, f, indent=2)
        f.write("\n")

    print(_("\nSBOM generated: {}").format(output_path))
    print(_("  {} packages total:").format(len(components)))
    for name, s in stats.items():
        print(_("    {}: {} ({} outdated)").format(s['display_name'], s['total'], s['outdated']))
    print(_("  Format: CycloneDX 1.6"))


def main():
    parser = argparse.ArgumentParser(description=_("Generic CycloneDX SBOM generator") + " | © 2026 Frmwrk GmbH")
    parser.add_argument("--config", default="sbom.config.yaml", help=_("Configuration file (default: sbom.config.yaml)"))
    parser.add_argument("--project-dir", default=".", help=_("Project directory (default: current directory)"))
    parser.add_argument("--licenses", action="store_true", help=_("Fetch and include license information"))
    parser.add_argument("--lang", default=None, help="Language (en, de)")
    parser.add_argument("--output", help=_("Output path (overrides config)"))
    args = parser.parse_args()

    # Load config
    project_dir = Path(args.project_dir).resolve()
    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = project_dir / args.config

    config = load_config(config_path)

    output_config = config.get("output", {})
    output_path = Path(args.output or output_config.get("sbom", "sbom.cyclonedx.json"))
    if not output_path.is_absolute():
        output_path = project_dir / output_path

    # Merge CLI flags into config options
    if args.licenses:
        config.setdefault("options", {})["fetch_licenses"] = True

    generate_sbom(project_dir, config, output_path)


if __name__ == "__main__":
    main()
