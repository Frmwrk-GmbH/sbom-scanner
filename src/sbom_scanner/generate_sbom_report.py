#!/usr/bin/env python3
"""
Generic report generator from CycloneDX SBOM.

Auto-detects all ecosystems in the SBOM and produces a report with
CVE scan results, outdated packages, and complete package lists.

Usage:
    python3 generate_sbom_report.py                              # HTML
    python3 generate_sbom_report.py --format pdf                  # PDF
    python3 generate_sbom_report.py --sbom other.json             # different SBOM
    python3 generate_sbom_report.py --skip-cve                    # without CVE scan
    python3 generate_sbom_report.py --config sbom.config.yaml     # with config
    python3 generate_sbom_report.py --project-dir ../my-app       # different project
    python3 generate_sbom_report.py --format json                 # JSON report
    python3 generate_sbom_report.py --format csv                  # CSV report
"""

import argparse
import json
import sys
from pathlib import Path

from .i18n import _

# ── Backward-compatible re-exports ───────────────────────────────────────────
from .report_data import (  # noqa: F401
    load_sbom,
    get_prop,
    severity_order,
    version_distance,
    run_scanners,
    run_grype,
)


def generate_html(sbom: dict, vulns: list[dict], *, simple: bool = False) -> str:
    """Backward-compatible wrapper — delegates to the appropriate renderer."""
    if simple:
        from .renderers.simple_html import SimpleHtmlRenderer
        renderer = SimpleHtmlRenderer()
    else:
        from .renderers.html import HtmlRenderer
        renderer = HtmlRenderer()
    return renderer._generate_html(sbom, vulns)


# ── Config ───────────────────────────────────────────────────────────────────

def load_config(config_path: Path) -> dict:
    if not config_path.exists():
        return {}
    try:
        import yaml
    except ImportError:
        if config_path.suffix == ".json":
            with open(config_path) as f:
                return json.load(f)
        return {}
    with open(config_path) as f:
        return yaml.safe_load(f) or {}


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description=_("SBOM Scanner — HTML/PDF Report") + " | \u00a9 2026 Frmwrk GmbH")
    parser.add_argument("--sbom", help=_("Path to SBOM (default: from config or sbom.cyclonedx.json)"))
    parser.add_argument("--output", help=_("Output path (default: from config or sbom-report.html)"))
    parser.add_argument("--config", default="sbom.config.yaml", help=_("Configuration file"))
    parser.add_argument("--project-dir", default=".", help=_("Project directory"))
    parser.add_argument("--format", default="html", dest="fmt",
                        help="Output format (html, simple-html, pdf, json, csv)")
    parser.add_argument("--skip-cve", action="store_true", help=_("Skip CVE scan"))
    parser.add_argument("--lang", default=None, help="Language (en, de)")
    # Backward compat aliases
    parser.add_argument("--pdf", action="store_true", help="Alias for --format pdf")
    parser.add_argument("--simple", action="store_true", help="Alias for --format simple-html")
    args = parser.parse_args()

    # Format aliases
    fmt = args.fmt
    if args.pdf:
        fmt = "pdf"
    if args.simple:
        fmt = "simple-html"

    project_dir = Path(args.project_dir).resolve()

    # Load config
    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = project_dir / args.config
    config = load_config(config_path)

    output_config = config.get("output", {})
    options = config.get("options", {})

    sbom_path = Path(args.sbom or output_config.get("sbom", "sbom.cyclonedx.json"))
    if not sbom_path.is_absolute():
        sbom_path = project_dir / sbom_path

    if not sbom_path.exists():
        print(f"Fehler: SBOM nicht gefunden: {sbom_path}", file=sys.stderr)
        print("Run `sbom scan` first.", file=sys.stderr)
        sys.exit(1)

    sbom = load_sbom(sbom_path)

    skip_cve = args.skip_cve or options.get("skip_cve", False)

    # CVE-Scan
    vulns = []
    if not skip_cve:
        lockfiles = []
        try:
            from .ecosystems import REGISTRY
            sources_config = config.get("sources", {})
            for eco in REGISTRY:
                raw = sources_config.get(eco.name)
                eco_configs = [raw] if isinstance(raw, dict) else (raw or [{}])
                for eco_config in eco_configs:
                    lockfiles.extend(eco.get_osv_lockfiles(project_dir, eco_config))
        except ImportError:
            pass

        vulns = run_scanners(sbom_path, lockfiles, project_dir)

    # Get renderer
    from .renderers import get_renderer
    renderer = get_renderer(fmt)
    if not renderer:
        print(f"Unknown format: {fmt}", file=sys.stderr)
        sys.exit(1)

    # Determine output path
    default_output = output_config.get("report", f"sbom-report{renderer.file_extension}")
    output_path = Path(args.output or default_output)
    if not output_path.is_absolute():
        output_path = project_dir / output_path

    # Render
    result = renderer.render(sbom, vulns, output_path)
    print(_("Report: {}").format(result))


if __name__ == "__main__":
    main()
