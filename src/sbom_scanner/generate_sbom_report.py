#!/usr/bin/env python3
"""
Generic HTML report generator from CycloneDX SBOM.

Auto-detects all ecosystems in the SBOM and produces a report with
CVE scan results, outdated packages, and complete package lists.

Usage:
    python3 generate_sbom_report.py                              # HTML
    python3 generate_sbom_report.py --pdf                         # HTML + PDF
    python3 generate_sbom_report.py --sbom other.json             # different SBOM
    python3 generate_sbom_report.py --skip-cve                    # without CVE scan
    python3 generate_sbom_report.py --config sbom.config.yaml     # with config
    python3 generate_sbom_report.py --project-dir ../my-app       # different project
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from html import escape
from pathlib import Path

from .i18n import _


_REPORT_CONFIG_CACHE: dict[str, dict] | None = None


def _get_report_config() -> dict[str, dict]:
    """Build report configuration from the ecosystem registry (cached)."""
    global _REPORT_CONFIG_CACHE
    if _REPORT_CONFIG_CACHE is None:
        try:
            from .ecosystems import REGISTRY
            _REPORT_CONFIG_CACHE = {eco.name: eco.report_config() for eco in REGISTRY}
        except ImportError:
            _REPORT_CONFIG_CACHE = {}
    return _REPORT_CONFIG_CACHE


# ── Helpers ──────────────────────────────────────────────────────────────────

def load_sbom(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)


def get_prop(component: dict, name: str) -> str | None:
    for p in component.get("properties", []):
        if p["name"] == name:
            return p["value"]
    return None


def severity_order(sev: str) -> int:
    s = sev.lower() if sev else ""
    if "critical" in s:
        return 0
    if "high" in s:
        return 1
    if "medium" in s:
        return 2
    if "low" in s:
        return 3
    return 4


def _build_dep_lookup(sbom: dict) -> dict[str, list[str]]:
    """Build a lookup: purl -> [dependent purls] from the CycloneDX dependencies section."""
    lookup: dict[str, list[str]] = {}
    for dep in sbom.get("dependencies", []):
        ref = dep.get("ref", "")
        depends_on = dep.get("dependsOn", [])
        if depends_on:
            lookup[ref] = depends_on
    return lookup


def _purl_to_name(purl: str) -> str:
    """Extract 'name@version' from a PURL."""
    # pkg:npm/express@4.18.2 -> express@4.18.2
    if "@" in purl:
        path = purl.split("/", 1)[-1] if "/" in purl else purl
        return path
    return purl


def _is_outdated(purl: str, comp_lookup: dict, eco_configs: dict) -> bool:
    """Check whether a package is outdated."""
    comp = comp_lookup.get(purl)
    if not comp:
        return False
    eco = get_prop(comp, "cdx:ecosystem") or ""
    cfg = eco_configs.get(eco, {})
    latest_prop = cfg.get("latest_prop", "")
    if not latest_prop:
        return False
    latest = get_prop(comp, latest_prop)
    return bool(latest and latest != comp.get("version", ""))


def _count_outdated_deep(purl: str, dep_lookup: dict, comp_lookup: dict,
                         eco_configs: dict, cache: dict,
                         _stack: frozenset | None = None) -> int:
    """Recursively count all unique outdated descendants (cached)."""
    if purl in cache:
        return cache[purl]
    # Cycle protection
    if _stack is None:
        _stack = frozenset()
    if purl in _stack:
        return 0
    _stack = _stack | {purl}

    seen: set[str] = set()  # Count each package only once
    count = 0

    def _walk(p: str) -> None:
        nonlocal count
        for child in dep_lookup.get(p, []):
            if child in seen or child in _stack:
                continue
            seen.add(child)
            if _is_outdated(child, comp_lookup, eco_configs):
                count += 1
            _walk(child)

    _walk(purl)
    cache[purl] = count
    return count


def _tree_node_display(purl: str, comp_lookup: dict, eco_configs: dict,
                       outdated_deep: int = 0) -> str:
    """Build the display HTML for a tree node."""
    name_ver = _purl_to_name(purl)
    name = name_ver.split("@")[0] if "@" in name_ver else name_ver
    version = name_ver.split("@")[1] if "@" in name_ver else ""

    comp = comp_lookup.get(purl)
    if comp:
        refs = comp.get("externalReferences", [])
        url = refs[0]["url"] if refs else ""
        name_html = f'<a href="{url}" target="_blank">{escape(name)}</a>' if url else escape(name)
    else:
        name_html = escape(name)

    parts = [name_html]
    parts.append(f'<span class="tree-ver">{escape(version)}</span>')

    if comp:
        eco = get_prop(comp, "cdx:ecosystem") or ""
        cfg = eco_configs.get(eco, {})
        latest_prop = cfg.get("latest_prop", "")
        latest = get_prop(comp, latest_prop) if latest_prop else None

        if latest and latest != version:
            dist = version_distance(version, latest)
            if dist >= 2:
                badge = f'<span class="badge critical">{dist} Major</span>'
            elif dist == 1:
                badge = '<span class="badge warning">1 Major</span>'
            else:
                badge = '<span class="badge minor">Patch</span>'
            parts.append(f'<span class="tree-latest">→ {escape(latest)}</span>')
            parts.append(badge)
        elif latest:
            parts.append('<span class="badge ok">current</span>')

    # Show outdated descendants count
    if outdated_deep > 0:
        parts.append(f'<span class="tree-warn" title="{outdated_deep} outdated dependencies in subtree">⚠ {outdated_deep}</span>')

    return " ".join(parts)


def _render_tree_node(purl: str, dep_lookup: dict, comp_lookup: dict,
                      eco_configs: dict, visited: set,
                      outdated_cache: dict, rendered: set,
                      depth: int = 0, max_depth: int = 4) -> str:
    """Render a tree node.

    Args:
        rendered: Global set — each package is rendered with its full
                  subtree only once; subsequent occurrences show a reference.
    """
    children = dep_lookup.get(purl, [])
    outdated_deep = _count_outdated_deep(purl, dep_lookup, comp_lookup, eco_configs, outdated_cache)
    display = _tree_node_display(purl, comp_lookup, eco_configs, outdated_deep)

    # Cycle in current path
    if purl in visited:
        return f'<div class="tree-leaf">{display} <span class="dep-type">(cyclic)</span></div>\n'

    # Depth limit
    if depth >= max_depth and children:
        return f'<div class="tree-leaf">{display} <span class="tree-count">{len(children)}</span> <span class="dep-type">(...)</span></div>\n'

    if not children:
        return f'<div class="tree-leaf">{display}</div>\n'

    # Already rendered -> show reference only (prevents exponential growth)
    if purl in rendered:
        return f'<div class="tree-leaf">{display} <span class="tree-count">{len(children)}</span> <span class="dep-type">(see above)</span></div>\n'

    rendered.add(purl)
    visited = visited | {purl}
    open_cls = " open" if outdated_deep > 0 and depth < 2 else ""
    html = f'<div class="tree-node{open_cls}">'
    html += f'<div class="tree-toggle">{display} <span class="tree-count">{len(children)}</span></div>\n'
    html += '<div class="tree-children">\n'
    for child in sorted(children):
        html += _render_tree_node(child, dep_lookup, comp_lookup, eco_configs, visited, outdated_cache, rendered, depth + 1, max_depth)
    html += '</div></div>\n'
    return html


def version_distance(current: str, latest: str) -> int:
    """Major version difference."""
    try:
        c_parts = [int(x) for x in current.split(".")[:3] if x.isdigit()]
        l_parts = [int(x) for x in latest.split(".")[:3] if x.isdigit()]
        if not c_parts or not l_parts:
            return 0
        return l_parts[0] - c_parts[0]
    except (ValueError, IndexError):
        return 0


def _tags_html(component: dict) -> str:
    """Generate HTML spans for CycloneDX tags of a component."""
    tags = component.get("tags", [])
    if not tags:
        return ""
    return " " + " ".join(f'<span class="tag">{escape(t)}</span>' for t in tags)


def _diff_badge(major_diff: int) -> str:
    if major_diff >= 2:
        return f'<span class="badge critical">{major_diff} Major</span>'
    elif major_diff == 1:
        return '<span class="badge warning">1 Major</span>'
    else:
        return '<span class="badge minor">Minor/Patch</span>'


def _status_badge(major_diff: int) -> str:
    if major_diff >= 2:
        return f'<span class="badge critical">{major_diff} Major behind</span>'
    elif major_diff == 1:
        return '<span class="badge warning">1 Major behind</span>'
    else:
        return '<span class="badge minor">Update available</span>'


# ── CVE-Scanning ─────────────────────────────────────────────────────────────

def run_scanners(sbom_path: Path, lockfiles: list[tuple[str, Path]],
                 project_dir: Path) -> list[dict]:
    """Run all registered CVE scanners and deduplicate results."""
    from .scanners import REGISTRY as SCANNER_REGISTRY

    all_vulns: list[dict] = []
    seen_ids: set[str] = set()

    for scanner in SCANNER_REGISTRY:
        print(f"CVE-Scan via {scanner.name} ...")
        try:
            vulns = scanner.scan(sbom_path, lockfiles, project_dir)
        except Exception as e:
            print(f"Warnung: {scanner.name} fehlgeschlagen: {e}", file=sys.stderr)
            continue

        for v in vulns:
            vid = v.get("id", "")
            if vid and vid not in seen_ids:
                all_vulns.append(v)
                seen_ids.add(vid)

    return all_vulns


# Legacy aliases for backwards compatibility and library API
def run_grype(sbom_path: Path) -> list[dict]:
    """Run grype (legacy wrapper)."""
    from .scanners.grype import GrypeScanner
    return GrypeScanner().scan(sbom_path, [], sbom_path.parent)


# ── HTML-Generierung ─────────────────────────────────────────────────────────

CSS = """\
    :root {
        --bg: #ffffff;
        --fg: #1a1a1a;
        --muted: #6b7280;
        --border: #e5e7eb;
        --accent: #2563eb;
        --red: #dc2626;
        --orange: #ea580c;
        --yellow: #ca8a04;
        --green: #16a34a;
        --red-bg: #fef2f2;
        --orange-bg: #fff7ed;
        --yellow-bg: #fefce8;
        --green-bg: #f0fdf4;
        --gray-bg: #f9fafb;
    }
    @media (prefers-color-scheme: dark) {
        :root {
            --bg: #111827;
            --fg: #f3f4f6;
            --muted: #9ca3af;
            --border: #374151;
            --accent: #60a5fa;
            --red: #f87171;
            --orange: #fb923c;
            --yellow: #facc15;
            --green: #4ade80;
            --red-bg: #1c1214;
            --orange-bg: #1c1710;
            --yellow-bg: #1c1b0e;
            --green-bg: #0f1c14;
            --gray-bg: #1f2937;
        }
    }
    @media print {
        :root {
            --bg: #ffffff;
            --fg: #1a1a1a;
            --muted: #6b7280;
            --border: #e5e7eb;
            --accent: #2563eb;
            --red: #dc2626;
            --orange: #ea580c;
            --yellow: #ca8a04;
            --green: #16a34a;
            --red-bg: #fef2f2;
            --orange-bg: #fff7ed;
            --yellow-bg: #fefce8;
            --green-bg: #f0fdf4;
            --gray-bg: #f9fafb;
        }
        body { font-size: 10pt; }
        .no-print { display: none; }
        table { font-size: 9pt; }
        h1 { font-size: 16pt; }
        h2 { font-size: 13pt; }
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        background: var(--bg);
        color: var(--fg);
        line-height: 1.5;
        padding: 2rem;
        max-width: 1200px;
        margin: 0 auto;
    }
    h1 { font-size: 1.5rem; margin-bottom: 0.25rem; }
    h2 {
        font-size: 1.15rem;
        margin: 2rem 0 0.75rem;
        padding-bottom: 0.35rem;
        border-bottom: 2px solid var(--border);
    }
    .subtitle { color: var(--muted); font-size: 0.9rem; margin-bottom: 1.5rem; }
    .stats {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
        gap: 0.75rem;
        margin-bottom: 1.5rem;
    }
    .stat {
        background: var(--gray-bg);
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 0.75rem 1rem;
    }
    .stat-value { font-size: 1.5rem; font-weight: 700; }
    .stat-label { font-size: 0.8rem; color: var(--muted); }
    table {
        width: 100%;
        border-collapse: collapse;
        font-size: 0.85rem;
        margin-bottom: 1rem;
    }
    th, td {
        text-align: left;
        padding: 0.4rem 0.6rem;
        border-bottom: 1px solid var(--border);
    }
    th {
        font-weight: 600;
        background: var(--gray-bg);
        position: sticky;
        top: 0;
    }
    tr:hover { background: var(--gray-bg); }
    .badge {
        display: inline-block;
        padding: 0.15rem 0.5rem;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 600;
    }
    .badge.critical { background: var(--red-bg); color: var(--red); }
    .badge.warning { background: var(--orange-bg); color: var(--orange); }
    .badge.minor { background: var(--yellow-bg); color: var(--yellow); }
    .badge.ok { background: var(--green-bg); color: var(--green); }
    .badge.neutral { background: var(--gray-bg); color: var(--muted); }
    .version-new { font-weight: 600; }
    a { color: var(--accent); text-decoration: none; }
    a:hover { text-decoration: underline; }
    .dep-type { font-size: 0.75rem; color: var(--muted); }
    .tag { display: inline-block; padding: 0.1rem 0.4rem; border-radius: 3px; font-size: 0.7rem; background: var(--border); color: var(--muted); margin-left: 0.3rem; }
    .section-empty { color: var(--muted); font-style: italic; padding: 1rem 0; }
    .toc { margin: 1rem 0; padding: 0.75rem 1rem; background: var(--gray-bg); border-radius: 8px; }
    .toc a { margin-right: 1.5rem; font-size: 0.85rem; }
    .tabs { display: flex; flex-wrap: wrap; gap: 0.25rem; margin: 1.5rem 0 0; border-bottom: 2px solid var(--border); }
    .tab-btn {
        padding: 0.5rem 1rem;
        font-size: 0.85rem;
        font-weight: 600;
        background: none;
        border: none;
        border-bottom: 2px solid transparent;
        margin-bottom: -2px;
        cursor: pointer;
        color: var(--muted);
        font-family: inherit;
        transition: color 0.15s, border-color 0.15s;
    }
    .tab-btn:hover { color: var(--fg); }
    .tab-btn.active { color: var(--accent); border-bottom-color: var(--accent); }
    .tab-btn .tab-count {
        display: inline-block;
        padding: 0.1rem 0.4rem;
        border-radius: 8px;
        font-size: 0.7rem;
        font-weight: 700;
        margin-left: 0.3rem;
        background: var(--gray-bg);
        color: var(--muted);
    }
    .tab-btn.active .tab-count { background: var(--accent); color: var(--bg); }
    .tab-panel { display: none; }
    .tab-panel.active { display: block; }
    @media print {
        .tabs { display: none; }
        .tab-panel { display: block !important; }
        .tab-panel::before {
            content: attr(data-tab-title);
            display: block;
            font-size: 13pt;
            font-weight: 700;
            margin: 1.5rem 0 0.5rem;
            padding-bottom: 0.25rem;
            border-bottom: 2px solid var(--border);
        }
    }
    .search-input {
        width: 100%;
        padding: 0.5rem 0.75rem;
        font-size: 0.85rem;
        font-family: inherit;
        border: 1px solid var(--border);
        border-radius: 6px;
        background: var(--bg);
        color: var(--fg);
        margin: 1rem 0 0.5rem;
        outline: none;
    }
    .search-input:focus { border-color: var(--accent); box-shadow: 0 0 0 2px color-mix(in srgb, var(--accent) 20%, transparent); }
    .filter-bar { display: flex; gap: 0.35rem; margin-bottom: 1rem; }
    .filter-btn {
        padding: 0.3rem 0.7rem;
        font-size: 0.75rem;
        font-weight: 600;
        font-family: inherit;
        border: 1px solid var(--border);
        border-radius: 4px;
        background: var(--bg);
        color: var(--muted);
        cursor: pointer;
        transition: all 0.15s;
    }
    .filter-btn:hover { border-color: var(--accent); color: var(--fg); }
    .filter-btn.active { background: var(--accent); color: var(--bg); border-color: var(--accent); }
    .filter-sep { width: 1px; background: var(--border); margin: 0 0.25rem; }
    .filter-count { font-weight: 400; opacity: 0.7; margin-left: 0.2rem; }
    .match-count { color: var(--muted); font-size: 0.8rem; margin-left: 0.5rem; }
    .tree-node { margin-left: 1rem; border-left: 2px solid var(--border); padding-left: 0.75rem; }
    .tree-toggle { cursor: pointer; padding: 0.35rem 0.5rem; margin: 0 -0.5rem; border-radius: 4px; font-size: 0.85rem; display: flex; align-items: center; gap: 0.4rem; flex-wrap: wrap; user-select: none; }
    .tree-toggle:hover { background: var(--gray-bg); }
    .tree-toggle::before { content: "▶"; color: var(--muted); font-size: 0.55rem; flex-shrink: 0; transition: transform 0.2s ease; }
    .tree-node.open > .tree-toggle::before { transform: rotate(90deg); }
    .tree-children { overflow: hidden; transition: height 0.2s ease, opacity 0.2s ease; opacity: 0; height: 0; }
    .tree-node.open > .tree-children { opacity: 1; }
    .tree-leaf { margin-left: 1rem; padding: 0.35rem 0.5rem; padding-left: 0.75rem; border-left: 2px solid var(--border); font-size: 0.85rem; display: flex; align-items: center; gap: 0.4rem; flex-wrap: wrap; }
    .tree-root { margin-left: 0; border-left: none; padding-left: 0; }
    .tree-root > .tree-toggle { font-weight: 600; font-size: 0.95rem; }
    .tree-ver { color: var(--muted); font-size: 0.8rem; font-family: monospace; }
    .tree-latest { color: var(--muted); font-size: 0.75rem; }
    .tree-count { display: inline-flex; align-items: center; justify-content: center; min-width: 1.2rem; height: 1.2rem; padding: 0 0.3rem; border-radius: 8px; font-size: 0.65rem; font-weight: 700; background: var(--border); color: var(--muted); }
    .tree-warn { font-size: 0.7rem; color: var(--orange); font-weight: 600; }
    .tree-eco-header { font-size: 1rem; font-weight: 600; margin: 0.75rem 0 0.5rem; padding-bottom: 0.25rem; border-bottom: 1px solid var(--border); }
    .subtabs { display: flex; gap: 0.35rem; margin: 1rem 0 0.5rem; flex-wrap: wrap; }
    .subtab-btn {
        padding: 0.35rem 0.8rem;
        font-size: 0.8rem;
        font-weight: 600;
        font-family: inherit;
        border: 1px solid var(--border);
        border-radius: 6px;
        background: var(--bg);
        color: var(--muted);
        cursor: pointer;
        transition: all 0.15s;
    }
    .subtab-btn:hover { border-color: var(--accent); color: var(--fg); }
    .subtab-btn.active { background: var(--accent); color: var(--bg); border-color: var(--accent); }
    .subtab-panel { display: none; }
    .subtab-panel.active { display: block; }
    @media print { .subtabs { display: none; } .subtab-panel { display: block !important; } }
    .tree-search { margin-bottom: 0.75rem; }
    footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); color: var(--muted); font-size: 0.8rem; }
"""


def _classify_components(components: list[dict]) -> dict[str, list[dict]]:
    """Group components by ecosystem, splitting by tag for multiroot setups.

    When an ecosystem has multiple different tags (multiroot),
    each tag gets its own group (e.g. "pypi:backend").
    Without tags or with only one tag, the ecosystem name is used as-is.
    """
    # First group by ecosystem
    eco_groups: dict[str, list[dict]] = {}
    for c in components:
        eco = get_prop(c, "cdx:ecosystem") or "unknown"
        eco_groups.setdefault(eco, []).append(c)

    # If an ecosystem has multiple tags (multiroot) -> split into groups
    groups: dict[str, list[dict]] = {}
    for eco, comps in eco_groups.items():
        tags_in_eco: set[str] = set()
        has_untagged = False
        for c in comps:
            ctags = c.get("tags", [])
            if ctags:
                tags_in_eco.update(ctags)
            else:
                has_untagged = True

        if len(tags_in_eco) > 1:
            # Multiroot — pro Tag eine Gruppe
            for c in comps:
                ctags = c.get("tags", [])
                if ctags:
                    tag = ctags[0]  # Erster Tag = Label
                    key = f"{eco}:{tag}"
                else:
                    key = eco
                groups.setdefault(key, []).append(c)
        else:
            groups[eco] = comps

    return groups


def _get_eco_config(eco_name: str) -> tuple[dict, str]:
    """Return (config, display_name) for an ecosystem key.

    Supports simple keys ("pypi") and multiroot keys ("pypi:subproject").
    """
    base_eco = eco_name.split(":")[0] if ":" in eco_name else eco_name
    tag = eco_name.split(":", 1)[1] if ":" in eco_name else ""
    cfg = _get_report_config().get(base_eco, {})
    display = cfg.get("display_name", base_eco)
    if tag:
        display = f"{display} ({tag})"
    return cfg, display


def _eco_stats(eco_name: str, eco_components: list[dict]) -> dict:
    """Compute statistics for an ecosystem."""
    cfg, _ = _get_eco_config(eco_name)
    latest_prop = cfg.get("latest_prop", "")
    dep_prop = cfg.get("dep_prop", "")

    outdated = [
        c for c in eco_components
        if latest_prop and get_prop(c, latest_prop)
        and get_prop(c, latest_prop) != c["version"]
    ]
    outdated.sort(key=lambda c: (
        -version_distance(c["version"], get_prop(c, latest_prop) or c["version"]),
        c["name"],
    ))

    # Dependency type counts
    dep_counts = {}
    if dep_prop:
        for c in eco_components:
            dt = get_prop(c, dep_prop) or "transitive"
            dep_counts[dt] = dep_counts.get(dt, 0) + 1

    return {
        "total": len(eco_components),
        "outdated": outdated,
        "dep_counts": dep_counts,
    }


def generate_html(sbom: dict, vulns: list[dict], *, simple: bool = False) -> str:
    meta = sbom.get("metadata", {})
    app = meta.get("component", {})
    app_name = app.get("name", "Unknown")
    app_version = app.get("version", "0.0.0")
    timestamp = meta.get("timestamp", "")
    components = sbom.get("components", [])

    # Group by ecosystem
    eco_groups = _classify_components(components)
    eco_stats = {name: _eco_stats(name, comps) for name, comps in eco_groups.items()}

    total_outdated = sum(len(s["outdated"]) for s in eco_stats.values())
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Overall Badge
    if vulns:
        worst = min(severity_order(v.get("severity", "")) for v in vulns)
        if worst <= 1:
            overall_badge = '<span class="badge critical">Vulnerabilities found</span>'
        else:
            overall_badge = '<span class="badge warning">Vulnerabilities found</span>'
    elif total_outdated > len(components) * 0.5:
        overall_badge = '<span class="badge warning">Many outdated packages</span>'
    else:
        overall_badge = '<span class="badge ok">OK</span>'

    # ── HTML Header ──
    html = f"""<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SBOM Report — {escape(app_name)} v{escape(app_version)}</title>
<style>
{CSS}
</style>
</head>
<body>

<h1>{escape(app_name)} — Dependency Report {overall_badge}</h1>
<div class="subtitle">Version {escape(app_version)} | Generated: {now} | SBOM: {escape(timestamp)}</div>
"""

    # ── Summary Stats ──
    html += '<div class="stats" id="summary">\n'
    html += f'    <div class="stat"><div class="stat-value">{len(components)}</div><div class="stat-label">Packages total</div></div>\n'

    for eco_name, stats in eco_stats.items():
        cfg, display = _get_eco_config(eco_name)
        dep_info = ""
        if stats["dep_counts"]:
            dep_labels = cfg.get("dep_labels", {})
            parts = []
            for dt, count in sorted(stats["dep_counts"].items()):
                label = dep_labels.get(dt, dt)
                parts.append(f"{count} {label}")
            dep_info = f" ({', '.join(parts)})"
        html += f'    <div class="stat"><div class="stat-value">{stats["total"]}</div><div class="stat-label">{escape(display)}{dep_info}</div></div>\n'

    html += f'    <div class="stat"><div class="stat-value" style="color: var({"--red" if vulns else "--green"})">{len(vulns)}</div><div class="stat-label">CVEs</div></div>\n'

    outdated_parts = []
    for eco_name, stats in eco_stats.items():
        cfg, display = _get_eco_config(eco_name)
        outdated_parts.append(f"{len(stats['outdated'])} {display}")
    outdated_label = f"Veraltet ({', '.join(outdated_parts)})" if outdated_parts else "Outdated"
    html += f'    <div class="stat"><div class="stat-value" style="color: var({"--orange" if total_outdated else "--green"})">{total_outdated}</div><div class="stat-label">{outdated_label}</div></div>\n'

    # Discontinued — generic check from extra_properties of all ecosystems
    report_cfg = _get_report_config()
    discontinued = []
    for cfg_vals in report_cfg.values():
        disc_prop = cfg_vals.get("extra_props", {}).get("discontinued", "")
        if disc_prop:
            discontinued.extend(c for c in components if get_prop(c, disc_prop) == "true")
    if discontinued:
        html += f'    <div class="stat"><div class="stat-value" style="color: var(--red)">{len(discontinued)}</div><div class="stat-label">Discontinued</div></div>\n'

    html += '</div>\n'

    # Check dependency graph
    dep_lookup = _build_dep_lookup(sbom)
    has_tree = len(dep_lookup) > 1

    # ── Navigation ──
    if simple:
        # Flacher TOC-Stil (kein JS)
        html += '<div class="toc no-print">\n'
        html += '    <a href="#vulns">CVEs</a>\n'
        for eco_name in eco_groups:
            cfg, display = _get_eco_config(eco_name)
            html += f'    <a href="#outdated-{eco_name}">Veraltet ({display})</a>\n'
            html += f'    <a href="#all-{eco_name}">{display}</a>\n'
        html += '</div>\n'
    else:
        # Tabs
        tab_ids = []
        tab_ids.append(("vulns", "CVEs", len(vulns)))
        for eco_name in eco_groups:
            cfg, display = _get_eco_config(eco_name)
            total = eco_stats[eco_name]["total"]
            tab_ids.append((eco_name, display, total))

        if has_tree:
            tab_ids.append(("tree", _("Dependency Tree"), len(dep_lookup)))

        html += '<div class="tabs no-print">\n'
        for i, (tid, label, count) in enumerate(tab_ids):
            active = " active" if i == 0 else ""
            html += f'    <button class="tab-btn{active}" data-tab="{tid}">{escape(label)}<span class="tab-count">{count}</span></button>\n'
        html += '</div>\n'

    # ── CVE Panel ──
    if not simple:
        html += '<div class="tab-panel active" id="tab-vulns" data-tab-title=_("Vulnerabilities (CVEs)")>\n'
    html += '<h2 id="vulns">Vulnerabilities (CVEs)</h2>\n'
    if vulns:
        vulns.sort(key=lambda v: severity_order(v.get("severity", "")))
        if not simple:
            html += '<input type="text" class="search-input" placeholder="Search CVE, package or description..." onkeyup="filterTable(this)">\n'
        html += "<table><thead><tr><th>ID</th><th>Package</th><th>Version</th><th>Severity</th><th>Description</th><th>Fix</th></tr></thead><tbody>\n"
        for v in vulns:
            sev = v.get("severity", "Unknown")
            sev_class = "critical" if severity_order(sev) <= 1 else "warning" if severity_order(sev) == 2 else "minor"
            fix = ", ".join(v.get("fix_versions", [])) or "-"
            vid = v["id"]
            if vid.startswith("CVE-") or vid.startswith("GHSA-"):
                vid_link = f'<a href="https://osv.dev/vulnerability/{vid}" target="_blank">{escape(vid)}</a>'
            else:
                vid_link = escape(vid)
            html += f'<tr><td>{vid_link}</td><td>{escape(v["package"])}</td><td>{escape(v["version"])}</td>'
            html += f'<td><span class="badge {sev_class}">{escape(sev)}</span></td>'
            html += f'<td>{escape(v.get("summary", ""))}</td><td>{escape(fix)}</td></tr>\n'
        html += "</tbody></table>\n"
    else:
        html += '<div class="section-empty">No known vulnerabilities found.</div>\n'
    if not simple:
        html += '</div>\n'

    # ── Per ecosystem ──
    for eco_name, eco_components in eco_groups.items():
        cfg, display = _get_eco_config(eco_name)
        stats = eco_stats[eco_name]

        if not simple:
            html += f'<div class="tab-panel" id="tab-{eco_name}" data-tab-title="{escape(display)}">\n'
        latest_prop = cfg.get("latest_prop", "")
        dep_prop = cfg.get("dep_prop", "")
        dep_labels = cfg.get("dep_labels", {})
        has_group = cfg.get("has_group_column", False)
        extra_props = cfg.get("extra_props", {})

        outdated = stats["outdated"]

        # URL-Generierung
        url_template = cfg.get("url_template", "")

        def make_link(c: dict, with_tags: bool = True) -> str:
            name = c["name"]
            group = c.get("group", "")
            if url_template:
                url = url_template.format(name=name, group=group)
                link = f'<a href="{url}" target="_blank">{escape(name)}</a>'
            else:
                link = escape(name)
            if with_tags:
                link += _tags_html(c)
            return link

        # ── Suchfeld + Filter ──
        if not simple:
            html += f'<input type="text" class="search-input" placeholder="{escape(display)} search..." onkeyup="filterTable(this)">\n'
            html += '<div class="filter-bar no-print">\n'
            html += '    <button class="filter-btn active" data-filter="all">All</button>\n'
            html += '    <button class="filter-btn" data-filter="outdated">Outdated</button>\n'
            html += '    <button class="filter-btn" data-filter="current">Current</button>\n'
            # Dependency-Typ-Filter (nur wenn es dep_types gibt)
            if dep_prop and stats["dep_counts"]:
                html += '    <span class="filter-sep"></span>\n'
                for dt in sorted(stats["dep_counts"]):
                    label = dep_labels.get(dt, dt)
                    count = stats["dep_counts"][dt]
                    html += f'    <button class="filter-btn" data-dep="{escape(dt)}">{escape(label)} <span class="filter-count">{count}</span></button>\n'
            # Modul-Filter (Subprojekte, generisch via module_prop)
            module_prop = cfg.get("module_prop", "")
            module_counts: dict[str, int] = {}
            if module_prop:
                for c in eco_components:
                    mod = get_prop(c, module_prop)
                    if mod:
                        for m in mod.split(", "):
                            module_counts[m] = module_counts.get(m, 0) + 1
            if len(module_counts) > 1:
                html += '    <span class="filter-sep"></span>\n'
                for mod in sorted(module_counts):
                    count = module_counts[mod]
                    html += f'    <button class="filter-btn" data-module="{escape(mod)}">{escape(mod)} <span class="filter-count">{count}</span></button>\n'
            html += '</div>\n'

        # ── Veraltete Packages ──
        html += f'<h2 id="outdated-{eco_name}" class="filterable" data-section="outdated">Outdated {display} packages ({len(outdated)})</h2>\n'
        if outdated:
            headers = "<th>Package</th>"
            if has_group:
                headers = "<th>Group</th><th>Artifact</th>"
            if dep_prop:
                headers += "<th>Typ</th>"

            headers += "<th>Aktuell</th>"

            # Upgradable column (pub-specific, from extra_properties)
            has_upgradable = "upgradable" in extra_props
            if has_upgradable:
                headers += "<th>Upgradable</th>"

            headers += "<th>Latest</th><th>Diff</th>"

            html += f"<table><thead><tr>{headers}</tr></thead><tbody>\n"
            for c in outdated:
                name = c["name"]
                version = c["version"]
                latest = get_prop(c, latest_prop) or "-"
                major_diff = version_distance(version, latest)
                diff_badge = _diff_badge(major_diff)

                # Discontinued-Badge
                disc_badge = ""
                if get_prop(c, extra_props.get("discontinued", "")) == "true":
                    disc_badge = ' <span class="badge critical">discontinued</span>'

                row = ""
                if has_group:
                    row += f"<td>{escape(c.get('group', ''))}</td><td>{make_link(c)}{disc_badge}</td>"
                else:
                    row += f"<td>{make_link(c)}{disc_badge}</td>"

                if dep_prop:
                    dep_type = get_prop(c, dep_prop) or "transitive"
                    dep_short = dep_labels.get(dep_type, dep_type)
                    row += f"<td><span class='dep-type'>{escape(dep_short)}</span></td>"

                row += f"<td>{escape(version)}</td>"

                if has_upgradable:
                    upgradable = get_prop(c, extra_props["upgradable"]) or "-"
                    row += f"<td>{escape(upgradable)}</td>"

                row += f'<td class="version-new">{escape(latest)}</td><td>{diff_badge}</td>'

                attrs = ""
                if dep_prop:
                    dep_val = get_prop(c, dep_prop) or "transitive"
                    attrs += f' data-dep="{escape(dep_val)}"'
                mod_val = get_prop(c, module_prop) if module_prop else None
                if mod_val:
                    attrs += f' data-module="{escape(mod_val)}"'
                html += f"<tr{attrs}>{row}</tr>\n"
            html += "</tbody></table>\n"
        else:
            html += f'<div class="section-empty">All {display} packages are up to date.</div>\n'

        # ── Full package list ──
        html += f'<h2 id="all-{eco_name}" class="filterable" data-section="all">All {display} packages ({len(eco_components)})</h2>\n'

        headers = "<th>Package</th>"
        if has_group:
            headers = "<th>Group</th><th>Artifact</th>"
        if dep_prop:
            headers += "<th>Typ</th>"
        headers += "<th>Version</th><th>Latest</th><th>Status</th>"

        html += f"<table><thead><tr>{headers}</tr></thead><tbody>\n"

        # Sortierung: veraltete zuerst, dann nach Major-Diff, dann Name
        def sort_key(c: dict):
            latest = get_prop(c, latest_prop) if latest_prop else None
            is_outdated = 0 if (latest and latest != c["version"]) else 1
            dist = -version_distance(c["version"], latest or c["version"])
            sort_name = f"{c.get('group', '')}:{c['name']}" if has_group else c["name"]
            return (is_outdated, dist, sort_name)

        for c in sorted(eco_components, key=sort_key):
            name = c["name"]
            version = c["version"]
            latest = get_prop(c, latest_prop) if latest_prop else None
            latest_display = latest or "-"

            # Status-Badge
            if get_prop(c, extra_props.get("discontinued", "")) == "true":
                status = '<span class="badge critical">discontinued</span>'
            elif get_prop(c, extra_props.get("advisory", "")) == "true":
                status = '<span class="badge critical">advisory</span>'
            elif latest_display == "-":
                status = '<span class="badge neutral">unknown</span>'
            elif latest != version:
                major_diff = version_distance(version, latest)
                status = _status_badge(major_diff)
            else:
                status = '<span class="badge ok">current</span>'

            row = ""
            if has_group:
                row += f"<td>{escape(c.get('group', ''))}</td><td>{make_link(c)}</td>"
            else:
                row += f"<td>{make_link(c)}</td>"

            if dep_prop:
                dep_type = get_prop(c, dep_prop) or "transitive"
                dep_short = dep_labels.get(dep_type, dep_type)
                row += f"<td><span class='dep-type'>{escape(dep_short)}</span></td>"

            row += f"<td>{escape(version)}</td><td>{escape(latest_display)}</td><td>{status}</td>"

            attrs = ""
            if dep_prop:
                dep_val = get_prop(c, dep_prop) or "transitive"
                attrs += f' data-dep="{escape(dep_val)}"'
            mod_val = get_prop(c, module_prop) if module_prop else None
            if mod_val:
                attrs += f' data-module="{escape(mod_val)}"'
            is_outdated = "1" if (latest and latest != version) else "0"
            html += f'<tr{attrs} data-outdated="{is_outdated}">{row}</tr>\n'
        html += "</tbody></table>\n"

        if not simple:
            html += '</div>\n'  # close tab-panel

    # ── Dependency tree tab ──
    if not simple and has_tree:
        comp_lookup = {c.get("purl", c.get("bom-ref", "")): c for c in components}
        eco_cfgs = _get_report_config()
        outdated_cache: dict[str, int] = {}

        html += '<div class="tab-panel" id="tab-tree" data-tab-title=_("Dependency Tree")>\n'
        html += '<h2>Dependency Tree</h2>\n'

        # Group root deps by ecosystem
        app_purl = meta.get("component", {}).get("purl", "")
        root_deps = dep_lookup.get(app_purl, [])

        # Derive PURL prefix -> ecosystem name from registry
        eco_prefix_map = {
            f"pkg:{cfg.get('purl_type', name)}/": name
            for name, cfg in eco_cfgs.items()
            if cfg.get("purl_type")
        }

        def _purl_eco(p: str) -> str:
            for prefix, eco in eco_prefix_map.items():
                if p.startswith(prefix):
                    return eco
            return "other"

        # Alle Deps gruppieren: Root-Deps + Module-Container
        deps_by_eco: dict[str, list[str]] = {}
        if root_deps:
            for p in root_deps:
                deps_by_eco.setdefault(_purl_eco(p), []).append(p)

        # Assign module containers to the correct ecosystem (via /_module/ convention)
        for ref in dep_lookup:
            if "/_module/" in ref:
                eco = _purl_eco(ref)
                deps_by_eco.setdefault(eco, []).append(ref)

        if not deps_by_eco:
            all_children = set()
            for deps in dep_lookup.values():
                all_children.update(deps)
            top_level = [ref for ref in dep_lookup if ref not in all_children and ref != app_purl]
            for p in top_level:
                deps_by_eco.setdefault(_purl_eco(p), []).append(p)

        # Reihenfolge aus Registry (statt hardcodiert)
        eco_order_all = [name for name in eco_cfgs] + ["other"]
        eco_order = [k for k in eco_order_all if k in deps_by_eco]

        # Build subtab list: ecosystems + modules
        subtab_items: list[tuple[str, str, list[str]]] = []
        for eco_key in eco_order:
            eco_deps = deps_by_eco[eco_key]
            cfg, display = _get_eco_config(eco_key)

            module_deps = [p for p in eco_deps if "/_module/" in p]
            regular_deps = [p for p in eco_deps if "/_module/" not in p]

            if module_deps:
                for mod_purl in sorted(module_deps):
                    mod_name = mod_purl.split("/_module/")[-1].split("@")[0]
                    mod_children = dep_lookup.get(mod_purl, [])
                    subtab_items.append((f"tree-mod-{mod_name}", f":{mod_name}", list(mod_children)))
            elif regular_deps:
                subtab_items.append((f"tree-{eco_key}", display, regular_deps))

        # Render subtabs (when 2+ entries)
        use_subtabs = len(subtab_items) > 1
        if use_subtabs:
            html += '<div class="subtabs">\n'
            for i, (sid, label, purls) in enumerate(subtab_items):
                active = " active" if i == 0 else ""
                html += f'    <button class="subtab-btn{active}" data-subtab="{sid}">{escape(label)} <span class="tab-count">{len(purls)}</span></button>\n'
            html += '</div>\n'

        for i, (sid, label, purls) in enumerate(subtab_items):
            if use_subtabs:
                active = " active" if i == 0 else ""
                html += f'<div class="subtab-panel{active}" id="{sid}">\n'

            # Collect all reachable packages and count outdated (deduplicated)
            all_reachable: set[str] = set()
            def _collect(p: str) -> None:
                if p in all_reachable:
                    return
                all_reachable.add(p)
                for child in dep_lookup.get(p, []):
                    _collect(child)
            for p in purls:
                _collect(p)
            total_outdated = sum(
                1 for p in all_reachable
                if _is_outdated(p, comp_lookup, eco_cfgs)
            )
            warn = f' — <span class="tree-warn">⚠ {total_outdated} outdated</span>' if total_outdated else ""
            html += f'<div class="tree-eco-header">{escape(label)} ({len(purls)} packages){warn}</div>\n'
            html += f'<input type="text" class="search-input tree-search" placeholder="{escape(label)} search..." onkeyup="filterTree(this)">\n'
            rendered: set[str] = set()
            for dep_purl in sorted(purls):
                html += _render_tree_node(dep_purl, dep_lookup, comp_lookup, eco_cfgs, set(), outdated_cache, rendered, 0)

            if use_subtabs:
                html += '</div>\n'

        html += '</div>\n'

    # ── Footer ──
    html += """
<footer>
    Generated by <a href="https://github.com/Frmwrk-GmbH/sbom-scanner" target="_blank">sbom-scanner</a> | SBOM: CycloneDX 1.6 | CVE data: grype + OSV | &copy; 2026 Frmwrk GmbH
</footer>
"""

    if not simple:
        html += """<script>
/* Tabs */
document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
        btn.classList.add('active');
        const panel = document.getElementById('tab-' + btn.dataset.tab);
        if (panel) panel.classList.add('active');
    });
});

/* Search — filters table rows in the current tab panel */
function filterTable(input) {
    const panel = input.closest('.tab-panel');
    if (!panel) return;
    const term = input.value.toLowerCase();
    panel.querySelectorAll('tbody tr').forEach(row => {
        row.style.display = row.textContent.toLowerCase().includes(term) ? '' : 'none';
    });
    updateMatchCount(panel);
}

function updateMatchCount(panel) {
    panel.querySelectorAll('table').forEach(table => {
        const visible = table.querySelectorAll('tbody tr:not([style*="display: none"])').length;
        const total = table.querySelectorAll('tbody tr').length;
        let counter = table.previousElementSibling;
        if (!counter || !counter.classList.contains('match-count')) {
            counter = document.createElement('span');
            counter.className = 'match-count';
            table.parentNode.insertBefore(counter, table);
        }
        counter.textContent = visible < total ? visible + ' / ' + total : '';
    });
}

/* Baum-Aufklappen mit Animation */
document.querySelectorAll('.tree-toggle').forEach(toggle => {
    const node = toggle.parentElement;
    const children = node.querySelector('.tree-children');
    if (!children) return;

    /* Initial: offene Knoten korrekt darstellen */
    if (node.classList.contains('open')) {
        children.style.height = 'auto';
        children.style.opacity = '1';
    }

    toggle.addEventListener('click', () => {
        if (node.classList.contains('open')) {
            /* Zuklappen */
            children.style.height = children.scrollHeight + 'px';
            children.offsetHeight; /* force reflow */
            children.style.height = '0';
            children.style.opacity = '0';
            node.classList.remove('open');
        } else {
            /* Aufklappen */
            node.classList.add('open');
            children.style.height = children.scrollHeight + 'px';
            children.style.opacity = '1';
            children.addEventListener('transitionend', function handler() {
                if (node.classList.contains('open')) {
                    children.style.height = 'auto';
                }
                children.removeEventListener('transitionend', handler);
            });
        }
    });
});

/* Sub-Tabs (Ökosystem-Tabs im Abhängigkeitsbaum) */
document.querySelectorAll('.subtab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const container = btn.closest('.tab-panel');
        if (!container) return;
        container.querySelectorAll('.subtab-btn').forEach(b => b.classList.remove('active'));
        container.querySelectorAll('.subtab-panel').forEach(p => p.classList.remove('active'));
        btn.classList.add('active');
        const panel = container.querySelector('#' + btn.dataset.subtab);
        if (panel) panel.classList.add('active');
    });
});

/* Tree search */
function filterTree(input) {
    const panel = input.closest('.subtab-panel') || input.closest('.tab-panel');
    if (!panel) return;
    const term = input.value.toLowerCase();

    panel.querySelectorAll('.tree-node, .tree-leaf').forEach(el => {
        if (!term) {
            el.style.display = '';
            if (el.classList.contains('tree-node')) {
                el.classList.remove('open');
                const ch = el.querySelector(':scope > .tree-children');
                if (ch) { ch.style.height = '0'; ch.style.opacity = '0'; }
            }
            return;
        }

        const ownText = (el.querySelector(':scope > .tree-toggle') || el).textContent.toLowerCase();
        const ownMatch = ownText.includes(term);

        if (el.classList.contains('tree-leaf')) {
            el.style.display = ownMatch ? '' : 'none';
        } else if (el.classList.contains('tree-node')) {
            const anyChildMatch = [...el.querySelectorAll('.tree-leaf, .tree-toggle')].some(
                c => c.textContent.toLowerCase().includes(term)
            );
            el.style.display = anyChildMatch ? '' : 'none';
            if (anyChildMatch) {
                el.classList.add('open');
                const ch = el.querySelector(':scope > .tree-children');
                if (ch) { ch.style.height = 'auto'; ch.style.opacity = '1'; }
            }
        }
    });
}

/* Filter-Buttons */
document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const bar = btn.closest('.filter-bar');
        const panel = btn.closest('.tab-panel');
        if (!panel) return;

        const isDep = !!btn.dataset.dep;
        const isModule = !!btn.dataset.module;
        const isSection = !!btn.dataset.filter;

        // Nur Buttons derselben Gruppe deaktivieren, Toggle bei dep/module
        if (isDep) {
            bar.querySelectorAll('.filter-btn[data-dep]').forEach(b => b.classList.remove('active'));
            if (!btn.classList.contains('active')) btn.classList.add('active');
        } else if (isModule) {
            bar.querySelectorAll('.filter-btn[data-module]').forEach(b => b.classList.remove('active'));
            if (!btn.classList.contains('active')) btn.classList.add('active');
        } else {
            bar.querySelectorAll('.filter-btn[data-filter]').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
        }

        // Aktive Filter sammeln
        const activeSection = bar.querySelector('.filter-btn[data-filter].active');
        const sectionFilter = activeSection ? activeSection.dataset.filter : 'all';
        const activeDep = bar.querySelector('.filter-btn[data-dep].active');
        const depFilter = activeDep ? activeDep.dataset.dep : null;
        const activeModule = bar.querySelector('.filter-btn[data-module].active');
        const moduleFilter = activeModule ? activeModule.dataset.module : null;

        // Sektionen ein-/ausblenden
        const sections = panel.querySelectorAll('.filterable');
        sections.forEach(s => {
            let show = true;
            if (sectionFilter === 'outdated') show = s.dataset.section === 'outdated';
            else if (sectionFilter === 'current') show = s.dataset.section === 'all';
            s.style.display = show ? '' : 'none';
            let t = s.nextElementSibling;
            while(t && !t.classList.contains('filterable')) { t.style.display = show ? '' : 'none'; t = t.nextElementSibling; }
        });

        // Zeilen filtern (dep-type + module kombiniert)
        panel.querySelectorAll('tbody tr').forEach(row => {
            let show = true;
            if (depFilter && row.dataset.dep) {
                show = show && row.dataset.dep === depFilter;
            }
            if (moduleFilter && row.dataset.module) {
                show = show && row.dataset.module.includes(moduleFilter);
            }
            row.style.display = show ? '' : 'none';
        });

        updateMatchCount(panel);
    });
});
</script>
"""

    html += """</body>
</html>"""

    return html


# ── Main ─────────────────────────────────────────────────────────────────────

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


def main():
    parser = argparse.ArgumentParser(description=_("SBOM HTML/PDF Report Generator") + " | © 2026 Frmwrk GmbH")
    parser.add_argument("--sbom", help=_("Path to SBOM (default: from config or sbom.cyclonedx.json)"))
    parser.add_argument("--output", help=_("Output path (default: from config or sbom-report.html)"))
    parser.add_argument("--config", default="sbom.config.yaml", help=_("Configuration file"))
    parser.add_argument("--project-dir", default=".", help=_("Project directory"))
    parser.add_argument("--pdf", action="store_true", help="Zusätzlich PDF generieren")
    parser.add_argument("--skip-cve", action="store_true", help=_("Skip CVE scan"))
    parser.add_argument("--lang", default=None, help="Language (en, de)")
    parser.add_argument("--simple", action="store_true", help=_("Simple report without tabs, search and filters"))
    args = parser.parse_args()

    project_dir = Path(args.project_dir).resolve()

    # Config laden
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
    generate_pdf = args.pdf or options.get("pdf", False)

    # CVE-Scan
    vulns = []
    if not skip_cve:
        # Lockfiles sammeln
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

    # HTML generieren
    use_simple = args.simple or options.get("simple", False)
    html = generate_html(sbom, vulns, simple=use_simple)
    output_path = Path(args.output or output_config.get("report", "sbom-report.html"))
    if not output_path.is_absolute():
        output_path = project_dir / output_path
    with open(output_path, "w") as f:
        f.write(html)
    print(f"HTML-Report: {output_path}")

    # PDF — einfache Version ohne Tabs/JS generieren
    if generate_pdf:
        if not use_simple:
            pdf_html = generate_html(sbom, vulns, simple=True)
            pdf_source = output_path.with_name(output_path.stem + "-print.html")
            with open(pdf_source, "w") as f:
                f.write(pdf_html)
        else:
            pdf_source = output_path

        pdf_path = output_path.with_suffix(".pdf")
        pdf_ok = False

        # 1. weasyprint
        if not pdf_ok:
            try:
                from weasyprint import HTML as WeasyHTML
                WeasyHTML(filename=str(pdf_source)).write_pdf(str(pdf_path))
                pdf_ok = True
            except Exception:
                pass

        # 2. Chrome/Chromium headless
        if not pdf_ok:
            for chrome in [
                "google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                "/Applications/Chromium.app/Contents/MacOS/Chromium",
            ]:
                try:
                    subprocess.run(
                        [chrome, "--headless", "--disable-gpu",
                         f"--print-to-pdf={pdf_path}", "--no-pdf-header-footer",
                         str(pdf_source)],
                        check=True, capture_output=True, timeout=30,
                    )
                    pdf_ok = True
                    break
                except (FileNotFoundError, subprocess.CalledProcessError):
                    continue

        # 3. wkhtmltopdf
        if not pdf_ok:
            try:
                subprocess.run(
                    ["wkhtmltopdf", "--quiet", "--enable-local-file-access",
                     str(pdf_source), str(pdf_path)],
                    check=True, timeout=30,
                )
                pdf_ok = True
            except (FileNotFoundError, subprocess.CalledProcessError):
                pass

        # Clean up temporary print HTML
        if pdf_source != output_path and pdf_source.exists():
            pdf_source.unlink()

        if pdf_ok:
            print(f"PDF-Report: {pdf_path}")
        else:
            print("Fehler: Kein PDF-Tool gefunden. Eines der folgenden installieren:", file=sys.stderr)
            print("  pip install weasyprint  (+ brew install pango glib)", file=sys.stderr)
            print("  Google Chrome / Chromium (headless)", file=sys.stderr)
            print("  wkhtmltopdf", file=sys.stderr)


if __name__ == "__main__":
    main()
