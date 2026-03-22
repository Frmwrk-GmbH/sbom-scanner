"""Shared data processing functions for SBOM report generation."""

import json
import sys
from html import escape
from pathlib import Path


_REPORT_CONFIG_CACHE: dict[str, dict] | None = None


def get_report_config() -> dict[str, dict]:
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


def build_dep_lookup(sbom: dict) -> dict[str, list[str]]:
    """Build a lookup: purl -> [dependent purls] from the CycloneDX dependencies section."""
    lookup: dict[str, list[str]] = {}
    for dep in sbom.get("dependencies", []):
        ref = dep.get("ref", "")
        depends_on = dep.get("dependsOn", [])
        if depends_on:
            lookup[ref] = depends_on
    return lookup


def purl_to_name(purl: str) -> str:
    """Extract 'name@version' from a PURL."""
    # pkg:npm/express@4.18.2 -> express@4.18.2
    if "@" in purl:
        path = purl.split("/", 1)[-1] if "/" in purl else purl
        return path
    return purl


def is_outdated(purl: str, comp_lookup: dict, eco_configs: dict) -> bool:
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


def count_outdated_deep(purl: str, dep_lookup: dict, comp_lookup: dict,
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
            if is_outdated(child, comp_lookup, eco_configs):
                count += 1
            _walk(child)

    _walk(purl)
    cache[purl] = count
    return count


def tree_node_display(purl: str, comp_lookup: dict, eco_configs: dict,
                      outdated_deep: int = 0) -> str:
    """Build the display HTML for a tree node."""
    name_ver = purl_to_name(purl)
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


def render_tree_node(purl: str, dep_lookup: dict, comp_lookup: dict,
                     eco_configs: dict, visited: set,
                     outdated_cache: dict, rendered: set,
                     depth: int = 0, max_depth: int = 4) -> str:
    """Render a tree node.

    Args:
        rendered: Global set — each package is rendered with its full
                  subtree only once; subsequent occurrences show a reference.
    """
    children = dep_lookup.get(purl, [])
    outdated_deep = count_outdated_deep(purl, dep_lookup, comp_lookup, eco_configs, outdated_cache)
    display = tree_node_display(purl, comp_lookup, eco_configs, outdated_deep)

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
        html += render_tree_node(child, dep_lookup, comp_lookup, eco_configs, visited, outdated_cache, rendered, depth + 1, max_depth)
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


def tags_html(component: dict) -> str:
    """Generate HTML spans for CycloneDX tags of a component."""
    tags = component.get("tags", [])
    if not tags:
        return ""
    return " " + " ".join(f'<span class="tag">{escape(t)}</span>' for t in tags)


def get_license(component: dict) -> str:
    """Extract license from a CycloneDX component (licenses field or property)."""
    licenses = component.get("licenses", [])
    if licenses:
        lic = licenses[0].get("license", {})
        return lic.get("id", "") or lic.get("name", "")
    return ""


# Permissive licenses (green badge)
_PERMISSIVE = {"MIT", "ISC", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0", "Unlicense", "0BSD", "CC0-1.0"}
# Copyleft licenses (yellow badge)
_COPYLEFT = {"GPL-2.0", "GPL-3.0", "LGPL-2.1", "LGPL-3.0", "AGPL-3.0", "MPL-2.0",
             "GPL-2.0-only", "GPL-3.0-only", "GPL-2.0-or-later", "GPL-3.0-or-later",
             "LGPL-2.1-only", "LGPL-3.0-only", "AGPL-3.0-only"}


def license_badge(lic: str) -> str:
    """Return a colored badge for a license identifier."""
    if not lic:
        return '<span class="badge neutral">unknown</span>'
    # Normalize for lookup
    lic_upper = lic.upper().replace(" ", "-")
    for p in _PERMISSIVE:
        if p.upper() in lic_upper:
            return f'<span class="badge ok">{escape(lic)}</span>'
    for c in _COPYLEFT:
        if c.upper() in lic_upper:
            return f'<span class="badge warning">{escape(lic)}</span>'
    return f'<span class="badge neutral">{escape(lic)}</span>'


def diff_badge(major_diff: int) -> str:
    if major_diff >= 2:
        return f'<span class="badge critical">{major_diff} Major</span>'
    elif major_diff == 1:
        return '<span class="badge warning">1 Major</span>'
    else:
        return '<span class="badge minor">Minor/Patch</span>'


def status_badge(major_diff: int) -> str:
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


# ── Ecosystem classification ─────────────────────────────────────────────────

def classify_components(components: list[dict]) -> dict[str, list[dict]]:
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


def get_eco_config(eco_name: str) -> tuple[dict, str]:
    """Return (config, display_name) for an ecosystem key.

    Supports simple keys ("pypi") and multiroot keys ("pypi:subproject").
    """
    base_eco = eco_name.split(":")[0] if ":" in eco_name else eco_name
    tag = eco_name.split(":", 1)[1] if ":" in eco_name else ""
    cfg = get_report_config().get(base_eco, {})
    display = cfg.get("display_name", base_eco)
    if tag:
        display = f"{display} ({tag})"
    return cfg, display


def eco_stats(eco_name: str, eco_components: list[dict]) -> dict:
    """Compute statistics for an ecosystem."""
    cfg, _ = get_eco_config(eco_name)
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
