"""Simple HTML report renderer (no JS, no tabs, no filters)."""
from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from pathlib import Path

from ..report_data import (
    get_report_config, classify_components, eco_stats, get_eco_config,
    build_dep_lookup, severity_order,
    get_prop, version_distance, tags_html, diff_badge, status_badge,
)
from .base import Renderer
from .html import CSS


class SimpleHtmlRenderer(Renderer):
    name = "simple-html"
    display_name = "Simple HTML Report"
    file_extension = ".html"

    def render(self, sbom, vulns, output_path, **kwargs):
        html = self._generate_html(sbom, vulns)
        with open(output_path, "w") as f:
            f.write(html)
        return output_path

    def _generate_html(self, sbom, vulns):
        meta = sbom.get("metadata", {})
        app = meta.get("component", {})
        app_name = app.get("name", "Unknown")
        app_version = app.get("version", "0.0.0")
        timestamp = meta.get("timestamp", "")
        components = sbom.get("components", [])

        # Group by ecosystem
        eco_groups = classify_components(components)
        eco_stats_map = {name: eco_stats(name, comps) for name, comps in eco_groups.items()}

        total_outdated = sum(len(s["outdated"]) for s in eco_stats_map.values())
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

        for eco_name, stats in eco_stats_map.items():
            cfg, display = get_eco_config(eco_name)
            dep_info = ""
            if stats["dep_counts"]:
                dep_labels_cfg = cfg.get("dep_labels", {})
                parts = []
                for dt, count in sorted(stats["dep_counts"].items()):
                    label = dep_labels_cfg.get(dt, dt)
                    parts.append(f"{count} {label}")
                dep_info = f" ({', '.join(parts)})"
            html += f'    <div class="stat"><div class="stat-value">{stats["total"]}</div><div class="stat-label">{escape(display)}{dep_info}</div></div>\n'

        html += f'    <div class="stat"><div class="stat-value" style="color: var({"--red" if vulns else "--green"})">{len(vulns)}</div><div class="stat-label">CVEs</div></div>\n'

        outdated_parts = []
        for eco_name, stats in eco_stats_map.items():
            cfg, display = get_eco_config(eco_name)
            outdated_parts.append(f"{len(stats['outdated'])} {display}")
        outdated_label = f"Veraltet ({', '.join(outdated_parts)})" if outdated_parts else "Outdated"
        html += f'    <div class="stat"><div class="stat-value" style="color: var({"--orange" if total_outdated else "--green"})">{total_outdated}</div><div class="stat-label">{outdated_label}</div></div>\n'

        # Discontinued
        report_cfg = get_report_config()
        discontinued = []
        for cfg_vals in report_cfg.values():
            disc_prop = cfg_vals.get("extra_props", {}).get("discontinued", "")
            if disc_prop:
                discontinued.extend(c for c in components if get_prop(c, disc_prop) == "true")
        if discontinued:
            html += f'    <div class="stat"><div class="stat-value" style="color: var(--red)">{len(discontinued)}</div><div class="stat-label">Discontinued</div></div>\n'

        html += '</div>\n'

        # ── Navigation (flat TOC, no JS) ──
        html += '<div class="toc no-print">\n'
        html += '    <a href="#vulns">CVEs</a>\n'
        for eco_name in eco_groups:
            cfg, display = get_eco_config(eco_name)
            html += f'    <a href="#outdated-{eco_name}">Veraltet ({display})</a>\n'
            html += f'    <a href="#all-{eco_name}">{display}</a>\n'
        html += '</div>\n'

        # ── CVE Panel ──
        html += '<h2 id="vulns">Vulnerabilities (CVEs)</h2>\n'
        if vulns:
            vulns.sort(key=lambda v: severity_order(v.get("severity", "")))
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

        # ── Per ecosystem ──
        for eco_name, eco_components in eco_groups.items():
            cfg, display = get_eco_config(eco_name)
            stats = eco_stats_map[eco_name]

            latest_prop = cfg.get("latest_prop", "")
            dep_prop = cfg.get("dep_prop", "")
            dep_labels = cfg.get("dep_labels", {})
            has_group = cfg.get("has_group_column", False)
            extra_props = cfg.get("extra_props", {})
            module_prop = cfg.get("module_prop", "")

            outdated = stats["outdated"]

            url_template = cfg.get("url_template", "")

            def make_link(c: dict, with_tags: bool = True, _url_template=url_template) -> str:
                name = c["name"]
                group = c.get("group", "")
                if _url_template:
                    url = _url_template.format(name=name, group=group)
                    link = f'<a href="{url}" target="_blank">{escape(name)}</a>'
                else:
                    link = escape(name)
                if with_tags:
                    link += tags_html(c)
                return link

            # ── Outdated Packages ──
            html += f'<h2 id="outdated-{eco_name}">Outdated {display} packages ({len(outdated)})</h2>\n'
            if outdated:
                headers = "<th>Package</th>"
                if has_group:
                    headers = "<th>Group</th><th>Artifact</th>"
                if dep_prop:
                    headers += "<th>Typ</th>"

                headers += "<th>Aktuell</th>"

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
                    diff_bdg = diff_badge(major_diff)

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

                    row += f'<td class="version-new">{escape(latest)}</td><td>{diff_bdg}</td>'
                    html += f"<tr>{row}</tr>\n"
                html += "</tbody></table>\n"
            else:
                html += f'<div class="section-empty">All {display} packages are up to date.</div>\n'

            # ── Full package list ──
            html += f'<h2 id="all-{eco_name}">All {display} packages ({len(eco_components)})</h2>\n'

            headers = "<th>Package</th>"
            if has_group:
                headers = "<th>Group</th><th>Artifact</th>"
            if dep_prop:
                headers += "<th>Typ</th>"
            has_licenses = any(c.get("licenses") for c in eco_components)
            headers += "<th>Version</th><th>Latest</th><th>Status</th>"
            if has_licenses:
                headers += "<th>License</th>"

            html += f"<table><thead><tr>{headers}</tr></thead><tbody>\n"

            def sort_key(c: dict, _latest_prop=latest_prop, _has_group=has_group):
                latest = get_prop(c, _latest_prop) if _latest_prop else None
                is_out = 0 if (latest and latest != c["version"]) else 1
                dist = -version_distance(c["version"], latest or c["version"])
                sort_name = f"{c.get('group', '')}:{c['name']}" if _has_group else c["name"]
                return (is_out, dist, sort_name)

            for c in sorted(eco_components, key=sort_key):
                name = c["name"]
                version = c["version"]
                latest = get_prop(c, latest_prop) if latest_prop else None
                latest_display = latest or "-"

                if get_prop(c, extra_props.get("discontinued", "")) == "true":
                    status = '<span class="badge critical">discontinued</span>'
                elif get_prop(c, extra_props.get("advisory", "")) == "true":
                    status = '<span class="badge critical">advisory</span>'
                elif latest_display == "-":
                    status = '<span class="badge neutral">unknown</span>'
                elif latest != version:
                    major_diff = version_distance(version, latest)
                    status = status_badge(major_diff)
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
                if has_licenses:
                    from ..report_data import get_license, license_badge
                    lic = get_license(c)
                    row += f"<td>{license_badge(lic)}</td>"
                html += f"<tr>{row}</tr>\n"
            html += "</tbody></table>\n"

        # ── Footer ──
        html += """
<footer>
    Generated by <a href="https://github.com/Frmwrk-GmbH/sbom-scanner" target="_blank">sbom-scanner</a> | SBOM: CycloneDX 1.6 | CVE data: grype + OSV | &copy; 2026 Frmwrk GmbH
</footer>

</body>
</html>"""

        return html
