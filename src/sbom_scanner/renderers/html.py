"""Interactive HTML report renderer."""
from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from pathlib import Path

from ..i18n import _
from ..report_data import (
    get_report_config, classify_components, eco_stats, get_eco_config,
    build_dep_lookup, count_outdated_deep, is_outdated, severity_order,
    get_prop, version_distance, purl_to_name, tags_html, diff_badge, status_badge,
    render_tree_node, get_license, license_badge,
)
from .base import Renderer


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
    .tree-toggle::before { content: "\\25b6"; color: var(--muted); font-size: 0.55rem; flex-shrink: 0; transition: transform 0.2s ease; }
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


JS = """\
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

/* License filter buttons */
document.querySelectorAll('[data-lic-filter]').forEach(btn => {
    btn.addEventListener('click', () => {
        const bar = btn.closest('.filter-bar');
        bar.querySelectorAll('[data-lic-filter]').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        const filter = btn.dataset.licFilter;
        const panel = btn.closest('.tab-panel');
        if (!panel) return;
        panel.querySelectorAll('tbody tr').forEach(row => {
            if (filter === 'all') {
                row.style.display = '';
            } else {
                row.style.display = row.dataset.license === filter ? '' : 'none';
            }
        });
        updateMatchCount(panel);
    });
});
"""


class HtmlRenderer(Renderer):
    name = "html"
    display_name = "Interactive HTML Report"
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
                dep_labels = cfg.get("dep_labels", {})
                parts = []
                for dt, count in sorted(stats["dep_counts"].items()):
                    label = dep_labels.get(dt, dt)
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

        # Check dependency graph
        dep_lookup = build_dep_lookup(sbom)
        has_tree = len(dep_lookup) > 1

        # ── Tabs ──
        tab_ids = []
        tab_ids.append(("vulns", "CVEs", len(vulns)))
        for eco_name in eco_groups:
            cfg, display = get_eco_config(eco_name)
            total = eco_stats_map[eco_name]["total"]
            tab_ids.append((eco_name, display, total))

        if has_tree:
            tab_ids.append(("tree", _("Dependency Tree"), len(dep_lookup)))

        # License tab (only if any component has license data)
        has_any_licenses = any(c.get("licenses") for c in components)
        if has_any_licenses:
            lic_count = sum(1 for c in components if get_license(c))
            tab_ids.append(("licenses", "Licenses", lic_count))

        html += '<div class="tabs no-print">\n'
        for i, (tid, label, count) in enumerate(tab_ids):
            active = " active" if i == 0 else ""
            html += f'    <button class="tab-btn{active}" data-tab="{tid}">{escape(label)}<span class="tab-count">{count}</span></button>\n'
        html += '</div>\n'

        # ── CVE Panel ──
        html += '<div class="tab-panel active" id="tab-vulns" data-tab-title="' + _("Vulnerabilities (CVEs)") + '">\n'
        html += '<h2 id="vulns">Vulnerabilities (CVEs)</h2>\n'
        if vulns:
            vulns.sort(key=lambda v: severity_order(v.get("severity", "")))
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
        html += '</div>\n'

        # ── Per ecosystem ──
        for eco_name, eco_components in eco_groups.items():
            cfg, display = get_eco_config(eco_name)
            stats = eco_stats_map[eco_name]

            html += f'<div class="tab-panel" id="tab-{eco_name}" data-tab-title="{escape(display)}">\n'
            latest_prop = cfg.get("latest_prop", "")
            dep_prop = cfg.get("dep_prop", "")
            dep_labels = cfg.get("dep_labels", {})
            has_group = cfg.get("has_group_column", False)
            extra_props = cfg.get("extra_props", {})

            outdated = stats["outdated"]

            # URL generation
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

            # ── Search + Filter ──
            html += f'<input type="text" class="search-input" placeholder="{escape(display)} search..." onkeyup="filterTable(this)">\n'
            html += '<div class="filter-bar no-print">\n'
            html += '    <button class="filter-btn active" data-filter="all">All</button>\n'
            html += '    <button class="filter-btn" data-filter="outdated">Outdated</button>\n'
            html += '    <button class="filter-btn" data-filter="current">Current</button>\n'
            # Dependency type filter
            if dep_prop and stats["dep_counts"]:
                html += '    <span class="filter-sep"></span>\n'
                for dt in sorted(stats["dep_counts"]):
                    label = dep_labels.get(dt, dt)
                    count = stats["dep_counts"][dt]
                    html += f'    <button class="filter-btn" data-dep="{escape(dt)}">{escape(label)} <span class="filter-count">{count}</span></button>\n'
            # Module filter
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

            has_licenses = any(c.get("licenses") for c in eco_components)

            # ── Outdated Packages ──
            html += f'<h2 id="outdated-{eco_name}" class="filterable" data-section="outdated">Outdated {display} packages ({len(outdated)})</h2>\n'
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
                if has_licenses:
                    headers += "<th>License</th>"

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
                    if has_licenses:
                        lic = get_license(c)
                        row += f"<td>{license_badge(lic)}</td>"

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
                    lic = get_license(c)
                    row += f"<td>{license_badge(lic)}</td>"

                attrs = ""
                if dep_prop:
                    dep_val = get_prop(c, dep_prop) or "transitive"
                    attrs += f' data-dep="{escape(dep_val)}"'
                mod_val = get_prop(c, module_prop) if module_prop else None
                if mod_val:
                    attrs += f' data-module="{escape(mod_val)}"'
                is_out = "1" if (latest and latest != version) else "0"
                html += f'<tr{attrs} data-outdated="{is_out}">{row}</tr>\n'
            html += "</tbody></table>\n"

            html += '</div>\n'  # close tab-panel

        # ── Dependency tree tab ──
        if has_tree:
            comp_lookup = {c.get("purl", c.get("bom-ref", "")): c for c in components}
            eco_cfgs = get_report_config()
            outdated_cache: dict[str, int] = {}

            html += '<div class="tab-panel" id="tab-tree" data-tab-title="' + _("Dependency Tree") + '">\n'
            html += '<h2>Dependency Tree</h2>\n'

            # Group root deps by ecosystem
            app_purl = meta.get("component", {}).get("purl", "")
            root_deps = dep_lookup.get(app_purl, [])

            # Derive PURL prefix -> ecosystem name from registry
            eco_prefix_map = {
                f"pkg:{cfg_val.get('purl_type', name)}/": name
                for name, cfg_val in eco_cfgs.items()
                if cfg_val.get("purl_type")
            }

            def _purl_eco(p: str) -> str:
                for prefix, eco in eco_prefix_map.items():
                    if p.startswith(prefix):
                        return eco
                return "other"

            deps_by_eco: dict[str, list[str]] = {}
            if root_deps:
                for p in root_deps:
                    deps_by_eco.setdefault(_purl_eco(p), []).append(p)

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

            eco_order_all = [name for name in eco_cfgs] + ["other"]
            eco_order = [k for k in eco_order_all if k in deps_by_eco]

            subtab_items: list[tuple[str, str, list[str]]] = []
            for eco_key in eco_order:
                eco_deps = deps_by_eco[eco_key]
                cfg, display = get_eco_config(eco_key)

                module_deps = [p for p in eco_deps if "/_module/" in p]
                regular_deps = [p for p in eco_deps if "/_module/" not in p]

                if module_deps:
                    for mod_purl in sorted(module_deps):
                        mod_name = mod_purl.split("/_module/")[-1].split("@")[0]
                        mod_children = dep_lookup.get(mod_purl, [])
                        subtab_items.append((f"tree-mod-{mod_name}", f":{mod_name}", list(mod_children)))
                elif regular_deps:
                    subtab_items.append((f"tree-{eco_key}", display, regular_deps))

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

                all_reachable: set[str] = set()
                def _collect(p: str) -> None:
                    if p in all_reachable:
                        return
                    all_reachable.add(p)
                    for child in dep_lookup.get(p, []):
                        _collect(child)
                for p in purls:
                    _collect(p)
                total_outdated_tree = sum(
                    1 for p in all_reachable
                    if is_outdated(p, comp_lookup, eco_cfgs)
                )
                warn = f' — <span class="tree-warn">⚠ {total_outdated_tree} outdated</span>' if total_outdated_tree else ""
                html += f'<div class="tree-eco-header">{escape(label)} ({len(purls)} packages){warn}</div>\n'
                html += f'<input type="text" class="search-input tree-search" placeholder="{escape(label)} search..." onkeyup="filterTree(this)">\n'
                rendered: set[str] = set()
                for dep_purl in sorted(purls):
                    html += render_tree_node(dep_purl, dep_lookup, comp_lookup, eco_cfgs, set(), outdated_cache, rendered, 0)

                if use_subtabs:
                    html += '</div>\n'

            html += '</div>\n'

        # ── License overview tab ──
        if has_any_licenses:
            html += '<div class="tab-panel" id="tab-licenses" data-tab-title="Licenses">\n'
            html += '<h2>Licenses</h2>\n'
            html += '<input type="text" class="search-input" placeholder="Search licenses..." onkeyup="filterTable(this)">\n'

            # Group components by license
            from collections import Counter
            lic_counter: Counter[str] = Counter()
            lic_packages: dict[str, list[dict]] = {}
            for c in components:
                lic = get_license(c)
                if not lic:
                    lic = "Unknown"
                lic_counter[lic] += 1
                lic_packages.setdefault(lic, []).append(c)

            # Filter buttons (clickable, color-coded)
            from ..report_data import _PERMISSIVE, _COPYLEFT
            def _lic_btn_class(name: str) -> str:
                upper = name.upper().replace(" ", "-")
                for p in _PERMISSIVE:
                    if p.upper() in upper:
                        return "ok"
                for c in _COPYLEFT:
                    if c.upper() in upper:
                        return "warning"
                return "neutral"

            html += '<div class="filter-bar no-print" id="license-filters">\n'
            html += f'    <button class="filter-btn active" data-lic-filter="all">All <span class="filter-count">{sum(lic_counter.values())}</span></button>\n'
            for lic_name, count in lic_counter.most_common():
                lic_val = escape(lic_name)
                cls = _lic_btn_class(lic_name if lic_name != "Unknown" else "")
                html += f'    <button class="filter-btn badge {cls}" data-lic-filter="{lic_val}">{lic_val} <span class="filter-count">{count}</span></button>\n'
            html += '</div>\n'

            # Table grouped by license
            html += '<table><thead><tr><th>License</th><th>Package</th><th>Version</th><th>Ecosystem</th></tr></thead><tbody>\n'
            for lic_name, count in lic_counter.most_common():
                for c in sorted(lic_packages[lic_name], key=lambda x: x["name"]):
                    eco = get_prop(c, "cdx:ecosystem") or ""
                    eco_cfg = get_report_config().get(eco, {})
                    url_template = eco_cfg.get("url_template", "")
                    name = c["name"]
                    group = c.get("group", "")
                    if url_template:
                        url = url_template.format(name=name, group=group)
                        name_html = f'<a href="{url}" target="_blank">{escape(name)}</a>'
                    else:
                        name_html = escape(name)
                    badge = license_badge(lic_name if lic_name != "Unknown" else "")
                    eco_display = eco_cfg.get("display_name", eco)
                    html += f'<tr data-license="{escape(lic_name)}"><td>{badge}</td><td>{name_html}</td><td>{escape(c["version"])}</td><td>{escape(eco_display)}</td></tr>\n'
            html += '</tbody></table>\n'
            html += '</div>\n'

        # ── Footer ──
        html += """
<footer>
    Generated by <a href="https://github.com/Frmwrk-GmbH/sbom-scanner" target="_blank">sbom-scanner</a> | SBOM: CycloneDX 1.6 | CVE data: grype + OSV | &copy; 2026 Frmwrk GmbH
</footer>
"""

        html += f"<script>\n{JS}</script>\n"

        html += """</body>
</html>"""

        return html
