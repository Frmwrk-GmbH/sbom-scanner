"""JSON report renderer."""
from __future__ import annotations

import json
from pathlib import Path

from .base import Renderer


class JsonRenderer(Renderer):
    name = "json"
    display_name = "JSON Report"
    file_extension = ".json"

    def render(self, sbom, vulns, output_path, **kwargs):
        from ..report_data import classify_components, eco_stats, get_eco_config, get_prop, version_distance

        components = sbom.get("components", [])
        eco_groups = classify_components(components)
        report = {
            "metadata": sbom.get("metadata", {}),
            "summary": {
                "total_packages": len(components),
                "total_vulnerabilities": len(vulns),
            },
            "vulnerabilities": vulns,
            "ecosystems": {},
        }
        for eco_name, eco_comps in eco_groups.items():
            cfg, display = get_eco_config(eco_name)
            stats = eco_stats(eco_name, eco_comps)
            report["ecosystems"][eco_name] = {
                "display_name": display,
                "total": stats["total"],
                "outdated": len(stats["outdated"]),
                "packages": [
                    {"name": c["name"], "version": c["version"],
                     "group": c.get("group", ""),
                     "latest": get_prop(c, cfg.get("latest_prop", "")) or None,
                     "dep_type": get_prop(c, cfg.get("dep_prop", "")) or None}
                    for c in eco_comps
                ],
            }
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)
        return output_path
