"""CSV report renderer."""
from __future__ import annotations

import csv
from pathlib import Path

from .base import Renderer


class CsvRenderer(Renderer):
    name = "csv"
    display_name = "CSV Report"
    file_extension = ".csv"

    def render(self, sbom, vulns, output_path, **kwargs):
        from ..report_data import classify_components, get_eco_config, get_prop

        components = sbom.get("components", [])
        eco_groups = classify_components(components)
        with open(output_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Ecosystem", "Group", "Name", "Version", "Latest", "Type", "Status", "License"])
            for eco_name, eco_comps in eco_groups.items():
                cfg, display = get_eco_config(eco_name)
                for c in sorted(eco_comps, key=lambda x: x["name"]):
                    latest = get_prop(c, cfg.get("latest_prop", "")) or ""
                    dep_type = get_prop(c, cfg.get("dep_prop", "")) or ""
                    status = "outdated" if latest and latest != c["version"] else "current" if latest else "unknown"
                    # License from CycloneDX licenses field or property
                    lic = ""
                    licenses = c.get("licenses", [])
                    if licenses:
                        lic = licenses[0].get("license", {}).get("id", "") or licenses[0].get("license", {}).get("name", "")
                    if not lic:
                        lic = get_prop(c, cfg.get("license_prop", "")) or ""
                    writer.writerow([display, c.get("group", ""), c["name"], c["version"], latest, dep_type, status, lic])
        return output_path
