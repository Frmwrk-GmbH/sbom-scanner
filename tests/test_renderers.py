"""Tests for report renderers."""

import csv
import json
from pathlib import Path

from sbom_scanner.renderers import get_renderer
from sbom_scanner.renderers.html import HtmlRenderer
from sbom_scanner.renderers.simple_html import SimpleHtmlRenderer
from sbom_scanner.renderers.json_report import JsonRenderer
from sbom_scanner.renderers.csv_report import CsvRenderer


class TestRegistry:
    def test_get_renderer(self):
        assert get_renderer("html") is not None
        assert get_renderer("simple-html") is not None
        assert get_renderer("pdf") is not None
        assert get_renderer("json") is not None
        assert get_renderer("csv") is not None

    def test_unknown(self):
        assert get_renderer("xml") is None


class TestHtmlRenderer:
    def test_render(self, minimal_sbom, tmp_path):
        sbom_path, sbom = minimal_sbom
        output = tmp_path / "report.html"
        renderer = HtmlRenderer()
        result = renderer.render(sbom, [], output)
        assert result == output
        assert output.exists()
        html = output.read_text()
        assert "<!DOCTYPE html>" in html
        assert "test-app" in html
        assert "express" in html
        assert "flask" in html

    def test_contains_tabs(self, minimal_sbom, tmp_path):
        _, sbom = minimal_sbom
        output = tmp_path / "report.html"
        HtmlRenderer().render(sbom, [], output)
        html = output.read_text()
        assert "tab-btn" in html
        assert "<script>" in html

    def test_contains_tree(self, minimal_sbom, tmp_path):
        _, sbom = minimal_sbom
        output = tmp_path / "report.html"
        HtmlRenderer().render(sbom, [], output)
        html = output.read_text()
        assert "Dependency Tree" in html
        assert "tree-toggle" in html

    def test_vulns_section(self, minimal_sbom, tmp_path):
        _, sbom = minimal_sbom
        vulns = [
            {"id": "CVE-2024-0001", "package": "express", "version": "4.18.2",
             "severity": "High", "summary": "Test vuln", "fix_versions": ["4.18.3"]},
        ]
        output = tmp_path / "report.html"
        HtmlRenderer().render(sbom, vulns, output)
        html = output.read_text()
        assert "CVE-2024-0001" in html
        assert "High" in html

    def test_outdated_badge(self, minimal_sbom, tmp_path):
        _, sbom = minimal_sbom
        output = tmp_path / "report.html"
        HtmlRenderer().render(sbom, [], output)
        html = output.read_text()
        # express 4.18.2 → 5.0.0 = 1 Major behind
        assert "1 Major" in html


class TestSimpleHtmlRenderer:
    def test_render(self, minimal_sbom, tmp_path):
        _, sbom = minimal_sbom
        output = tmp_path / "report.html"
        SimpleHtmlRenderer().render(sbom, [], output)
        html = output.read_text()
        assert "<!DOCTYPE html>" in html
        assert "<script>" not in html

    def test_has_toc(self, minimal_sbom, tmp_path):
        _, sbom = minimal_sbom
        output = tmp_path / "report.html"
        SimpleHtmlRenderer().render(sbom, [], output)
        html = output.read_text()
        assert 'class="toc' in html


class TestJsonRenderer:
    def test_render(self, minimal_sbom, tmp_path):
        _, sbom = minimal_sbom
        output = tmp_path / "report.json"
        JsonRenderer().render(sbom, [], output)
        data = json.loads(output.read_text())
        assert "metadata" in data
        assert "summary" in data
        assert data["summary"]["total_packages"] == 3
        assert "ecosystems" in data

    def test_with_vulns(self, minimal_sbom, tmp_path):
        _, sbom = minimal_sbom
        vulns = [{"id": "CVE-2024-0001", "package": "express", "version": "4.18.2",
                  "severity": "High", "summary": "Test"}]
        output = tmp_path / "report.json"
        JsonRenderer().render(sbom, vulns, output)
        data = json.loads(output.read_text())
        assert data["summary"]["total_vulnerabilities"] == 1
        assert len(data["vulnerabilities"]) == 1

    def test_ecosystem_packages(self, minimal_sbom, tmp_path):
        _, sbom = minimal_sbom
        output = tmp_path / "report.json"
        JsonRenderer().render(sbom, [], output)
        data = json.loads(output.read_text())
        assert "npm" in data["ecosystems"]
        assert data["ecosystems"]["npm"]["total"] == 2
        npm_names = [p["name"] for p in data["ecosystems"]["npm"]["packages"]]
        assert "express" in npm_names


class TestCsvRenderer:
    def test_render(self, minimal_sbom, tmp_path):
        _, sbom = minimal_sbom
        output = tmp_path / "report.csv"
        CsvRenderer().render(sbom, [], output)
        with open(output) as f:
            reader = csv.reader(f)
            rows = list(reader)
        assert rows[0] == ["Ecosystem", "Group", "Name", "Version", "Latest", "Type", "Status"]
        assert len(rows) == 4  # header + 3 components

    def test_status_values(self, minimal_sbom, tmp_path):
        _, sbom = minimal_sbom
        output = tmp_path / "report.csv"
        CsvRenderer().render(sbom, [], output)
        with open(output) as f:
            reader = csv.DictReader(f)
            rows = {r["Name"]: r for r in reader}
        assert rows["express"]["Status"] == "outdated"
        assert rows["debug"]["Status"] == "current"
