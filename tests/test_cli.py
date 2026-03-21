"""Tests for CLI and integration."""

import json
import subprocess
import sys


class TestCli:
    def test_help(self):
        result = subprocess.run([sys.executable, "-m", "sbom_scanner.cli"], capture_output=True, text=True)
        assert "sbom <command>" in result.stdout
        assert "configure" in result.stdout
        assert "scan" in result.stdout
        assert "report" in result.stdout

    def test_version(self):
        result = subprocess.run([sys.executable, "-m", "sbom_scanner.cli", "version"], capture_output=True, text=True)
        assert "sbom-scanner" in result.stdout

    def test_unknown_command(self):
        result = subprocess.run([sys.executable, "-m", "sbom_scanner.cli", "bogus"], capture_output=True, text=True)
        assert result.returncode == 1

    def test_report_missing_sbom(self, tmp_path):
        result = subprocess.run(
            [sys.executable, "-m", "sbom_scanner.cli", "report",
             "--sbom", str(tmp_path / "nonexistent.json")],
            capture_output=True, text=True,
        )
        assert result.returncode != 0


class TestIntegration:
    def test_scan_and_report(self, npm_project, tmp_path):
        sbom_out = tmp_path / "sbom.json"
        report_out = tmp_path / "report.html"

        # Scan (skip latest versions for speed)
        from sbom_scanner.generate_sbom import generate_sbom, load_config
        generate_sbom(npm_project, {}, sbom_out)

        assert sbom_out.exists()
        sbom = json.loads(sbom_out.read_text())
        assert sbom["bomFormat"] == "CycloneDX"
        assert len(sbom["components"]) == 2

        # Report
        from sbom_scanner.renderers.html import HtmlRenderer
        HtmlRenderer().render(sbom, [], report_out)
        assert report_out.exists()
        html = report_out.read_text()
        assert "is-odd" in html

    def test_json_report_from_sbom(self, minimal_sbom, tmp_path):
        sbom_path, _ = minimal_sbom
        output = tmp_path / "report.json"

        from sbom_scanner.report_data import load_sbom
        from sbom_scanner.renderers.json_report import JsonRenderer
        sbom = load_sbom(sbom_path)
        JsonRenderer().render(sbom, [], output)

        data = json.loads(output.read_text())
        assert data["summary"]["total_packages"] == 3
        assert "npm" in data["ecosystems"]
        assert "pypi" in data["ecosystems"]
