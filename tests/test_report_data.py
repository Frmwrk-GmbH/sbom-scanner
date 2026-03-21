"""Tests for report_data.py — shared data processing functions."""

import json
from sbom_scanner.report_data import (
    load_sbom, get_prop, severity_order, version_distance,
    classify_components, eco_stats, get_eco_config,
    build_dep_lookup, purl_to_name, is_outdated,
    count_outdated_deep, diff_badge, status_badge, tags_html,
)


class TestGetProp:
    def test_found(self):
        comp = {"properties": [{"name": "cdx:ecosystem", "value": "npm"}]}
        assert get_prop(comp, "cdx:ecosystem") == "npm"

    def test_not_found(self):
        comp = {"properties": [{"name": "cdx:ecosystem", "value": "npm"}]}
        assert get_prop(comp, "cdx:missing") is None

    def test_empty_properties(self):
        assert get_prop({"properties": []}, "x") is None
        assert get_prop({}, "x") is None


class TestSeverityOrder:
    def test_critical(self):
        assert severity_order("Critical") == 0

    def test_high(self):
        assert severity_order("High") == 1

    def test_medium(self):
        assert severity_order("Medium") == 2

    def test_low(self):
        assert severity_order("Low") == 3

    def test_unknown(self):
        assert severity_order("") == 4
        assert severity_order("something") == 4


class TestVersionDistance:
    def test_same(self):
        assert version_distance("1.2.3", "1.2.3") == 0

    def test_major(self):
        assert version_distance("1.0.0", "3.0.0") == 2

    def test_minor(self):
        assert version_distance("1.0.0", "1.5.0") == 0

    def test_invalid(self):
        assert version_distance("abc", "def") == 0


class TestClassifyComponents:
    def test_groups_by_ecosystem(self, minimal_sbom):
        _, sbom = minimal_sbom
        groups = classify_components(sbom["components"])
        assert "npm" in groups
        assert "pypi" in groups
        assert len(groups["npm"]) == 2
        assert len(groups["pypi"]) == 1

    def test_multiroot_tags(self):
        comps = [
            {"name": "a", "tags": ["frontend"], "properties": [{"name": "cdx:ecosystem", "value": "npm"}]},
            {"name": "b", "tags": ["admin"], "properties": [{"name": "cdx:ecosystem", "value": "npm"}]},
        ]
        groups = classify_components(comps)
        assert "npm:frontend" in groups
        assert "npm:admin" in groups


class TestEcoStats:
    def test_counts(self, minimal_sbom):
        _, sbom = minimal_sbom
        npm_comps = [c for c in sbom["components"] if get_prop(c, "cdx:ecosystem") == "npm"]
        stats = eco_stats("npm", npm_comps)
        assert stats["total"] == 2
        assert len(stats["outdated"]) == 1  # express is outdated, debug is current


class TestBuildDepLookup:
    def test_builds_graph(self, minimal_sbom):
        _, sbom = minimal_sbom
        lookup = build_dep_lookup(sbom)
        assert "pkg:npm/express@4.18.2" in lookup["pkg:generic/test-app@1.0.0"]
        assert "pkg:npm/debug@4.3.4" in lookup["pkg:npm/express@4.18.2"]


class TestPurlToName:
    def test_npm(self):
        assert purl_to_name("pkg:npm/express@4.18.2") == "express@4.18.2"

    def test_scoped(self):
        assert purl_to_name("pkg:npm/@scope/name@1.0.0") == "@scope/name@1.0.0"

    def test_no_version(self):
        # Without @, the full purl is returned (no version separator)
        assert purl_to_name("pkg:npm/express") == "pkg:npm/express"


class TestIsOutdated:
    def test_outdated(self, minimal_sbom):
        _, sbom = minimal_sbom
        from sbom_scanner.report_data import get_report_config
        comp_lookup = {c["purl"]: c for c in sbom["components"]}
        eco_cfgs = get_report_config()
        assert is_outdated("pkg:npm/express@4.18.2", comp_lookup, eco_cfgs)

    def test_current(self, minimal_sbom):
        _, sbom = minimal_sbom
        from sbom_scanner.report_data import get_report_config
        comp_lookup = {c["purl"]: c for c in sbom["components"]}
        eco_cfgs = get_report_config()
        assert not is_outdated("pkg:npm/debug@4.3.4", comp_lookup, eco_cfgs)


class TestCountOutdatedDeep:
    def test_counts_descendants(self, minimal_sbom):
        _, sbom = minimal_sbom
        from sbom_scanner.report_data import get_report_config
        dep_lookup = build_dep_lookup(sbom)
        comp_lookup = {c["purl"]: c for c in sbom["components"]}
        eco_cfgs = get_report_config()
        cache = {}
        # express has 1 child (debug) which is current → 0 outdated deep
        count = count_outdated_deep("pkg:npm/express@4.18.2", dep_lookup, comp_lookup, eco_cfgs, cache)
        assert count == 0


class TestBadges:
    def test_diff_badge_critical(self):
        assert "critical" in diff_badge(3)

    def test_diff_badge_warning(self):
        assert "warning" in diff_badge(1)

    def test_diff_badge_minor(self):
        assert "minor" in diff_badge(0)

    def test_status_badge(self):
        assert "Major behind" in status_badge(2)
        assert "Update available" in status_badge(0)


class TestTagsHtml:
    def test_with_tags(self):
        html = tags_html({"tags": ["frontend", "react"]})
        assert "frontend" in html
        assert "react" in html

    def test_no_tags(self):
        assert tags_html({}) == ""
        assert tags_html({"tags": []}) == ""


class TestLoadSbom:
    def test_loads(self, minimal_sbom):
        path, expected = minimal_sbom
        loaded = load_sbom(path)
        assert loaded["bomFormat"] == "CycloneDX"
        assert len(loaded["components"]) == 3
