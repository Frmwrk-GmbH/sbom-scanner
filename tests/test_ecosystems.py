"""Tests for ecosystem detection and parsing."""

from sbom_scanner.ecosystems import REGISTRY, get_ecosystem
from sbom_scanner.ecosystems.npm import NpmEcosystem
from sbom_scanner.ecosystems.pypi import PypiEcosystem
from sbom_scanner.ecosystems.cargo import CargoEcosystem


class TestRegistry:
    def test_all_registered(self):
        names = [e.name for e in REGISTRY]
        assert "npm" in names
        assert "pypi" in names
        assert "pub" in names
        assert "maven" in names
        assert "cargo" in names

    def test_get_ecosystem(self):
        assert get_ecosystem("npm") is not None
        assert get_ecosystem("nonexistent") is None


class TestEcosystemBaseProperties:
    def test_report_config(self):
        for eco in REGISTRY:
            cfg = eco.report_config()
            assert "display_name" in cfg
            assert "dep_prop" in cfg
            assert "latest_prop" in cfg
            assert "url_template" in cfg
            assert "purl_type" in cfg

    def test_scan_pattern(self):
        for eco in REGISTRY:
            pat = eco.scan_pattern()
            assert pat is not None, f"{eco.name} has no scan_pattern"
            assert "icon" in pat

    def test_config_options(self):
        for eco in REGISTRY:
            opts = eco.config_options()
            assert isinstance(opts, list)
            for opt in opts:
                assert "key" in opt
                assert "type" in opt
                assert "default" in opt

    def test_default_config(self):
        for eco in REGISTRY:
            dc = eco.default_config()
            assert isinstance(dc, dict)


class TestNpmEcosystem:
    def test_detect(self, npm_project):
        eco = NpmEcosystem()
        assert eco.detect(npm_project, {})

    def test_detect_missing(self, tmp_path):
        eco = NpmEcosystem()
        assert not eco.detect(tmp_path, {})

    def test_parse(self, npm_project):
        eco = NpmEcosystem()
        packages = eco.parse(npm_project, {})
        assert len(packages) == 2
        names = {p["name"] for p in packages}
        assert "is-odd" in names
        assert "is-number" in names

    def test_parse_dep_types(self, npm_project):
        eco = NpmEcosystem()
        packages = eco.parse(npm_project, {})
        by_name = {p["name"]: p for p in packages}
        assert by_name["is-odd"]["dep_type"] == "direct main"
        assert by_name["is-number"]["dep_type"] == "transitive"

    def test_exclude_dev(self, tmp_path):
        import json
        pkg = {"name": "t", "version": "1.0.0", "dependencies": {"a": "1.0"}, "devDependencies": {"b": "1.0"}}
        lock = {"lockfileVersion": 3, "packages": {
            "": {},
            "node_modules/a": {"version": "1.0.0"},
            "node_modules/b": {"version": "1.0.0", "dev": True},
        }}
        (tmp_path / "package.json").write_text(json.dumps(pkg))
        (tmp_path / "package-lock.json").write_text(json.dumps(lock))
        eco = NpmEcosystem()
        all_pkgs = eco.parse(tmp_path, {})
        assert len(all_pkgs) == 2
        no_dev = eco.parse(tmp_path, {"include_dev": False})
        assert len(no_dev) == 1
        assert no_dev[0]["name"] == "a"

    def test_build_component(self):
        eco = NpmEcosystem()
        pkg = {"name": "express", "version": "4.18.2", "dep_type": "direct main",
               "resolved": "", "integrity": "sha512-abc"}
        comp = eco.build_component(pkg, "5.0.0")
        assert comp["purl"] == "pkg:npm/express@4.18.2"
        assert comp["version"] == "4.18.2"
        props = {p["name"]: p["value"] for p in comp["properties"]}
        assert props["cdx:npm:latestVersion"] == "5.0.0"

    def test_read_project_info(self, npm_project):
        eco = NpmEcosystem()
        info = eco.read_project_info(npm_project)
        assert info == ("test-npm", "1.0.0")


class TestPypiEcosystem:
    def test_detect(self, pypi_project):
        eco = PypiEcosystem()
        assert eco.detect(pypi_project, {})

    def test_parse(self, pypi_project):
        eco = PypiEcosystem()
        packages = eco.parse(pypi_project, {})
        assert len(packages) == 2
        names = {p["name"] for p in packages}
        assert "flask" in names
        assert "requests" in names

    def test_all_direct_in_simple_requirements(self, pypi_project):
        eco = PypiEcosystem()
        packages = eco.parse(pypi_project, {})
        assert all(p["direct"] for p in packages)

    def test_pip_compile_format(self, tmp_path):
        (tmp_path / "requirements.txt").write_text(
            "flask==2.3.0\n"
            "    # via -r requirements.in\n"
            "werkzeug==2.3.0\n"
            "    # via flask\n"
        )
        eco = PypiEcosystem()
        packages = eco.parse(tmp_path, {})
        by_name = {p["name"]: p for p in packages}
        assert by_name["flask"]["direct"]
        assert not by_name["werkzeug"]["direct"]


class TestCargoEcosystem:
    def test_detect(self, cargo_project):
        eco = CargoEcosystem()
        assert eco.detect(cargo_project, {})

    def test_parse(self, cargo_project):
        eco = CargoEcosystem()
        packages = eco.parse(cargo_project, {})
        assert len(packages) == 1
        assert packages[0]["name"] == "serde"
        assert packages[0]["version"] == "1.0.200"

    def test_read_project_info(self, cargo_project):
        eco = CargoEcosystem()
        info = eco.read_project_info(cargo_project)
        assert info == ("test-cargo", "0.1.0")
