"""Shared test fixtures."""

import json
import pytest
from pathlib import Path


@pytest.fixture
def minimal_sbom(tmp_path):
    """A minimal valid CycloneDX 1.6 SBOM with a few components."""
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000000",
        "version": 1,
        "metadata": {
            "timestamp": "2026-01-01T00:00:00Z",
            "tools": {"components": [{"type": "application", "name": "test", "version": "1.0.0"}]},
            "component": {
                "type": "application",
                "name": "test-app",
                "version": "1.0.0",
                "bom-ref": "pkg:generic/test-app@1.0.0",
                "purl": "pkg:generic/test-app@1.0.0",
            },
        },
        "components": [
            {
                "type": "library", "group": "npmjs", "name": "express", "version": "4.18.2",
                "purl": "pkg:npm/express@4.18.2", "bom-ref": "pkg:npm/express@4.18.2",
                "externalReferences": [{"type": "distribution", "url": "https://www.npmjs.com/package/express"}],
                "properties": [
                    {"name": "cdx:ecosystem", "value": "npm"},
                    {"name": "cdx:npm:dependency", "value": "direct main"},
                    {"name": "cdx:npm:latestVersion", "value": "5.0.0"},
                ],
            },
            {
                "type": "library", "group": "npmjs", "name": "debug", "version": "4.3.4",
                "purl": "pkg:npm/debug@4.3.4", "bom-ref": "pkg:npm/debug@4.3.4",
                "properties": [
                    {"name": "cdx:ecosystem", "value": "npm"},
                    {"name": "cdx:npm:dependency", "value": "transitive"},
                    {"name": "cdx:npm:latestVersion", "value": "4.3.4"},
                ],
            },
            {
                "type": "library", "group": "pypi", "name": "flask", "version": "2.3.0",
                "purl": "pkg:pypi/flask@2.3.0", "bom-ref": "pkg:pypi/flask@2.3.0",
                "externalReferences": [{"type": "distribution", "url": "https://pypi.org/project/flask/"}],
                "properties": [
                    {"name": "cdx:ecosystem", "value": "pypi"},
                    {"name": "cdx:pip:dependency", "value": "direct main"},
                    {"name": "cdx:pypi:latestVersion", "value": "3.1.0"},
                ],
            },
        ],
        "dependencies": [
            {
                "ref": "pkg:generic/test-app@1.0.0",
                "dependsOn": ["pkg:npm/express@4.18.2", "pkg:pypi/flask@2.3.0"],
            },
            {
                "ref": "pkg:npm/express@4.18.2",
                "dependsOn": ["pkg:npm/debug@4.3.4"],
            },
        ],
    }
    path = tmp_path / "sbom.cyclonedx.json"
    path.write_text(json.dumps(sbom, indent=2))
    return path, sbom


@pytest.fixture
def npm_project(tmp_path):
    """A minimal npm project with package.json and package-lock.json."""
    pkg = {"name": "test-npm", "version": "1.0.0", "dependencies": {"is-odd": "^3.0.1"}}
    lock = {
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "test-npm", "version": "1.0.0"},
            "node_modules/is-odd": {"version": "3.0.1", "resolved": "https://registry.npmjs.org/is-odd/-/is-odd-3.0.1.tgz"},
            "node_modules/is-number": {"version": "6.0.0", "resolved": "https://registry.npmjs.org/is-number/-/is-number-6.0.0.tgz"},
        },
    }
    (tmp_path / "package.json").write_text(json.dumps(pkg))
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    return tmp_path


@pytest.fixture
def pypi_project(tmp_path):
    """A minimal PyPI project with requirements.txt."""
    (tmp_path / "requirements.txt").write_text("flask==2.3.0\nrequests==2.31.0\n")
    return tmp_path


@pytest.fixture
def cargo_project(tmp_path):
    """A minimal Cargo project."""
    (tmp_path / "Cargo.toml").write_text('[package]\nname = "test-cargo"\nversion = "0.1.0"\n\n[dependencies]\nserde = "1.0"\n')
    (tmp_path / "Cargo.lock").write_text('[[package]]\nname = "serde"\nversion = "1.0.200"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n')
    return tmp_path
