# SBOM Scanner

A modular, multi-ecosystem SBOM scanner for software projects. Produces a [CycloneDX 1.6](https://cyclonedx.org/) SBOM of all dependencies (including transitive) and generates reports in multiple formats with CVE scanning and version analysis.

## Features

- **Multi-ecosystem** — npm, yarn, PyPI, Dart/Flutter, Maven/Gradle, Rust/Cargo
- **Multiroot / Monorepo** — multiple lockfiles per ecosystem, with labels and tags
- **Gradle subprojects** — automatic detection and scanning of all submodules
- **Ecosystem-specific options** — include/exclude dev deps, choose dependency tree method, select Gradle configurations
- **Auto-detect** — discovers ecosystems automatically from lockfiles
- **Auto-configurator** — recursively scans projects and generates config interactively (fancy TUI or simple text mode)
- **CVE scanning** — pluggable scanner architecture with [grype](https://github.com/anchore/grype) and [osv-scanner](https://github.com/google/osv-scanner) built in
- **Latest-version check** — parallel lookups against npm, PyPI, crates.io, Maven Central, Google Maven
- **Multiple output formats** — HTML (interactive), simple HTML, PDF, JSON, CSV
- **Dependency tree** — expandable, animated, outdated descendants bubble up, sub-tabs per ecosystem/module
- **Fully modular** — three plugin registries: ecosystems, scanners, renderers — each extensible with one file + registry entry
- **Library API** — directly importable (`from sbom_scanner import generate_sbom, generate_report`)
- **i18n** — English by default, German translation included (`--lang de`)
- **Installable** — `pip install` with a single `sbom` compound command

## Quickstart

```bash
# Install
pip install sbom-scanner[all]

# 1. Generate config (interactive — scans the project and asks)
sbom configure --project-dir /path/to/project

# 2. Scan dependencies and generate SBOM
sbom scan --project-dir /path/to/project

# 3. Generate report
sbom report --project-dir /path/to/project
sbom report --project-dir /path/to/project --format json
sbom report --project-dir /path/to/project --format csv
sbom report --project-dir /path/to/project --format pdf

# Open report
open /path/to/project/sbom-report.html
```

Step 1 is optional — without a config file, ecosystems are auto-detected with default paths. Config is recommended for monorepos or subdirectory layouts.

## Installation

```bash
# From PyPI
pip install sbom-scanner[all]

# From the repository
pip install .[all]

# For development
pip install -e .[all]
```

**Optional extras:**

| Extra | Installs | When needed |
|---|---|---|
| `yaml` | PyYAML | YAML config and Dart/Flutter |
| `python` | pipdeptree | Transitive Python deps and dependency graph |
| `pdf` | weasyprint | PDF export (alternative: Chrome headless) |
| `tui` | rich, InquirerPy | Fancy interactive configurator |
| `all` | all of the above | Recommended |

**External tools (optional):**

| Tool | When needed |
|---|---|
| [grype](https://github.com/anchore/grype) | CVE scanning |
| [osv-scanner](https://github.com/google/osv-scanner) | CVE scanning |
| Google Chrome / Chromium | PDF export (alternative to weasyprint) |
| `dart` CLI | Dart/Flutter outdated check |

## Output Formats

| Format | Flag | Description |
|---|---|---|
| `html` | `--format html` (default) | Interactive report with tabs, search, filters, dependency tree, dark mode |
| `simple-html` | `--format simple-html` | Flat HTML without JavaScript — suitable for email or archiving |
| `pdf` | `--format pdf` | PDF via weasyprint, Chrome headless, or wkhtmltopdf |
| `json` | `--format json` | Structured JSON with metadata, vulnerabilities, and per-ecosystem package data |
| `csv` | `--format csv` | Flat CSV for import into Excel, Google Sheets, or databases |

Backward-compatible aliases: `--simple` = `--format simple-html`, `--pdf` = `--format pdf`

## Configuration

Create an `sbom.config.yaml` in the project directory (or let `sbom configure` generate it):

### Minimal config

```yaml
project:
  name: my-app
  version: "1.0.0"
```

### Full config

```yaml
project:
  name: my-app
  version: "2.0.0"
  description: "My application"

# Only specify when paths differ from defaults.
# Omit = auto-detect with default paths.
sources:
  npm:
    package_json: package.json        # default
    lockfile: package-lock.json       # default (also supports yarn.lock)
    include_dev: true                 # include devDependencies (default: true)
    include_optional: true            # include optionalDependencies (default: true)
  pypi:
    requirements: requirements.txt    # default (pip-compile or plain)
    dep_tree_method: auto             # auto | pipdeptree | pip-compile | flat
  pub:
    pubspec_yaml: pubspec.yaml        # default
    pubspec_lock: pubspec.lock        # default
    include_dev: true                 # include dev_dependencies (default: true)
  maven:
    gradle_dir: .                     # default (root with build.gradle)
    configurations:                   # Gradle configurations to scan
      - runtimeClasspath              # default
    include_subprojects: true         # scan subprojects (default: true)
  cargo:
    cargo_toml: Cargo.toml            # default
    lockfile: Cargo.lock              # default
    include_dev: true                 # include [dev-dependencies] (default: true)
    include_build: false              # include [build-dependencies] (default: false)

output:
  sbom: sbom.cyclonedx.json
  report: sbom-report.html
  format: html                        # html | simple-html | pdf | json | csv

options:
  skip_cve: false
  workers: 20
```

### Subdirectory paths

When lockfiles are not in the project root:

```yaml
project:
  name: my-fullstack-app
  version: "1.0.0"

sources:
  pypi:
    requirements: backend/requirements.txt
  npm:
    package_json: frontend/package.json
    lockfile: frontend/package-lock.json
```

### Multiroot / Monorepo

Multiple instances of the same ecosystem as a list:

```yaml
project:
  name: my-monorepo
  version: "3.0.0"

sources:
  npm:
    - label: frontend
      package_json: apps/frontend/package.json
      lockfile: apps/frontend/package-lock.json
      tags: [web, react]
      include_dev: false
    - label: admin
      package_json: apps/admin/package.json
      lockfile: apps/admin/package-lock.json
  cargo:
    cargo_toml: services/api/Cargo.toml
    lockfile: services/api/Cargo.lock
```

- **`label`** — Display name in the report. Fallback: derived from the directory path when multiple entries exist.
- **`tags`** — Applied as [CycloneDX tags](https://cyclonedx.org/docs/1.6/json/#components_items_tags) to each component. Shown as badges in the report and available in the SBOM JSON for automation.

### Gradle subprojects

Gradle projects with submodules are detected automatically. All subprojects (`:client`, `:server`, `:common` etc.) are scanned individually. Module filters and dependency tree sub-tabs appear in the report.

```yaml
sources:
  maven:
    gradle_dir: .
    configurations:
      - runtimeClasspath
      - testRuntimeClasspath
    include_subprojects: true
```

## Auto-Configurator

Instead of writing the config manually:

```bash
sbom configure --project-dir /path/to/project
```

With `rich` + `InquirerPy` installed, you get a fancy TUI with cursor navigation, status table, ecosystem-specific options, and a global options submenu. Without these dependencies, a simple text menu is used as fallback (`--simple` forces it).

Features:
- Recursively scans, skips `node_modules`, `target`, `.venv` etc.
- Suggests labels from directory names
- Reads project name/version from manifest files
- Loads existing config for editing
- Per-ecosystem options submenu (dev deps, Gradle configurations, etc.)
- Global options: CVE scan, PDF, simple report, workers
- `--non-interactive` accepts all defaults

## CLI Reference

### sbom configure

```
sbom configure [--project-dir DIR] [--output FILE] [--non-interactive] [--simple] [--lang LANG]
```

| Flag | Default | Description |
|---|---|---|
| `--project-dir` | `.` | Project directory to scan |
| `--output` | `sbom.config.yaml` | Output path (relative to project-dir) |
| `--non-interactive` | `false` | Accept all defaults |
| `--simple` | `false` | Force simple text menu (no TUI) |
| `--lang` | `en` | Language (`en`, `de`) |

### sbom scan

```
sbom scan [--project-dir DIR] [--config FILE] [--output FILE] [--lang LANG]
```

| Flag | Default | Description |
|---|---|---|
| `--project-dir` | `.` | Project directory |
| `--config` | `sbom.config.yaml` | Configuration file (in project-dir) |
| `--output` | from config or `sbom.cyclonedx.json` | Output path |
| `--lang` | `en` | Language (`en`, `de`) |

### sbom report

```
sbom report [--project-dir DIR] [--config FILE] [--sbom FILE] [--output FILE] [--format FMT] [--skip-cve] [--lang LANG]
```

| Flag | Default | Description |
|---|---|---|
| `--project-dir` | `.` | Project directory |
| `--config` | `sbom.config.yaml` | Configuration file |
| `--sbom` | from config or `sbom.cyclonedx.json` | Input SBOM |
| `--output` | from config or auto (based on format) | Output path |
| `--format` | `html` | Output format: `html`, `simple-html`, `pdf`, `json`, `csv` |
| `--skip-cve` | `false` | Skip CVE scanning |
| `--lang` | `en` | Language (`en`, `de`) |
| `--simple` | | Alias for `--format simple-html` |
| `--pdf` | | Alias for `--format pdf` |

### sbom version

Shows version and copyright.

## Library API

Directly importable in Python:

```python
from pathlib import Path
from sbom_scanner import generate_sbom, generate_report, load_config

project = Path("../my-project")
config = load_config(project / "sbom.config.yaml")
sbom_path = project / "sbom.cyclonedx.json"

# Scan dependencies
generate_sbom(project, config, sbom_path)

# Generate report (default: interactive HTML)
generate_report(sbom_path, project / "sbom-report.html", skip_cve=True)
```

## Supported Ecosystems

| Ecosystem | Lockfile | Registry | Options |
|---|---|---|---|
| npm | `package-lock.json` (v1/v2/v3), `yarn.lock` (v1) | npmjs.org | `include_dev`, `include_optional` |
| PyPI | `requirements.txt` (pip-compile or plain) | pypi.org | `dep_tree_method` |
| Dart/Flutter | `pubspec.lock` | pub.dev | `include_dev` |
| Maven/Gradle | `build.gradle` / `build.gradle.kts` | Maven Central + Google Maven | `configurations` (multi-select), `include_subprojects` |
| Rust/Cargo | `Cargo.lock` | crates.io | `include_dev`, `include_build` |

## Plugin Architecture

Three plugin registries, all following the same pattern: base class + registry + one file per plugin.

### Adding a New Ecosystem

Just one file + registry entry. No changes to scanners, renderers, or the configurator needed.

1. Create `src/sbom_scanner/ecosystems/composer.py`:

```python
from .base import Ecosystem

class ComposerEcosystem(Ecosystem):
    name = "composer"
    display_name = "PHP/Composer"
    cdx_prefix = "cdx:composer"
    purl_type = "composer"
    package_url_template = "https://packagist.org/packages/{name}"
    dep_property = "cdx:composer:dependency"
    latest_property = "cdx:composer:latestVersion"
    dep_labels = {"direct main": "direct", "transitive": "transitive"}

    def scan_pattern(self):
        return {
            "detect_files": ["composer.lock"],
            "companion_files": ["composer.json"],
            "config_keys": {"composer.lock": "lockfile", "composer.json": "composer_json"},
            "icon": "🐘",
        }

    def config_options(self):
        return [
            {"key": "include_dev", "label": "Include dev dependencies", "type": "bool", "default": True},
        ]

    def detect(self, project_dir, config): ...
    def parse(self, project_dir, config): ...
    def fetch_latest_versions(self, packages, workers=20): ...
    def build_component(self, pkg, latest): ...
    def get_direct_purls(self, packages): ...
```

2. Register in `src/sbom_scanner/ecosystems/__init__.py`.

### Adding a New CVE Scanner

1. Create `src/sbom_scanner/scanners/trivy.py`:

```python
from .base import Scanner

class TrivyScanner(Scanner):
    name = "trivy"
    targets = ["*"]  # or ["npm", "pypi"] for specific ecosystems

    def is_available(self): ...
    def scan(self, sbom_path, lockfiles, project_dir): ...
```

2. Register in `src/sbom_scanner/scanners/__init__.py`.

**Built-in scanners:**

| Scanner | Type | Targets |
|---|---|---|
| grype | SBOM-based | `*` |
| osv | Lockfile-based | `*` |

### Adding a New Report Renderer

1. Create `src/sbom_scanner/renderers/markdown.py`:

```python
from .base import Renderer

class MarkdownRenderer(Renderer):
    name = "markdown"
    display_name = "Markdown Report"
    file_extension = ".md"

    def render(self, sbom, vulns, output_path, **kwargs):
        from ..report_data import classify_components, eco_stats, get_eco_config
        # Build markdown output from sbom data
        ...
        return output_path
```

2. Register in `src/sbom_scanner/renderers/__init__.py`.

**Built-in renderers:**

| Renderer | Format | Description |
|---|---|---|
| `html` | Interactive HTML | Tabs, search, filters, dependency tree, dark mode |
| `simple-html` | Flat HTML | No JavaScript, suitable for email/archiving |
| `pdf` | PDF | Via weasyprint, Chrome headless, or wkhtmltopdf |
| `json` | JSON | Structured data for automation |
| `csv` | CSV | Flat table for spreadsheets |

## Project Structure

```
sbom-scanner/
├── pyproject.toml
├── README.md
├── LICENSE                             # MIT
├── CONTRIBUTING.md
├── sbom.config.yaml                    # Example config
└── src/
    └── sbom_scanner/
        ├── __init__.py                 # Version + library API
        ├── cli.py                      # Compound CLI: sbom <command>
        ├── i18n.py                     # Internationalization (gettext)
        ├── configure.py                # sbom configure (TUI + simple fallback)
        ├── generate_sbom.py            # sbom scan (ecosystem-agnostic)
        ├── generate_sbom_report.py     # sbom report (orchestrator)
        ├── report_data.py              # Shared data processing for renderers
        ├── ecosystems/
        │   ├── __init__.py             # Registry
        │   ├── base.py                 # Base class (Ecosystem)
        │   ├── npm.py                  # npm + yarn
        │   ├── pypi.py                 # PyPI + pipdeptree
        │   ├── pub.py                  # Dart/Flutter
        │   ├── maven.py                # Maven/Gradle + subprojects
        │   └── cargo.py                # Rust/Cargo
        ├── scanners/
        │   ├── __init__.py             # Registry
        │   ├── base.py                 # Base class (Scanner)
        │   ├── grype.py                # grype (SBOM-based)
        │   └── osv.py                  # osv-scanner (lockfile-based)
        ├── renderers/
        │   ├── __init__.py             # Registry
        │   ├── base.py                 # Base class (Renderer)
        │   ├── html.py                 # Interactive HTML report
        │   ├── simple_html.py          # Simple flat HTML report
        │   ├── pdf.py                  # PDF conversion
        │   ├── json_report.py          # JSON output
        │   └── csv_report.py           # CSV output
        └── locales/
            └── de/LC_MESSAGES/         # German translation (.po/.mo)
```

## CI/CD Integration

### GitLab CI

```yaml
sbom:
  stage: test
  script:
    - pip install sbom-scanner[all]
    - sbom scan --project-dir .
    - sbom report --project-dir . --skip-cve
    - sbom report --project-dir . --format json --output sbom-report.json --skip-cve
  artifacts:
    paths:
      - sbom.cyclonedx.json
      - sbom-report.html
      - sbom-report.json
```

### GitHub Actions

```yaml
- name: SBOM Scan
  run: |
    pip install sbom-scanner[all]
    sbom scan --project-dir .
    sbom report --project-dir . --format html --skip-cve
    sbom report --project-dir . --format json --skip-cve
```

### With CVE scanning

```yaml
before_script:
  - pip install sbom-scanner[all]
  - curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
script:
  - sbom scan --project-dir .
  - sbom report --project-dir .
```

## License

MIT — © 2026 Frmwrk GmbH
