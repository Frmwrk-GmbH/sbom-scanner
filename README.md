# SBOM Scanner

A generic SBOM and HTML report generator for software projects. Produces a [CycloneDX 1.6](https://cyclonedx.org/) SBOM of all dependencies (including transitive) and an interactive HTML report with CVE scanning and version analysis.

## Features

- **Multi-ecosystem** — npm, PyPI, Dart/Flutter, Maven/Gradle, Rust/Cargo, yarn
- **Multiroot / Monorepo** — multiple lockfiles per ecosystem, with labels and tags
- **Gradle subprojects** — automatic detection and scanning of all submodules
- **Auto-detect** — discovers ecosystems automatically from lockfiles
- **Auto-configurator** — recursively scans projects and generates config interactively (fancy TUI or simple text mode)
- **CVE scanning** — pluggable scanner architecture with [grype](https://github.com/anchore/grype) and [osv-scanner](https://github.com/google/osv-scanner) built in
- **Latest-version check** — parallel lookups against npm, PyPI, crates.io, Maven Central, Google Maven
- **HTML report** — tabs, search, filters (dependency type, module, status), dark mode, print styles
- **Dependency tree** — expandable, animated, outdated descendants bubble up, sub-tabs per ecosystem/module
- **PDF export** — via weasyprint, Chrome headless, or wkhtmltopdf
- **Two report modes** — interactive (tabs/JS) with `--simple` fallback (flat, no JS)
- **Fully modular** — new ecosystem or CVE scanner = one file + registry entry, no changes to the report generator
- **Library API** — directly importable (`from sbom_scanner import generate_sbom, generate_report`)
- **i18n** — English by default, German translation included (`--lang de`)
- **Installable** — `pip install` with three CLI commands

## Quickstart

```bash
# Install
pip install sbom-scanner[all]

# 1. Generate config (interactive — scans the project and asks)
sbom configure --project-dir /path/to/project

# 2. Generate SBOM
sbom scan --project-dir /path/to/project

# 3. Generate HTML report
sbom report --project-dir /path/to/project

# Open report
open /path/to/project/sbom-report.html
```

Step 1 is optional — without a config file, ecosystems are auto-detected with default paths. Config is recommended for monorepos or subdirectory layouts.

## Installation

```bash
# From PyPI (once published)
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
| `all` | PyYAML + pipdeptree + rich + InquirerPy | Recommended |

**External tools (optional):**

| Tool | When needed |
|---|---|
| [grype](https://github.com/anchore/grype) | CVE scanning |
| [osv-scanner](https://github.com/google/osv-scanner) | CVE scanning |
| Google Chrome / Chromium | PDF export (alternative to weasyprint) |
| `dart` CLI | Dart/Flutter outdated check |

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
  pypi:
    requirements: requirements.txt    # default (pip-compile or plain)
  pub:
    pubspec_yaml: pubspec.yaml        # default
    pubspec_lock: pubspec.lock        # default
  maven:
    gradle_dir: .                     # default (root with build.gradle)
    configuration: runtimeClasspath   # default
  cargo:
    cargo_toml: Cargo.toml            # default
    lockfile: Cargo.lock              # default

output:
  sbom: sbom.cyclonedx.json
  report: sbom-report.html

options:
  skip_cve: false
  pdf: false
  simple: false
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
    - label: admin
      package_json: apps/admin/package.json
      lockfile: apps/admin/package-lock.json
      tags: [internal]
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
    configuration: runtimeClasspath   # optional, default: runtimeClasspath
```

## Auto-Configurator

Instead of writing the config manually:

```bash
sbom configure --project-dir /path/to/project
```

With `rich` + `InquirerPy` installed, you get a fancy TUI with cursor navigation, status table, and options submenu. Without these dependencies, a simple text menu is used as fallback (`--simple` forces it).

Features:
- Recursively scans, skips `node_modules`, `target`, `.venv` etc.
- Suggests labels from directory names
- Reads project name/version from manifest files
- Loads existing config for editing
- Options submenu: CVE scan, PDF, simple report, workers
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
sbom report [--project-dir DIR] [--config FILE] [--sbom FILE] [--output FILE] [--skip-cve] [--pdf] [--simple] [--lang LANG]
```

| Flag | Default | Description |
|---|---|---|
| `--project-dir` | `.` | Project directory |
| `--config` | `sbom.config.yaml` | Configuration file |
| `--sbom` | from config or `sbom.cyclonedx.json` | Input SBOM |
| `--output` | from config or `sbom-report.html` | Output path |
| `--skip-cve` | `false` | Skip CVE scanning |
| `--pdf` | `false` | Additionally generate PDF (uses simple report) |
| `--simple` | `false` | Simple report without tabs, search, and filters |
| `--lang` | `en` | Language (`en`, `de`) |

## Library API

Directly importable in Python:

```python
from pathlib import Path
from sbom_scanner import generate_sbom, generate_report, load_config

project = Path("../my-project")
config = load_config(project / "sbom.config.yaml")
sbom_path = project / "sbom.cyclonedx.json"

# Generate SBOM
generate_sbom(project, config, sbom_path)

# Generate HTML report
generate_report(sbom_path, project / "sbom-report.html", skip_cve=True)
```

## Supported Ecosystems

| Ecosystem | Lockfile | Registry | Detection |
|---|---|---|---|
| npm | `package-lock.json` (v1/v2/v3), `yarn.lock` (v1) | npmjs.org | `package.json` + lockfile |
| PyPI | `requirements.txt` (pip-compile or plain) | pypi.org | `requirements.txt` |
| Dart/Flutter | `pubspec.lock` | pub.dev | `pubspec.yaml` + `pubspec.lock` |
| Maven/Gradle | `build.gradle` / `build.gradle.kts` | Maven Central + Google Maven | `build.gradle` + `gradlew` |
| Rust/Cargo | `Cargo.lock` | crates.io | `Cargo.toml` + `Cargo.lock` |

**PyPI notes:**
- pip-compile format (with `# via` comments) — automatically detects direct vs. transitive
- Plain `requirements.txt` — all packages as direct, transitive via `pipdeptree` (if installed)

**Maven/Gradle notes:**
- Subprojects are automatically detected and scanned individually
- Module membership (`:client`, `:server` etc.) shown as filter in the report
- Also supports pre-computed `gradle-dependencies.json` (custom Gradle task)

## Adding a New Ecosystem

Just one file + registry entry. **No changes to the report generator needed.**

1. Create a new file, e.g. `src/sbom_scanner/ecosystems/composer.py`:

```python
from .base import Ecosystem

class ComposerEcosystem(Ecosystem):
    # Identification
    name = "composer"
    display_name = "PHP/Composer"
    cdx_prefix = "cdx:composer"
    purl_type = "composer"

    # Report configuration
    package_url_template = "https://packagist.org/packages/{name}"
    dep_property = "cdx:composer:dependency"
    latest_property = "cdx:composer:latestVersion"
    dep_labels = {"direct main": "direct", "transitive": "transitive"}
    has_group_column = False

    # Auto-configurator pattern
    def scan_pattern(self):
        return {
            "detect_files": ["composer.lock"],
            "companion_files": ["composer.json"],
            "config_keys": {"composer.lock": "lockfile", "composer.json": "composer_json"},
            "icon": "🐘",
        }

    # Required methods
    def detect(self, project_dir, config): ...
    def parse(self, project_dir, config): ...
    def fetch_latest_versions(self, packages, workers=20): ...
    def build_component(self, pkg, latest): ...
    def get_direct_purls(self, packages): ...

    # Optional
    def parse_dependency_graph(self, project_dir, config, packages):
        return []
```

2. Register in `src/sbom_scanner/ecosystems/__init__.py`:

```python
from .composer import ComposerEcosystem

REGISTRY: list = [
    ...
    ComposerEcosystem(),
]
```

That's it. The report generator reads all properties from the class — tabs, filters, badges, tree work automatically. The auto-configurator discovers it via `scan_pattern()`.

## Adding a New CVE Scanner

Same architecture — one file + registry entry.

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

| Scanner | Type | Targets | Description |
|---|---|---|---|
| grype | SBOM-based | `*` | Scans the CycloneDX SBOM |
| osv | Lockfile-based | `*` | Scans lockfiles against the OSV database |

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
        ├── i18n.py                     # Internationalization (gettext)
        ├── configure.py                # sbom configure (TUI + simple fallback)
        ├── generate_sbom.py            # sbom scan (ecosystem-agnostic)
        ├── generate_sbom_report.py     # sbom report (ecosystem-agnostic)
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
        └── locales/
            └── de/LC_MESSAGES/         # German translation (.po/.mo)
```

## CI/CD Integration

GitLab CI example:

```yaml
sbom:
  stage: test
  script:
    - pip install sbom-scanner[all]
    - sbom scan --project-dir .
    - sbom report --project-dir . --skip-cve
  artifacts:
    paths:
      - sbom.cyclonedx.json
      - sbom-report.html
```

With CVE scanning:

```yaml
sbom:
  stage: test
  image: python:3.13
  before_script:
    - pip install sbom-scanner[all]
    - curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
  script:
    - sbom scan --project-dir .
    - sbom report --project-dir .
  artifacts:
    paths:
      - sbom.cyclonedx.json
      - sbom-report.html
```

## License

MIT — © 2026 Frmwrk GmbH
