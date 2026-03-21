# Contributing to sbom-scanner

Thank you for your interest in contributing! Here are the guidelines.

## Getting Started

1. Fork and clone the repository.
2. Create a virtual environment and install development dependencies:

   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -e ".[all]"
   ```

3. Create a feature branch from `main`:

   ```bash
   git checkout -b feature/my-feature
   # or
   git checkout -b bugfix/my-bugfix
   ```

## Making Changes

- Keep changes focused — one feature or fix per pull request.
- Follow the existing code style (PEP 8, type hints where used).
- Update documentation if your change affects user-facing behavior.

## Commit Messages

We use **semantic commit messages**:

```
tag: short description

Optional longer description explaining why (not what).
```

**Tags:**

| Tag | When to use |
|---|---|
| `feat` | New feature |
| `fix` | Bug fix |
| `refactor` | Code restructuring without behavior change |
| `docs` | Documentation only |
| `chore` | Build, CI, tooling, dependencies |
| `ci` | CI/CD pipeline changes |
| `style` | Formatting, whitespace, imports |
| `test` | Adding or updating tests |

**Examples:**

```
feat: add Go module ecosystem support

Implements Go module scanning from go.sum and go.mod files.
Includes dependency graph parsing and latest version lookups.
```

```
fix: deduplicate dependsOn entries in CycloneDX output
```

```
refactor: extract report data processing into report_data.py
```

**Rules:**
- Tag and description in English
- Lowercase after the tag (no capital letter)
- No period at the end of the short description
- Wrap the body at 72 characters

## Plugin Architecture

sbom-scanner has three plugin registries. Each is extensible with just one file + registry entry:

### Adding a new ecosystem

Create `src/sbom_scanner/ecosystems/your_ecosystem.py`, subclass `Ecosystem`, and register in `ecosystems/__init__.py`. See the README for a full example.

### Adding a new CVE scanner

Create `src/sbom_scanner/scanners/your_scanner.py`, subclass `Scanner`, and register in `scanners/__init__.py`.

### Adding a new report renderer

Create `src/sbom_scanner/renderers/your_renderer.py`, subclass `Renderer`, and register in `renderers/__init__.py`.

No other files need to be modified — the configurator, report generator, and CLI discover plugins automatically from the registries.

## Submitting a Pull Request

1. Push your branch to your fork.
2. Open a pull request against `main`.
3. Describe **what** your change does and **why**.
4. Link any related issues.

## Reporting Issues

Open an issue on GitHub with:

- A clear description of the problem or suggestion.
- Steps to reproduce (for bugs).
- Expected vs. actual behavior.

## Code of Conduct

Be respectful and constructive. We follow the
[Contributor Covenant](https://www.contributor-covenant.org/) code of conduct.

## License

By contributing, you agree that your contributions will be licensed under the
[MIT License](LICENSE).
