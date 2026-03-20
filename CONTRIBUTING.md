# Contributing to sbom-report-generator

Thank you for your interest in contributing! Here are a few guidelines to help
you get started.

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
   git checkout -b my-feature
   ```

## Making Changes

- Keep changes focused — one feature or fix per pull request.
- Follow the existing code style (PEP 8, type hints where used).
- Add or update tests if applicable.
- Update documentation if your change affects user-facing behavior.

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
