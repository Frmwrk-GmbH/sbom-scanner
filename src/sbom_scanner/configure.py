#!/usr/bin/env python3
"""
Auto-configurator for sbom-scanner.

Recursively searches a project directory for known lockfiles,
displays findings, and interactively generates an sbom.config.yaml.

Usage:
    sbom configure                            # current directory
    sbom configure --project-dir ../my-app    # different directory
    sbom configure --non-interactive          # accept all defaults
"""

import argparse
import json
import re
import sys
from pathlib import Path

from .i18n import _

# ── Lockfile patterns per ecosystem (loaded from registry) ────────────────────

def _load_ecosystem_patterns() -> list[dict]:
    """Build scan patterns from the ecosystem registry."""
    try:
        from .ecosystems import REGISTRY
    except ImportError:
        return []

    patterns = []
    for eco in REGISTRY:
        pat = eco.scan_pattern()
        if pat is None:
            continue
        pat["ecosystem"] = eco.name
        pat["display"] = eco.display_name
        patterns.append(pat)
    return patterns


def _get_ecosystem_patterns() -> list[dict]:
    global _PATTERNS_CACHE
    if _PATTERNS_CACHE is None:
        _PATTERNS_CACHE = _load_ecosystem_patterns()
    return _PATTERNS_CACHE


_PATTERNS_CACHE: list[dict] | None = None


def _get_ecosystem_icons() -> dict[str, str]:
    return {p["ecosystem"]: p.get("icon", "") for p in _get_ecosystem_patterns()}


def _get_eco_options(ecosystem_name: str) -> list[dict]:
    """Get config options for an ecosystem from the registry."""
    try:
        from .ecosystems import REGISTRY
        for eco in REGISTRY:
            if eco.name == ecosystem_name:
                return eco.config_options()
    except ImportError:
        pass
    return []

# Directories to skip during traversal
SKIP_DIRS = {
    "node_modules", ".git", ".svn", ".hg", "__pycache__", ".dart_tool",
    "build", "dist", ".next", ".nuxt", ".output", "target", ".gradle",
    "vendor", ".venv", "venv", "env", ".tox", ".eggs",
    ".pub-cache", ".pub", ".cache", ".turbo",
}


# ── Scan logic ───────────────────────────────────────────────────────────────

def scan_project(project_dir: Path) -> list[dict]:
    """Recursively search the project directory for lockfiles."""
    findings = []

    for pattern in _get_ecosystem_patterns():
        eco = pattern["ecosystem"]

        if "detect_dir_marker" in pattern:
            for marker_path in _walk_find(project_dir, pattern["detect_dir_marker"]):
                marker_dir = marker_path.parent
                rel_dir = marker_dir.relative_to(project_dir)
                findings.append({
                    "ecosystem": eco,
                    "display": pattern["display"],
                    "dir": str(rel_dir),
                    "files": {pattern["config_dir_key"]: str(rel_dir)},
                    "label_suggestion": _suggest_label(rel_dir, project_dir),
                })
            continue

        for detect_file in pattern["detect_files"]:
            for found_path in _walk_find(project_dir, detect_file):
                found_dir = found_path.parent
                rel_dir = found_dir.relative_to(project_dir)
                rel_file = found_path.relative_to(project_dir)

                files = {pattern["config_keys"][detect_file]: str(rel_file)}
                companions_ok = True
                for companion in pattern.get("companion_files", []):
                    companion_path = found_dir / companion
                    if companion_path.exists():
                        rel_companion = companion_path.relative_to(project_dir)
                        files[pattern["config_keys"][companion]] = str(rel_companion)
                    else:
                        companions_ok = False

                if not companions_ok:
                    continue

                findings.append({
                    "ecosystem": eco,
                    "display": pattern["display"],
                    "dir": str(rel_dir) if str(rel_dir) != "." else "(root)",
                    "files": files,
                    "label_suggestion": _suggest_label(rel_dir, project_dir),
                })

    return findings


def _walk_find(root: Path, filename: str):
    """Recursive search, skips well-known directories.

    Supports exact match ("package.json") and suffix match ("*.sln").
    """
    is_glob = filename.startswith("*.")
    suffix = filename[1:] if is_glob else None  # e.g. ".sln"
    try:
        for item in sorted(root.iterdir()):
            if item.is_dir():
                if item.name in SKIP_DIRS:
                    continue
                yield from _walk_find(item, filename)
            elif is_glob:
                if item.name.endswith(suffix):
                    yield item
            elif item.name == filename:
                yield item
    except PermissionError:
        pass


def _suggest_label(rel_dir: Path, project_dir: Path) -> str:
    """Suggest a label based on the directory name."""
    parts = str(rel_dir).replace("\\", "/").split("/")
    parts = [p for p in parts if p and p != "."]
    if not parts:
        return ""
    if len(parts) == 1:
        return parts[0]
    return "/".join(parts[-2:])


def _read_project_name(project_dir: Path, findings: list[dict]) -> tuple[str, str]:
    """Try to read project name and version from ecosystem manifests."""
    try:
        from .ecosystems import REGISTRY
        for eco in REGISTRY:
            info = eco.read_project_info(project_dir)
            if info:
                name, version = info
                if name:
                    return name, version or "0.0.0"
    except ImportError:
        pass
    return project_dir.name, "0.0.0"


# ── Config generation ────────────────────────────────────────────────────────

def generate_config(project_dir: Path, selected: list[dict], name: str, version: str,
                    options: dict | None = None, auto_version: bool = False) -> str:
    """Generate YAML config as a string."""
    lines = [
        _("# SBOM Scanner — Configuration"),
        _("# Generated for: {}").format(project_dir),
        "",
        "project:",
        f'  name: "{name}"',
    ]
    if not auto_version:
        lines.append(f'  version: "{version}"')
    else:
        lines.append(f'  # version: auto-detected from manifest')
    lines.append("")

    by_eco: dict[str, list[dict]] = {}
    for item in selected:
        by_eco.setdefault(item["ecosystem"], []).append(item)

    def _can_skip(item: dict) -> bool:
        """Check if an item uses all defaults and has no custom options."""
        if not _is_default_config(item):
            return False
        if item.get("label") or item.get("tags"):
            return False
        # Check for non-default ecosystem options
        eco_opts = item.get("eco_options", {})
        if eco_opts:
            eco_options = _get_eco_options(item["ecosystem"])
            defaults = {o["key"]: o["default"] for o in eco_options}
            if any(v != defaults.get(k) for k, v in eco_opts.items()):
                return False
        return True

    has_sources = False
    for eco, items in by_eco.items():
        if all(_can_skip(item) for item in items) and len(items) == 1:
            continue
        has_sources = True

    if has_sources:
        lines.append("sources:")
        for eco, items in by_eco.items():
            if all(_can_skip(item) for item in items) and len(items) == 1:
                continue

            lines.append(f"  {eco}:")
            if len(items) == 1:
                item = items[0]
                for key, value in item["files"].items():
                    lines.append(f"    {key}: {value}")
                if item.get("label"):
                    lines.append(f"    label: {item['label']}")
                if item.get("tags"):
                    tags_str = ", ".join(item["tags"])
                    lines.append(f"    tags: [{tags_str}]")
                _write_eco_options(lines, item, "    ")
            else:
                for item in items:
                    lines.append(f"    - label: {item.get('label', '')}")
                    for key, value in item["files"].items():
                        lines.append(f"      {key}: {value}")
                    if item.get("tags"):
                        tags_str = ", ".join(item["tags"])
                        lines.append(f"      tags: [{tags_str}]")
                    _write_eco_options(lines, item, "      ")

    # Options (only non-default values)
    defaults = {"skip_cve": False, "fetch_licenses": False, "pdf": False, "simple": False, "workers": 20}
    if options:
        non_default = {k: v for k, v in options.items() if v != defaults.get(k)}
        if non_default:
            lines.append("options:")
            for k, v in non_default.items():
                if isinstance(v, bool):
                    lines.append(f"  {k}: {'true' if v else 'false'}")
                else:
                    lines.append(f"  {k}: {v}")

    lines.append("")
    return "\n".join(lines)


def _write_eco_options(lines: list[str], item: dict, indent: str) -> None:
    """Write non-default ecosystem options to config YAML lines."""
    eco_opts = item.get("eco_options", {})
    if not eco_opts:
        return
    eco_options = _get_eco_options(item["ecosystem"])
    defaults = {o["key"]: o["default"] for o in eco_options}
    for key, value in eco_opts.items():
        if value == defaults.get(key):
            continue
        if isinstance(value, bool):
            lines.append(f"{indent}{key}: {'true' if value else 'false'}")
        elif isinstance(value, list):
            lines.append(f"{indent}{key}:")
            for v in value:
                lines.append(f"{indent}  - {v}")
        else:
            lines.append(f"{indent}{key}: {value}")


def _is_default_config(item: dict) -> bool:
    """Check if this finding uses default paths (can be omitted from config)."""
    try:
        from .ecosystems import REGISTRY
        for eco in REGISTRY:
            if eco.name == item["ecosystem"]:
                return item["files"] == eco.default_config()
    except ImportError:
        pass
    return False


# ── Interactive mode (Rich + InquirerPy) ─────────────────────────────────────

def _run_interactive(project_dir: Path, findings: list[dict], default_name: str,
                     default_version: str, output_path: Path) -> None:
    """Interactive mode with rich + InquirerPy — main menu loop."""
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        from rich.syntax import Syntax
        from rich import box
        from InquirerPy import inquirer
        from InquirerPy.separator import Separator
    except ImportError:
        _run_simple_interactive(project_dir, findings, default_name, default_version, output_path)
        return

    console = Console()

    # Load existing config?
    existing_config = None
    if output_path.exists():
        try:
            import yaml
            with open(output_path) as fh:
                existing_config = yaml.safe_load(fh) or {}
        except (ImportError, Exception):
            try:
                import json as _json
                if output_path.suffix == ".json":
                    with open(output_path) as fh:
                        existing_config = _json.load(fh)
            except Exception:
                pass

    if existing_config:
        action = inquirer.select(
            message=_("{} already exists:").format(output_path.name),
            choices=[
                {"name": "  ✎  " + _("Edit existing configuration"), "value": "edit"},
                {"name": "  ✚  " + _("Create new (from scan results)"), "value": "new"},
                {"name": "  ✕  " + _("Cancel"), "value": "cancel"},
            ],
            default="edit",
            instruction="",
        ).execute()

        if action == "cancel":
            console.print("[yellow]" + _("Cancelled.") + "[/]")
            return

        if action == "edit":
            # Map config values to findings
            proj = existing_config.get("project", {})
            default_name = proj.get("name", default_name)
            default_version = proj.get("version", default_version)
            sources = existing_config.get("sources", {})

            # Sync findings with config state
            configured_files: set[str] = set()
            for eco_key, eco_val in sources.items():
                entries = [eco_val] if isinstance(eco_val, dict) else (eco_val or [])
                for entry in entries:
                    for val in entry.values():
                        if isinstance(val, str):
                            configured_files.add(val)

            for f in findings:
                # Check if this source appears in the config
                file_vals = set(f["files"].values())
                f["enabled"] = bool(file_vals & configured_files)

                # Import label + tags from config
                eco_sources = sources.get(f["ecosystem"])
                if eco_sources:
                    entries = [eco_sources] if isinstance(eco_sources, dict) else eco_sources
                    for entry in entries:
                        entry_files = set(str(v) for v in entry.values() if isinstance(v, str))
                        if file_vals & entry_files:
                            f["label"] = entry.get("label", f.get("label_suggestion", ""))
                            f["tags"] = entry.get("tags", [])
                            break

    name = default_name
    version = default_version
    auto_version = True  # True = detect from manifest, False = use fixed value

    options = {
        "skip_cve": False,
        "fetch_licenses": False,
        "pdf": False,
        "simple": False,
        "workers": 20,
    }
    # Load options from existing config
    if existing_config:
        for key in options:
            if key in existing_config.get("options", {}):
                options[key] = existing_config["options"][key]

    # Initialize state (if not loaded from config)
    for f in findings:
        f.setdefault("enabled", True)
        f.setdefault("label", f["label_suggestion"])
        f.setdefault("tags", [])
        f.setdefault("eco_options", {})

    # ── Main menu loop ──
    cursor_idx = 0
    # Menu position: "name", "version", ("toggle", N), "options", "done", "cancel"
    next_default = ("name", None)

    while True:
        console.clear()
        console.print()
        console.print(Panel.fit(
            f"[bold cyan]SBOM Scanner[/] — Auto-Configurator\n"
            f"[dim]{project_dir}[/]\n"
            f"[dim]© 2026 Frmwrk GmbH[/]",
            border_style="cyan",
        ))
        console.print()

        # Status table
        table = Table(
            box=box.ROUNDED, border_style="dim", show_lines=False,
            title=f"[bold]{name}[/] v{version}",
            title_style="",
        )
        table.add_column("#", style="dim", width=3, justify="right")
        table.add_column("", width=2)  # Status
        table.add_column(_("Ecosystem"), style="bold")
        table.add_column(_("Directory"), style="cyan")
        table.add_column(_("Label"), style="yellow")
        table.add_column(_("Tags"), style="dim")

        for i, f in enumerate(findings, 1):
            icon = _get_ecosystem_icons().get(f["ecosystem"], "")
            status = "[green]●[/]" if f["enabled"] else "[dim]○[/]"
            tags_str = ", ".join(f["tags"]) if f["tags"] else ""
            table.add_row(
                str(i), status,
                f"{icon} {f['display']}", f["dir"],
                f["label"] or "[dim]—[/]", tags_str or "[dim]—[/]",
            )

        console.print(table)
        console.print()

        # Menu options
        enabled_count = sum(1 for f in findings if f["enabled"])
        menu_choices = []
        menu_choices.append({"name": "  ✎  " + _("Project name: {}").format(name), "value": ("name", None)})
        ver_display = f"{version} (auto)" if auto_version else version
        menu_choices.append({"name": "  ✎  " + _("Version: {}").format(ver_display), "value": ("version", None)})
        menu_choices.append(Separator())
        source_start_idx = len(menu_choices)
        for i, f in enumerate(findings):
            icon = _get_ecosystem_icons().get(f["ecosystem"], "")
            check = "●" if f["enabled"] else "○"
            menu_choices.append({
                "name": f"  {check}  {icon} {f['display']:20s} {f['dir']}",
                "value": ("toggle", i),
            })
        menu_choices.append(Separator())
        opts_summary = []
        if options["skip_cve"]:
            opts_summary.append(_("CVE off"))
        if options["fetch_licenses"]:
            opts_summary.append(_("Licenses"))
        if options["pdf"]:
            opts_summary.append("PDF")
        if options["simple"]:
            opts_summary.append("Simple")
        opts_str = ", ".join(opts_summary) if opts_summary else _("Default")
        menu_choices.append({"name": "  ⚙  " + _("Options ({})").format(opts_str), "value": ("options", None)})
        menu_choices.append(Separator())
        menu_choices.append({"name": "  ✓  " + _("Done — Generate config ({} sources)").format(enabled_count), "value": ("done", None)})
        menu_choices.append({"name": "  ✕  " + _("Cancel"), "value": ("cancel", None)})

        # Default selection
        default_value = next_default

        action, idx = inquirer.select(
            message=_("Select source to configure:"),
            choices=menu_choices,
            default=default_value,
            instruction=_("↑↓ navigate, Enter select"),
        ).execute() or ("cancel", None)

        if action == "cancel":
            console.print("[yellow]" + _("Cancelled.") + "[/]")
            return

        if action == "done":
            break

        if action == "name":
            name = inquirer.text(message=_("Project name:"), default=name).execute()
            next_default = ("version", None)
            continue

        if action == "version":
            ver_choice = inquirer.select(
                message=_("Version:"),
                choices=[
                    {"name": f"  ⚡ Auto-detect from manifest ({default_version})", "value": "auto"},
                    {"name": f"  ✎  Fixed: {version}", "value": "fixed"},
                ],
                default="auto" if auto_version else "fixed",
                instruction="",
            ).execute()
            if ver_choice == "auto":
                auto_version = True
                version = default_version
            else:
                auto_version = False
                version = inquirer.text(message=_("Version:"), default=version).execute()
            next_default = ("toggle", 0) if findings else ("options", None)
            continue

        if action == "options":
            opt_cursor = "skip_cve"
            while True:
                console.clear()
                console.print(Panel.fit(
                    "[bold cyan]" + _("Options") + "[/] \u2014 " + f"{name} v{version}",
                    border_style="cyan",
                ))
                console.print()
                opt_choices = [
                    {"name": _("  CVE scan:       {}").format(_('Off') if options['skip_cve'] else _('On')), "value": "skip_cve"},
                    {"name": _("  Fetch licenses: {}").format(_('Yes') if options['fetch_licenses'] else _('No')), "value": "fetch_licenses"},
                    {"name": _("  Generate PDF:   {}").format(_('Yes') if options['pdf'] else _('No')), "value": "pdf"},
                    {"name": _("  Simple report:  {}").format(_('Yes') if options['simple'] else _('No')), "value": "simple"},
                    {"name": _("  Workers:        {}").format(options['workers']), "value": "workers"},
                    Separator(),
                    {"name": "  ←  " + _("Back"), "value": "back"},
                ]
                opt_action = inquirer.select(
                    message=_("Options:"),
                    choices=opt_choices,
                    default=opt_cursor,
                    instruction="",
                ).execute()

                if opt_action == "back":
                    break
                elif opt_action == "workers":
                    val = inquirer.text(
                        message=_("Parallel workers:"),
                        default=str(options["workers"]),
                    ).execute()
                    try:
                        options["workers"] = int(val)
                    except ValueError:
                        pass
                elif opt_action in options:
                    options[opt_action] = not options[opt_action]
                opt_cursor = opt_action
            next_default = ("done", None)
            continue

        if action == "toggle":
            finding = findings[idx]
            icon = _get_ecosystem_icons().get(finding["ecosystem"], "")

            console.print(f"\n  {icon} [bold]{finding['display']}[/] — [cyan]{finding['dir']}[/]")
            files = ", ".join(finding["files"].values())
            console.print("  [dim]" + _("Files: {}").format(files) + "[/]\n")

            # Toggle + configure as select
            sub_choices = []
            # Get ecosystem-specific options
            eco_options = _get_eco_options(finding["ecosystem"])

            if finding["enabled"]:
                sub_choices.append({"name": "  ○  " + _("Deactivate"), "value": "disable"})
                sub_choices.append({"name": "  ✎  " + _("Change label ({})").format(finding['label'] or '—'), "value": "label"})
                sub_choices.append({"name": "  #  " + _("Change tags ({})").format(', '.join(finding['tags']) or '—'), "value": "tags"})
                if eco_options:
                    opts = finding.get("eco_options", {})
                    non_default = sum(1 for o in eco_options if opts.get(o["key"], o["default"]) != o["default"])
                    opts_label = f"{non_default} custom" if non_default else _("Default")
                    sub_choices.append({"name": f"  ⚙  " + _("Options ({})").format(opts_label), "value": "eco_options"})
            else:
                sub_choices.append({"name": "  ●  " + _("Activate"), "value": "enable"})
            sub_choices.append({"name": "  ←  " + _("Back"), "value": "back"})

            sub_action = inquirer.select(
                message=f"{icon} {finding['display']} — {finding['dir']}:",
                choices=sub_choices,
                instruction="",
            ).execute()

            if sub_action == "disable":
                finding["enabled"] = False
            elif sub_action == "enable":
                finding["enabled"] = True
            elif sub_action == "label":
                finding["label"] = inquirer.text(
                    message="Label:",
                    default=finding["label"],
                ).execute()
            elif sub_action == "tags":
                tags_input = inquirer.text(
                    message=_("Tags (comma-separated):"),
                    default=", ".join(finding["tags"]),
                ).execute()
                finding["tags"] = [t.strip() for t in tags_input.split(",") if t.strip()] if tags_input else []
            elif sub_action == "eco_options":
                opts = finding.setdefault("eco_options", {})
                opt_cursor = eco_options[0]["key"] if eco_options else None
                while True:
                    console.clear()
                    console.print(f"\n  ⚙  {finding['display']} — {_('Options')}\n")
                    opt_choices = []
                    for o in eco_options:
                        val = opts.get(o["key"], o["default"])
                        if o["type"] == "bool":
                            display_val = _("Yes") if val else _("No")
                            opt_choices.append({"name": f"  {o['label']}: {display_val}", "value": o["key"]})
                        elif o["type"] == "enum":
                            opt_choices.append({"name": f"  {o['label']}: {val}", "value": o["key"]})
                        elif o["type"] == "multi-select":
                            display_val = ", ".join(val) if isinstance(val, list) else str(val)
                            opt_choices.append({"name": f"  {o['label']}: {display_val}", "value": o["key"]})
                    opt_choices.append(Separator())
                    opt_choices.append({"name": "  ←  " + _("Back"), "value": "back"})

                    opt_action = inquirer.select(
                        message=_("Options:"),
                        choices=opt_choices,
                        default=opt_cursor,
                        instruction="",
                    ).execute()

                    if opt_action == "back":
                        break

                    opt_def = next((o for o in eco_options if o["key"] == opt_action), None)
                    if not opt_def:
                        continue

                    if opt_def["type"] == "bool":
                        opts[opt_action] = not opts.get(opt_action, opt_def["default"])
                    elif opt_def["type"] == "enum":
                        opts[opt_action] = inquirer.select(
                            message=opt_def["label"] + ":",
                            choices=opt_def["choices"],
                            default=opts.get(opt_action, opt_def["default"]),
                        ).execute()
                    elif opt_def["type"] == "multi-select":
                        current = opts.get(opt_action, opt_def["default"])
                        choices = [
                            {"name": c, "value": c, "enabled": c in current}
                            for c in opt_def["choices"]
                        ]
                        opts[opt_action] = inquirer.checkbox(
                            message=opt_def["label"] + ":",
                            choices=choices,
                            instruction="Space = toggle, Enter = confirm",
                        ).execute()

                    opt_cursor = opt_action

            # Next entry, or options if last
            if idx + 1 < len(findings):
                next_default = ("toggle", idx + 1)
            else:
                next_default = ("options", None)

    # ── Generate config ──
    selected = [f for f in findings if f["enabled"]]

    if not selected:
        console.print("[yellow]" + _("No sources selected.") + "[/]")
        return

    config_str = generate_config(project_dir, selected, name, version, options, auto_version=auto_version)

    console.print()
    console.print(Panel(
        Syntax(config_str, "yaml", theme="monokai", line_numbers=False),
        title="[bold]sbom.config.yaml[/]",
        border_style="green",
    ))

    # One question: save / overwrite
    if output_path.exists():
        save_msg = _("{} overwrite?").format(output_path.name)
    else:
        save_msg = _("Save to {}?").format(output_path.name)

    save = inquirer.select(
        message=save_msg,
        choices=[
            {"name": "  ✓  " + _("Save"), "value": True},
            {"name": "  ✕  " + _("Cancel"), "value": False},
        ],
        default=True,
        instruction="",
    ).execute()

    if save:
        with open(output_path, "w") as f:
            f.write(config_str)
        console.print("\n[bold green]✓ " + _("Config written:") + "[/] " + str(output_path))
        console.print()
        console.print(Panel.fit(
            "[bold]" + _("Next steps:") + "[/]\n"
            f"  [cyan]sbom scan[/] --project-dir {project_dir}\n"
            f"  [cyan]sbom report[/]   --project-dir {project_dir}",
            border_style="dim",
        ))
    else:
        console.print("[yellow]" + _("Not saved.") + "[/]")


# ── Simple fallback (without rich/InquirerPy) ────────────────────────────────

def _prompt_yn(question: str, default: bool = True) -> bool:
    suffix = " [Y/n] " if default else " [y/N] "
    answer = input(question + suffix).strip().lower()
    if not answer:
        return default
    return answer in ("j", "ja", "y", "yes")


def _prompt_str(question: str, default: str = "") -> str:
    if default:
        answer = input(f"{question} [{default}]: ").strip()
        return answer if answer else default
    return input(f"{question}: ").strip()


def _prompt_choice(question: str, choices: list[tuple[str, str]], default: str = "") -> str:
    """Simple numbered selection prompt."""
    print(question)
    for i, (key, label) in enumerate(choices, 1):
        marker = ">" if key == default else " "
        print(f"  {marker} {i}. {label}")
    while True:
        answer = input(_("Selection [1-{}]: ").format(len(choices))).strip()
        if not answer and default:
            return default
        try:
            idx = int(answer) - 1
            if 0 <= idx < len(choices):
                return choices[idx][0]
        except ValueError:
            pass


def _run_simple_interactive(project_dir: Path, findings: list[dict], default_name: str,
                            default_version: str, output_path: Path) -> None:
    """Simple interactive mode without external dependencies — main menu loop."""

    name = default_name
    version = default_version
    auto_version = True

    options = {"skip_cve": False, "fetch_licenses": False, "pdf": False, "simple": False, "workers": 20}

    # Load existing config
    if output_path.exists():
        try:
            import yaml
            with open(output_path) as fh:
                existing = yaml.safe_load(fh) or {}
            proj = existing.get("project", {})
            name = proj.get("name", name)
            version = proj.get("version", version)
            for k in options:
                if k in existing.get("options", {}):
                    options[k] = existing["options"][k]
        except Exception:
            pass

    # Initialize state
    for f in findings:
        f.setdefault("enabled", True)
        f.setdefault("label", f["label_suggestion"])
        f.setdefault("tags", [])
        f.setdefault("eco_options", {})

    # ── Main menu loop ──
    while True:
        print(f"\n{'═' * 60}")
        print(f"  {name} v{version}")
        print(f"{'═' * 60}")

        for i, f in enumerate(findings, 1):
            icon = _get_ecosystem_icons().get(f["ecosystem"], "")
            status = "●" if f["enabled"] else "○"
            tags_str = ", ".join(f["tags"]) if f["tags"] else "—"
            print(f"  {i}. {status} {icon} {f['display']:20s} {f['dir']:20s} label={f['label'] or '—':15s} tags={tags_str}")

        opts_parts = []
        if options["skip_cve"]:
            opts_parts.append(_("CVE off"))
        if options["fetch_licenses"]:
            opts_parts.append(_("Licenses"))
        if options["pdf"]:
            opts_parts.append("PDF")
        if options["simple"]:
            opts_parts.append("Simple")
        opts_str = ", ".join(opts_parts) if opts_parts else _("Default")

        print(_("\n  N) Project name   V) Version    O) Options ({})").format(opts_str))
        print(_("  F) Finish         X) Cancel"))
        print()

        choice = input(_("  Selection [1-{}/N/V/O/F/X]: ").format(len(findings))).strip().lower()

        if choice == "x":
            print(_("Cancelled."))
            return
        elif choice == "f":
            break
        elif choice == "n":
            name = _prompt_str("  " + _("Project name"), name)
        elif choice == "v":
            version = _prompt_str("  " + _("Version"), version)
        elif choice == "o":
            # Options submenu
            while True:
                print("\n  " + _("Options:"))
                print(_("    1. CVE scan:       {}").format(_('Off') if options['skip_cve'] else _('On')))
                print(_("    2. Fetch licenses: {}").format(_('Yes') if options['fetch_licenses'] else _('No')))
                print(_("    3. Generate PDF:   {}").format(_('Yes') if options['pdf'] else _('No')))
                print(_("    4. Simple report:  {}").format(_('Yes') if options['simple'] else _('No')))
                print(_("    5. Workers:        {}").format(options['workers']))
                print("    B. " + _("Back"))
                opt = input(_("  Selection [1-5/B]: ")).strip().lower()
                if opt == "b" or opt == "z" or opt == "":
                    break
                elif opt == "1":
                    options["skip_cve"] = not options["skip_cve"]
                elif opt == "2":
                    options["fetch_licenses"] = not options["fetch_licenses"]
                elif opt == "3":
                    options["pdf"] = not options["pdf"]
                elif opt == "4":
                    options["simple"] = not options["simple"]
                elif opt == "5":
                    val = _prompt_str("  " + _("Workers"), str(options["workers"]))
                    try:
                        options["workers"] = int(val)
                    except ValueError:
                        pass
        else:
            # Number -> configure source
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(findings):
                    finding = findings[idx]
                    icon = _get_ecosystem_icons().get(finding["ecosystem"], "")
                    files = ", ".join(finding["files"].values())
                    print(f"\n  {icon} {finding['display']} — {finding['dir']}")
                    print("  " + _("Files: {}").format(files))

                    finding["enabled"] = _prompt_yn("  " + _("Include?"), finding["enabled"])
                    if finding["enabled"]:
                        finding["label"] = _prompt_str("  " + _("Label"), finding["label"])
                        tags_input = _prompt_str("  " + _("Tags (comma-separated)"), ", ".join(finding["tags"]))
                        finding["tags"] = [t.strip() for t in tags_input.split(",") if t.strip()] if tags_input else []

                        # Ecosystem-specific options
                        eco_options = _get_eco_options(finding["ecosystem"])
                        if eco_options:
                            opts = finding.setdefault("eco_options", {})
                            print(f"\n  {_('Options')}:")
                            for o in eco_options:
                                val = opts.get(o["key"], o["default"])
                                if o["type"] == "bool":
                                    opts[o["key"]] = _prompt_yn(f"    {o['label']}", val)
                                elif o["type"] == "enum":
                                    print(f"    {o['label']} ({', '.join(o['choices'])})")
                                    opts[o["key"]] = _prompt_str(f"    ", str(val))
                                elif o["type"] == "multi-select":
                                    current = ", ".join(val) if isinstance(val, list) else str(val)
                                    print(f"    {o['label']} ({', '.join(o['choices'])})")
                                    result = _prompt_str(f"    " + _("Selection (comma-separated)"), current)
                                    opts[o["key"]] = [v.strip() for v in result.split(",") if v.strip()]
            except ValueError:
                pass

    # ── Generate config ──
    selected = [f for f in findings if f["enabled"]]
    if not selected:
        print(_("No sources selected."))
        return

    config_str = generate_config(project_dir, selected, name, version, options, auto_version=auto_version)

    print(f"\n{'─' * 60}")
    print(config_str)
    print(f"{'─' * 60}")

    if output_path.exists():
        if not _prompt_yn("\n" + _("{} overwrite?").format(output_path.name), default=False):
            print(_("Cancelled."))
            return
    else:
        if not _prompt_yn("\n" + _("Save to {}?").format(output_path.name)):
            print(_("Not saved."))
            return

    with open(output_path, "w") as f:
        f.write(config_str)
    print("\n" + _("Config written: {}").format(output_path))
    print("\n" + _("Next steps:"))
    print(f"  sbom scan --project-dir {project_dir}")
    print(f"  sbom report --project-dir {project_dir}")


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Auto-configurator for sbom-scanner | © 2026 Frmwrk GmbH")
    parser.add_argument("--project-dir", default=".", help=_("Project directory"))
    parser.add_argument("--output", default="sbom.config.yaml", help=_("Output path for config"))
    parser.add_argument("--non-interactive", action="store_true", help=_("Accept all defaults without prompting"))
    parser.add_argument("--lang", default=None, help="Language (en, de)")
    parser.add_argument("--simple", action="store_true", help=_("Simple text menu without TUI dependencies"))
    args = parser.parse_args()

    project_dir = Path(args.project_dir).resolve()

    # Scan project
    try:
        from rich.console import Console
        console = Console()
        with console.status("[bold cyan]" + _("Scanning project..."), spinner="dots"):
            findings = scan_project(project_dir)
    except ImportError:
        print(_("Scanning: {}").format(project_dir) + "\n")
        findings = scan_project(project_dir)

    if not findings:
        try:
            from rich.console import Console
            Console().print("[bold red]" + _("No supported lockfiles found.") + "[/]")
        except ImportError:
            print(_("No supported lockfiles found."))
        sys.exit(1)

    default_name, default_version = _read_project_name(project_dir, findings)

    output_path = Path(args.output)
    if not output_path.is_absolute():
        output_path = project_dir / output_path

    if args.non_interactive:
        selected = findings
        for item in selected:
            item["label"] = item["label_suggestion"]
            item["tags"] = []
        config_str = generate_config(project_dir, selected, default_name, default_version, auto_version=True)

        try:
            from rich.console import Console
            from rich.syntax import Syntax
            from rich.panel import Panel
            console = Console()
            console.print(Panel(
                Syntax(config_str, "yaml", theme="monokai", line_numbers=False),
                title="[bold]sbom.config.yaml[/]",
                border_style="green",
            ))
        except ImportError:
            print(f"{'─' * 60}")
            print(config_str)
            print(f"{'─' * 60}")

        with open(output_path, "w") as f:
            f.write(config_str)

        try:
            from rich.console import Console
            Console().print("[bold green]" + _("Config written:") + "[/] " + str(output_path))
        except ImportError:
            print(_("Config written: {}").format(output_path))
    elif args.simple:
        _run_simple_interactive(project_dir, findings, default_name, default_version, output_path)
    else:
        _run_interactive(project_dir, findings, default_name, default_version, output_path)


if __name__ == "__main__":
    main()
