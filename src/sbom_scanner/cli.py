"""Compound CLI entry point: sbom <command>."""

import sys


def main():
    """Route to subcommands: sbom configure|scan|report."""
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        _print_help()
        sys.exit(0)

    command = sys.argv[1]

    # Remove the subcommand from argv so argparse in each module works normally
    sys.argv = [f"sbom {command}"] + sys.argv[2:]

    if command == "configure":
        from .configure import main as configure_main
        configure_main()
    elif command == "scan":
        from .generate_sbom import main as scan_main
        scan_main()
    elif command == "report":
        from .generate_sbom_report import main as report_main
        report_main()
    elif command == "version":
        from . import __version__
        print(f"sbom-scanner {__version__} — © 2026 Frmwrk GmbH")
    else:
        print(f"Unknown command: {command}")
        print()
        _print_help()
        sys.exit(1)


def _print_help():
    from . import __version__
    print(f"sbom-scanner {__version__} — © 2026 Frmwrk GmbH")
    print()
    print("Usage: sbom <command> [options]")
    print()
    print("Commands:")
    print("  configure   Auto-detect ecosystems and generate sbom.config.yaml")
    print("  scan        Generate CycloneDX 1.6 SBOM from project dependencies")
    print("  report      Generate HTML/PDF report from SBOM")
    print("  version     Show version")
    print()
    print("Examples:")
    print("  sbom configure --project-dir .")
    print("  sbom scan --project-dir .")
    print("  sbom report --project-dir .")
    print()
    print("Run 'sbom <command> --help' for command-specific options.")


if __name__ == "__main__":
    main()
