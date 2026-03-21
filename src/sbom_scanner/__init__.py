"""SBOM Report Generator — Multi-ecosystem CycloneDX SBOM + HTML report.

Library usage:

    from pathlib import Path
    from sbom_scanner import generate_sbom, generate_report, load_config

    project = Path("../my-project")
    config = load_config(project / "sbom.config.yaml")
    sbom_path = project / "sbom.cyclonedx.json"

    generate_sbom(project, config, sbom_path)
    generate_report(sbom_path, project / "sbom-report.html")
"""

__version__ = "1.0.1"

from pathlib import Path

from .generate_sbom import generate_sbom, load_config
from .generate_sbom_report import generate_html, load_sbom, run_scanners


def generate_report(
    sbom_path: str | Path,
    output_path: str | Path,
    *,
    skip_cve: bool = False,
    pdf: bool = False,
    project_dir: str | Path | None = None,
    config: dict | None = None,
) -> Path:
    """Generate an HTML report from a CycloneDX SBOM.

    Args:
        sbom_path: Path to the CycloneDX JSON SBOM.
        output_path: Path for the HTML report output.
        skip_cve: Skip CVE scanning.
        pdf: Additionally generate a PDF.
        project_dir: Project directory (for osv-scanner lockfile discovery).
        config: Config dict (for osv-scanner lockfile paths).

    Returns:
        Path to the generated HTML report.
    """
    sbom_path = Path(sbom_path)
    output_path = Path(output_path)
    project_dir = Path(project_dir) if project_dir else sbom_path.parent

    sbom = load_sbom(sbom_path)

    vulns = []
    if not skip_cve:
        lockfiles = []
        try:
            from .ecosystems import REGISTRY
            sources_config = (config or {}).get("sources", {})
            for eco in REGISTRY:
                raw = sources_config.get(eco.name)
                eco_configs = [raw] if isinstance(raw, dict) else (raw or [{}])
                for eco_config in eco_configs:
                    lockfiles.extend(eco.get_osv_lockfiles(project_dir, eco_config))
        except ImportError:
            pass

        vulns = run_scanners(sbom_path, lockfiles, project_dir)

    html = generate_html(sbom, vulns)
    with open(output_path, "w") as f:
        f.write(html)

    if pdf:
        pdf_path = output_path.with_suffix(".pdf")
        try:
            from weasyprint import HTML as WeasyHTML
            WeasyHTML(filename=str(output_path)).write_pdf(str(pdf_path))
        except ImportError:
            import subprocess
            subprocess.run(
                ["wkhtmltopdf", "--quiet", "--enable-local-file-access",
                 str(output_path), str(pdf_path)],
                check=True, timeout=30,
            )

    return output_path


__all__ = [
    "__version__",
    "generate_sbom",
    "generate_report",
    "generate_html",
    "load_config",
    "load_sbom",
    "run_scanners",
]
