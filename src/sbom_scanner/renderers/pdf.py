"""PDF report renderer."""
from __future__ import annotations

import subprocess
from pathlib import Path

from .base import Renderer


class PdfRenderer(Renderer):
    name = "pdf"
    display_name = "PDF Report"
    file_extension = ".pdf"

    def render(self, sbom, vulns, output_path, **kwargs):
        from .simple_html import SimpleHtmlRenderer

        # Generate simple HTML first (no JS/tabs for PDF)
        simple = SimpleHtmlRenderer()
        html_path = output_path.with_suffix(".html")
        simple.render(sbom, vulns, html_path)

        pdf_path = output_path
        pdf_ok = False

        # 1. weasyprint
        if not pdf_ok:
            try:
                from weasyprint import HTML as WeasyHTML
                WeasyHTML(filename=str(html_path)).write_pdf(str(pdf_path))
                pdf_ok = True
            except Exception:
                pass

        # 2. Chrome/Chromium headless
        if not pdf_ok:
            for chrome in [
                "google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                "/Applications/Chromium.app/Contents/MacOS/Chromium",
            ]:
                try:
                    subprocess.run(
                        [chrome, "--headless", "--disable-gpu",
                         f"--print-to-pdf={pdf_path}", "--no-pdf-header-footer",
                         str(html_path)],
                        check=True, capture_output=True, timeout=30,
                    )
                    pdf_ok = True
                    break
                except (FileNotFoundError, subprocess.CalledProcessError):
                    continue

        # 3. wkhtmltopdf
        if not pdf_ok:
            try:
                subprocess.run(
                    ["wkhtmltopdf", "--quiet", "--enable-local-file-access",
                     str(html_path), str(pdf_path)],
                    check=True, timeout=30,
                )
                pdf_ok = True
            except (FileNotFoundError, subprocess.CalledProcessError):
                pass

        # Clean up temporary HTML
        if html_path.exists():
            html_path.unlink()

        if not pdf_ok:
            import sys
            print("Fehler: Kein PDF-Tool gefunden. Eines der folgenden installieren:", file=sys.stderr)
            print("  pip install weasyprint  (+ brew install pango glib)", file=sys.stderr)
            print("  Google Chrome / Chromium (headless)", file=sys.stderr)
            print("  wkhtmltopdf", file=sys.stderr)

        return pdf_path
