"""Renderer registry."""
from .html import HtmlRenderer
from .simple_html import SimpleHtmlRenderer
from .pdf import PdfRenderer
from .json_report import JsonRenderer
from .csv_report import CsvRenderer

REGISTRY: list = [
    HtmlRenderer(),
    SimpleHtmlRenderer(),
    PdfRenderer(),
    JsonRenderer(),
    CsvRenderer(),
]


def get_renderer(name: str):
    for r in REGISTRY:
        if r.name == name:
            return r
    return None
