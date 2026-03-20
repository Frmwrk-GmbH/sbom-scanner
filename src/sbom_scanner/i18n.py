"""Internationalization setup using gettext.

Default language: English (source strings are English).
Set LANGUAGE=de or use --lang de for German.
"""

import gettext
import os
import sys
from pathlib import Path

_LOCALE_DIR = Path(__file__).parent / "locales"
_DOMAIN = "sbom_scanner"

_translation: gettext.GNUTranslations | gettext.NullTranslations | None = None


def setup(lang: str | None = None) -> None:
    """Initialize translations. Call once at startup.

    Args:
        lang: Language code (e.g. 'de', 'en'). None = use LANGUAGE/LC_ALL/LANG env.
              English is the default (source strings are English).
    """
    global _translation
    languages = [lang] if lang else None
    _translation = gettext.translation(
        _DOMAIN, localedir=str(_LOCALE_DIR),
        languages=languages, fallback=True,
    )
    _translation.install()


def _detect_lang_from_argv() -> str | None:
    """Check for --lang flag in sys.argv (before argparse runs)."""
    for i, arg in enumerate(sys.argv):
        if arg == "--lang" and i + 1 < len(sys.argv):
            return sys.argv[i + 1]
        if arg.startswith("--lang="):
            return arg.split("=", 1)[1]
    return None


def _(message: str) -> str:
    """Translate a string."""
    global _translation
    if _translation is None:
        lang = _detect_lang_from_argv()
        setup(lang)
    return _translation.gettext(message)  # type: ignore
