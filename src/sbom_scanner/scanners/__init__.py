"""CVE scanner registry.

To register a new scanner:
  1. Import the module.
  2. Add an instance to REGISTRY.
"""

from .grype import GrypeScanner
from .osv import OsvScanner

# All registered scanners (order = execution order)
REGISTRY: list = [
    GrypeScanner(),
    OsvScanner(),
]


def get_scanner(name: str):
    """Return a scanner by name, or None."""
    for scanner in REGISTRY:
        if scanner.name == name:
            return scanner
    return None
