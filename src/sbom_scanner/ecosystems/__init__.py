"""Ecosystem registry.

To register a new ecosystem:
  1. Import the module.
  2. Add an instance to REGISTRY.
"""

from .cargo import CargoEcosystem
from .maven import MavenEcosystem
from .npm import NpmEcosystem
from .pub import PubEcosystem
from .pypi import PypiEcosystem

# All registered ecosystems (order = order in the report)
REGISTRY: list = [
    NpmEcosystem(),
    PypiEcosystem(),
    PubEcosystem(),
    MavenEcosystem(),
    CargoEcosystem(),
]


def get_ecosystem(name: str):
    """Return an ecosystem by name, or None."""
    for eco in REGISTRY:
        if eco.name == name:
            return eco
    return None
