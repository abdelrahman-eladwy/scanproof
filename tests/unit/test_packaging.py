import tomllib
from pathlib import Path

import scanproof

ROOT = Path(__file__).parents[2]


def test_versions_match() -> None:
    """release.yml refuses a tag unless pyproject and __init__ agree; catch drift early."""
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert pyproject["project"]["version"] == scanproof.__version__
