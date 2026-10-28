from __future__ import annotations

import json
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import respx

from scanproof.connectors.gitlab import GitLabConnector

FIXTURES = Path(__file__).parent / "fixtures"


def pytest_configure(config: pytest.Config) -> None:
    """SCANPROOF_TEST_INSTALLED=1 (CI's package and docker jobs): the suite must exercise the
    installed wheel or image, so refuse to run if `scanproof` resolves to a source tree."""
    if os.environ.get("SCANPROOF_TEST_INSTALLED") != "1":
        return
    import scanproof

    where = Path(scanproof.__file__).resolve()
    if "site-packages" not in where.parts and "dist-packages" not in where.parts:
        raise pytest.UsageError(
            f"SCANPROOF_TEST_INSTALLED=1 but scanproof is imported from {where}"
        )


BASE = "https://gitlab.example.com"
API = f"{BASE}/api/v4"
TOKEN = "glpat-TEST-TOKEN-do-not-leak"


def load_fixture(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.fixture
def sleeps() -> list[float]:
    return []


@pytest.fixture
def connector(sleeps: list[float]) -> Iterator[GitLabConnector]:
    gl = GitLabConnector(BASE, TOKEN, sleep=sleeps.append, backoff_seconds=0.5, max_retries=2)
    yield gl
    gl.close()


@pytest.fixture
def mock_api() -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_called=False) as router:
        # Every GitLab pipeline has a bridges endpoint; default to "no child pipelines".
        # Tests that need children override it: mock_api.routes["bridges"].respond(json=[...])
        router.get(
            url__regex=r".*/api/v4/projects/[^/]+/pipelines/\d+/bridges", name="bridges"
        ).respond(json=[])
        yield router
