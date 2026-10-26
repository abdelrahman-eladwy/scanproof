from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import respx

from scanproof.connectors.gitlab import GitLabConnector

FIXTURES = Path(__file__).parent / "fixtures"
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
        yield router
