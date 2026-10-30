"""Hostile API JSON must end as a ConnectorError (exit 2), never as a crash.

A deeply nested API document made `response.json()` raise RecursionError, which only
ValueError handlers surrounded. It escaped the CLI as a traceback with exit code 1, the
code reserved for a policy FAIL, instead of INDETERMINATE (2).

The size-cap tests pin the documented guarantee that API documents, not only artifacts,
are capped while streaming.
"""

from __future__ import annotations

import json
from collections.abc import Iterator

import httpx
import pytest
import respx

from scanproof.connectors.base import ConnectorError, ErrorKind
from scanproof.connectors.github import GitHubConnector
from scanproof.connectors.gitlab import GitLabConnector
from tests.conftest import API, BASE, FIXTURES, TOKEN, load_fixture

LIMIT = 1000
DEEP = b"[" * 100_000 + b"]" * 100_000
GL_PIPELINE = f"{API}/projects/123/pipelines/1042"
GL_JOBS = f"{API}/projects/123/pipelines/1042/jobs"
GH_API = "https://api.github.com"
GH_RUN_BODY = json.loads((FIXTURES / "github-real" / "run.json").read_text())
GH_RUN = f"{GH_API}/repos/acme/app/actions/runs/{GH_RUN_BODY['id']}"
GH_JOBS = f"{GH_RUN}/jobs"


class _Chunks(httpx.SyncByteStream):
    """A body with no Content-Length, so only the streaming cap can stop it."""

    def __init__(self, body: bytes) -> None:
        self._body = body

    def __iter__(self) -> Iterator[bytes]:
        yield self._body[:600]
        yield self._body[600:]


def _streamed(body: bytes) -> httpx.Response:
    return httpx.Response(200, stream=_Chunks(body))


@pytest.fixture
def gitlab() -> Iterator[GitLabConnector]:
    with GitLabConnector(BASE, TOKEN, sleep=lambda _: None) as gl:
        yield gl


@pytest.fixture
def github() -> Iterator[GitHubConnector]:
    with GitHubConnector(GH_API, TOKEN, sleep=lambda _: None) as gh:
        yield gh


def _invalid(exc: pytest.ExceptionInfo[ConnectorError]) -> None:
    assert exc.value.kind is ErrorKind.INVALID_RESPONSE


# ---------------------------------------------------------------- deep nesting


@respx.mock
def test_gitlab_deeply_nested_pipeline_is_invalid_response(gitlab) -> None:
    respx.get(GL_PIPELINE).respond(content=DEEP)
    with pytest.raises(ConnectorError) as exc:
        gitlab.get_pipeline("123", 1042)
    _invalid(exc)


@respx.mock
def test_gitlab_deeply_nested_job_page_is_invalid_response(gitlab) -> None:
    respx.get(GL_JOBS).respond(content=DEEP)
    with pytest.raises(ConnectorError) as exc:
        gitlab.list_jobs("123", 1042)
    _invalid(exc)


@respx.mock
def test_github_deeply_nested_run_is_invalid_response(github) -> None:
    respx.get(GH_RUN).respond(content=DEEP)
    with pytest.raises(ConnectorError) as exc:
        github.get_pipeline("acme/app", GH_RUN_BODY["id"])
    _invalid(exc)


@respx.mock
def test_github_deeply_nested_job_page_is_invalid_response(github) -> None:
    respx.get(GH_RUN).respond(json=GH_RUN_BODY)
    respx.get(GH_JOBS).respond(content=DEEP)
    with pytest.raises(ConnectorError) as exc:
        github.list_jobs("acme/app", GH_RUN_BODY["id"])
    _invalid(exc)


# ---------------------------------------------------------------- size caps


@respx.mock
def test_api_document_is_capped_while_streaming() -> None:
    body = b'{"pad": "' + b"x" * 2 * LIMIT + b'"}'
    respx.get(GL_PIPELINE).mock(side_effect=lambda _: _streamed(body))
    with (
        GitLabConnector(BASE, TOKEN, max_artifact_bytes=LIMIT, sleep=lambda _: None) as gl,
        pytest.raises(ConnectorError) as exc,
    ):
        gl.get_pipeline("123", 1042)
    assert exc.value.kind is ErrorKind.LIMIT_EXCEEDED


@respx.mock
def test_api_page_is_capped_while_streaming() -> None:
    body = b'[{"pad": "' + b"x" * 2 * LIMIT + b'"}]'
    respx.get(GL_JOBS).mock(side_effect=lambda _: _streamed(body))
    with (
        GitLabConnector(BASE, TOKEN, max_artifact_bytes=LIMIT, sleep=lambda _: None) as gl,
        pytest.raises(ConnectorError) as exc,
    ):
        gl.list_jobs("123", 1042)
    assert exc.value.kind is ErrorKind.LIMIT_EXCEEDED


@respx.mock
def test_small_api_documents_still_work(gitlab) -> None:
    respx.get(GL_PIPELINE).respond(json=load_fixture("gitlab/pipeline.json"))
    assert gitlab.get_pipeline("123", 1042).id == 1042
