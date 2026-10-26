from __future__ import annotations

import httpx
import pytest
import respx

from scanproof.connectors.base import AuthError, ConnectorError, ErrorKind, NotFoundError
from scanproof.connectors.gitlab import GitLabConnector
from scanproof.models import JobStatus
from tests.conftest import API, BASE, TOKEN, load_fixture

PIPELINE_URL = f"{API}/projects/123/pipelines/1042"
JOBS_URL = f"{API}/projects/123/pipelines/1042/jobs"


# ---------------------------------------------------------------- construction


def test_rejects_empty_token() -> None:
    with pytest.raises(AuthError):
        GitLabConnector(BASE, "")


def test_rejects_plain_http_base_url() -> None:
    with pytest.raises(ConnectorError) as exc:
        GitLabConnector("http://gitlab.example.com", TOKEN)
    assert exc.value.kind is ErrorKind.NETWORK


def test_allows_http_for_loopback_dev_instances() -> None:
    GitLabConnector("http://localhost:8080", TOKEN).close()


def test_repr_never_contains_token(connector: GitLabConnector) -> None:
    assert TOKEN not in repr(connector)


# ---------------------------------------------------------------- pipeline


def test_get_pipeline_parses_and_sends_bearer(connector, mock_api) -> None:
    route = mock_api.get(PIPELINE_URL).respond(json=load_fixture("gitlab/pipeline.json"))
    pipeline = connector.get_pipeline("123", 1042)

    assert pipeline.id == 1042
    assert pipeline.sha.startswith("a1b2c3")
    request = route.calls.last.request
    assert request.headers["Authorization"] == f"Bearer {TOKEN}"
    assert "PRIVATE-TOKEN" not in request.headers
    assert TOKEN not in str(request.url)


def test_project_path_is_url_encoded(connector, mock_api) -> None:
    route = mock_api.get(f"{API}/projects/acme%2Fpayment-service/pipelines/1042").respond(
        json=load_fixture("gitlab/pipeline.json")
    )
    connector.get_pipeline("acme/payment-service", 1042)
    assert route.called


def test_invalid_pipeline_payload(connector, mock_api) -> None:
    mock_api.get(PIPELINE_URL).respond(json={"id": 1042})
    with pytest.raises(ConnectorError) as exc:
        connector.get_pipeline("123", 1042)
    assert exc.value.kind is ErrorKind.INVALID_RESPONSE


@pytest.mark.parametrize("code", [401, 403])
def test_auth_errors(connector, mock_api, code: int) -> None:
    mock_api.get(PIPELINE_URL).respond(code, json={"message": "403 Forbidden"})
    with pytest.raises(AuthError) as exc:
        connector.get_pipeline("123", 1042)
    assert exc.value.status_code == code
    assert TOKEN not in str(exc.value)


def test_not_found(connector, mock_api) -> None:
    mock_api.get(PIPELINE_URL).respond(404)
    with pytest.raises(NotFoundError):
        connector.get_pipeline("123", 1042)


# ---------------------------------------------------------------- jobs & pagination


def test_list_jobs_follows_pagination_and_includes_retried(connector, mock_api) -> None:
    route = mock_api.get(JOBS_URL)
    route.side_effect = [
        httpx.Response(
            200, json=load_fixture("gitlab/jobs_page1.json"), headers={"x-next-page": "2"}
        ),
        httpx.Response(
            200, json=load_fixture("gitlab/jobs_page2.json"), headers={"x-next-page": ""}
        ),
    ]
    jobs = connector.list_jobs("123", 1042)

    assert [j.id for j in jobs] == [8821, 8822, 8823, 8830, 8840]
    first, second = route.calls
    assert first.request.url.params["include_retried"] == "true"
    assert first.request.url.params["per_page"] == "100"
    assert second.request.url.params["page"] == "2"


def test_job_fields_are_normalised(connector, mock_api) -> None:
    mock_api.get(JOBS_URL).respond(json=load_fixture("gitlab/jobs_page1.json"))
    sast = next(j for j in connector.list_jobs("123", 1042) if j.name == "semgrep-sast")

    assert sast.status is JobStatus.SUCCESS
    assert sast.commit_sha == "a1b2c3d4e5f60718293a4b5c6d7e8f9001122334"
    assert sast.pipeline_id == 1042
    assert sast.has_archive


def test_unknown_status_never_becomes_success(connector, mock_api) -> None:
    mock_api.get(JOBS_URL).respond(
        json=[{"id": 1, "name": "x", "status": "brand_new_state", "commit": {}, "pipeline": {}}]
    )
    (job,) = connector.list_jobs("123", 1042)
    assert job.status is JobStatus.UNKNOWN
    assert job.raw_status == "brand_new_state"


def test_jobs_response_must_be_a_list(connector, mock_api) -> None:
    mock_api.get(JOBS_URL).respond(json={"message": "unexpected"})
    with pytest.raises(ConnectorError) as exc:
        connector.list_jobs("123", 1042)
    assert exc.value.kind is ErrorKind.INVALID_RESPONSE


# ---------------------------------------------------------------- retries


def test_retries_transient_errors_with_backoff(connector, mock_api, sleeps) -> None:
    mock_api.get(PIPELINE_URL).side_effect = [
        httpx.Response(503),
        httpx.Response(502),
        httpx.Response(200, json=load_fixture("gitlab/pipeline.json")),
    ]
    assert connector.get_pipeline("123", 1042).id == 1042
    assert sleeps == [0.5, 1.0]


def test_respects_retry_after(connector, mock_api, sleeps) -> None:
    mock_api.get(PIPELINE_URL).side_effect = [
        httpx.Response(429, headers={"Retry-After": "7"}),
        httpx.Response(200, json=load_fixture("gitlab/pipeline.json")),
    ]
    connector.get_pipeline("123", 1042)
    assert sleeps == [7.0]


def test_gives_up_after_max_retries(connector, mock_api) -> None:
    mock_api.get(PIPELINE_URL).respond(503)
    with pytest.raises(ConnectorError) as exc:
        connector.get_pipeline("123", 1042)
    assert exc.value.kind is ErrorKind.SERVER
    assert mock_api.calls.call_count == 3  # 1 + max_retries(2)


def test_network_errors_are_retried_then_reported(connector, mock_api) -> None:
    mock_api.get(PIPELINE_URL).side_effect = httpx.ConnectError("boom")
    with pytest.raises(ConnectorError) as exc:
        connector.get_pipeline("123", 1042)
    assert exc.value.kind is ErrorKind.NETWORK
    assert mock_api.calls.call_count == 3


# ---------------------------------------------------------------- redirects & downloads

ARTIFACT_URL = f"{API}/projects/123/jobs/8821/artifacts/semgrep.json"


def test_cross_origin_redirect_does_not_leak_token(connector, mock_api) -> None:
    storage = "https://storage.example.net/bucket/semgrep.json?sig=abc"
    mock_api.get(ARTIFACT_URL).respond(302, headers={"Location": storage})
    storage_route = mock_api.get(storage).respond(content=b'{"results": []}')

    assert connector.download_artifact_file("123", 8821, "semgrep.json") == b'{"results": []}'
    assert "Authorization" not in storage_route.calls.last.request.headers


def test_same_origin_redirect_keeps_token(connector, mock_api) -> None:
    moved = f"{API}/projects/123/jobs/8821/artifacts/reports/semgrep.json"
    mock_api.get(ARTIFACT_URL).respond(301, headers={"Location": moved})
    route = mock_api.get(moved).respond(content=b"{}")
    connector.download_artifact_file("123", 8821, "semgrep.json")
    assert route.calls.last.request.headers["Authorization"] == f"Bearer {TOKEN}"


def test_refuses_https_to_http_redirect(connector, mock_api) -> None:
    mock_api.get(ARTIFACT_URL).respond(302, headers={"Location": "http://evil.example/x"})
    with pytest.raises(ConnectorError) as exc:
        connector.download_artifact_file("123", 8821, "semgrep.json")
    assert exc.value.kind is ErrorKind.UNSAFE_REDIRECT


def test_refuses_redirect_loops(connector, mock_api) -> None:
    mock_api.get(ARTIFACT_URL).respond(302, headers={"Location": ARTIFACT_URL})
    with pytest.raises(ConnectorError) as exc:
        connector.download_artifact_file("123", 8821, "semgrep.json")
    assert exc.value.kind is ErrorKind.UNSAFE_REDIRECT


def test_rejects_path_traversal(connector) -> None:
    with pytest.raises(ConnectorError):
        connector.download_artifact_file("123", 8821, "../../secrets.json")


def test_artifact_size_limit_from_content_length(mock_api) -> None:
    gl = GitLabConnector(BASE, TOKEN, max_artifact_bytes=1000)
    mock_api.get(ARTIFACT_URL).respond(content=b"x" * 2000)
    with pytest.raises(ConnectorError) as exc:
        gl.download_artifact_file("123", 8821, "semgrep.json")
    assert exc.value.kind is ErrorKind.LIMIT_EXCEEDED


def test_artifact_size_limit_while_streaming(mock_api) -> None:
    """A server that omits Content-Length must still be capped."""
    gl = GitLabConnector(BASE, TOKEN, max_artifact_bytes=1000)
    mock_api.get(ARTIFACT_URL).mock(
        side_effect=lambda request: httpx.Response(200, stream=_chunks([b"a" * 600, b"b" * 600]))
    )
    with pytest.raises(ConnectorError) as exc:
        gl.download_artifact_file("123", 8821, "semgrep.json")
    assert exc.value.kind is ErrorKind.LIMIT_EXCEEDED


def test_artifact_not_found(connector, mock_api) -> None:
    mock_api.get(ARTIFACT_URL).respond(404)
    with pytest.raises(NotFoundError):
        connector.download_artifact_file("123", 8821, "semgrep.json")


class _chunks(httpx.SyncByteStream):
    def __init__(self, parts: list[bytes]) -> None:
        self.parts = parts

    def __iter__(self):
        yield from self.parts


@respx.mock
def test_module_level_respx_still_isolated() -> None:
    """Sanity check: nothing in this file reaches the real network."""
    respx.get(PIPELINE_URL).respond(json=load_fixture("gitlab/pipeline.json"))
    with GitLabConnector(BASE, TOKEN) as gl:
        assert gl.get_pipeline("123", 1042).ref == "main"
