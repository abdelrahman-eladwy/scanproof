from __future__ import annotations

import httpx
import pytest
import respx

from scanproof.connectors.base import AuthError, ConnectorError, ErrorKind, NotFoundError
from scanproof.connectors.gitlab import GitLabConnector
from scanproof.connectors.http import MAX_REDIRECTS
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
    assert mock_api.calls.call_count == MAX_REDIRECTS + 1  # gives up after the cap, not later


@pytest.mark.parametrize("path", ["../../user", "reports/../../../../user", "a/../../b"])
def test_rejects_path_traversal_before_any_request(connector, mock_api, path) -> None:
    """'../' would make the token-bearing request hit another GitLab API endpoint."""
    with pytest.raises(ConnectorError) as exc:
        connector.download_artifact_file("123", 8821, path)
    assert exc.value.kind is ErrorKind.INVALID_RESPONSE
    assert "'..'" in exc.value.message
    assert mock_api.calls.call_count == 0


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


# ---------------------------------------------------------------- anonymous mode


def test_anonymous_sends_no_credentials(mock_api) -> None:
    route = mock_api.get(PIPELINE_URL).respond(json=load_fixture("gitlab/pipeline.json"))
    with GitLabConnector(BASE, None, anonymous=True) as gl:
        gl.get_pipeline("123", 1042)
        assert "anonymous=True" in repr(gl)
    assert "Authorization" not in route.calls.last.request.headers


def test_anonymous_and_token_are_exclusive() -> None:
    with pytest.raises(AuthError, match="not both"):
        GitLabConnector(BASE, TOKEN, anonymous=True)


def test_anonymous_403_hint(mock_api) -> None:
    mock_api.get(PIPELINE_URL).respond(403)
    with GitLabConnector(BASE, None, anonymous=True) as gl, pytest.raises(AuthError) as exc:
        gl.get_pipeline("123", 1042)
    assert "public projects" in str(exc.value)


def test_anonymous_404_hint(mock_api) -> None:
    mock_api.get(PIPELINE_URL).respond(404)
    with GitLabConnector(BASE, None, anonymous=True) as gl, pytest.raises(NotFoundError) as exc:
        gl.get_pipeline("123", 1042)
    assert "anonymous access cannot see it" in str(exc.value)


@pytest.mark.parametrize(
    "bad",
    [{"commit": "abc"}, {"pipeline": 5}, {"artifacts": ["x"]}, {"artifacts": [None]}],
)
def test_malformed_job_payload_is_invalid_response_not_crash(connector, mock_api, bad) -> None:
    """Found by fuzzing: unexpected types used to escape as AttributeError (a traceback
    instead of INDETERMINATE)."""
    job = {**load_fixture("gitlab/jobs_page1.json")[0], **bad}
    mock_api.get(JOBS_URL).respond(json=[job])
    with pytest.raises(ConnectorError) as exc:
        connector.list_jobs("123", 1042)
    assert exc.value.kind is ErrorKind.INVALID_RESPONSE


def test_pipeline_payload_that_is_a_list(connector, mock_api) -> None:
    mock_api.get(PIPELINE_URL).respond(json=[1, 2])
    with pytest.raises(ConnectorError) as exc:
        connector.get_pipeline("123", 1042)
    assert exc.value.kind is ErrorKind.INVALID_RESPONSE


@pytest.mark.parametrize("anonymous", [True, False])
def test_rate_limit_hint_only_in_anonymous_mode(mock_api, anonymous) -> None:
    """#74: gitlab.com allows 60 anonymous API requests/hour per IP; say so, and how to fix it."""
    mock_api.get(PIPELINE_URL).respond(429)
    token = None if anonymous else TOKEN
    with (
        GitLabConnector(BASE, token, anonymous=anonymous, sleep=lambda _: None) as gl,
        pytest.raises(ConnectorError) as exc,
    ):
        gl.get_pipeline("123", 1042)
    assert exc.value.kind is ErrorKind.RATE_LIMITED
    assert ("read_api token" in str(exc.value)) is anonymous
    assert TOKEN not in str(exc.value)
