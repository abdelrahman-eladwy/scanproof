"""#44 Phase 1, hostile providers: pagination loops, slow servers, oversized pages and downloads
that drop mid-transfer. Each must end as a connector error (UNKNOWN, exit 2): never a hang,
never silently partial data, never a pass.
"""

from __future__ import annotations

import httpx
import pytest
from typer.testing import CliRunner

from scanproof.cli import EXIT_INDETERMINATE, app
from scanproof.connectors.azure_devops import AzureDevOpsConnector
from scanproof.connectors.base import ConnectorError, ErrorKind
from scanproof.connectors.bitbucket import BitbucketConnector
from scanproof.connectors.github import GitHubConnector
from scanproof.connectors.gitlab import GitLabConnector
from scanproof.connectors.jenkins import JenkinsConnector
from tests.conftest import API, BASE, TOKEN

JOBS = f"{API}/projects/123/pipelines/1042/jobs"
GH = "https://api.github.com"
JOB = {"id": 1, "name": "sast", "status": "success", "stage": "test", "commit": {"id": "a" * 40}}


class Clock:
    """A monotonic clock the test moves forward."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class Drip(httpx.SyncByteStream):
    """A server that keeps sending, slowly: each chunk advances the clock."""

    def __init__(self, clock: Clock, step: float, chunks: int = 10) -> None:
        self.clock, self.step, self.chunks = clock, step, chunks

    def __iter__(self):
        yield b"["
        for _ in range(self.chunks):
            self.clock.now += self.step
            yield b" "
        yield b"]"


class SlowEmpty(httpx.SyncByteStream):
    """An empty response whose stream completes after the clock advances."""

    def __init__(self, clock: Clock, elapsed: float) -> None:
        self.clock, self.elapsed = clock, elapsed

    def __iter__(self):
        self.clock.now += self.elapsed
        yield from ()


class Drops(httpx.SyncByteStream):
    def __iter__(self):
        yield b'{"partial": '
        raise httpx.RemoteProtocolError("peer closed connection without sending complete body")


def gitlab(**kw) -> GitLabConnector:
    return GitLabConnector(BASE, TOKEN, sleep=lambda _: None, **kw)


def test_redirect_with_url_credentials_is_refused_before_follow(mock_api) -> None:
    source = f"{API}/projects/123/pipelines/1042"
    target = "https://attacker:password@example.org/collect"
    mock_api.get(source).respond(302, headers={"Location": target})
    with gitlab() as gl, pytest.raises(ConnectorError) as err:
        gl._get_json("/projects/123/pipelines/1042")
    assert err.value.kind is ErrorKind.UNSAFE_REDIRECT
    assert "password" not in err.value.message
    assert len(mock_api.calls) == 1


# ---------------------------------------------------------------- pagination loops


def test_gitlab_page_header_going_backwards_is_a_loop(mock_api) -> None:
    route = mock_api.get(JOBS).mock(
        side_effect=lambda req: httpx.Response(200, json=[JOB], headers={"x-next-page": "1"})
    )
    with gitlab() as gl, pytest.raises(ConnectorError) as err:
        gl.list_jobs("123", 1042)
    assert err.value.kind is ErrorKind.INVALID_RESPONSE
    assert "did not advance" in err.value.message
    assert route.call_count == 1  # detected at once, not after 100 pages


@pytest.mark.parametrize("header", ["abc", "-1", "2.5"])
def test_gitlab_unparseable_page_header_is_a_connector_error(mock_api, header) -> None:
    mock_api.get(JOBS).respond(200, json=[JOB], headers={"x-next-page": header})
    with gitlab() as gl, pytest.raises(ConnectorError) as err:
        gl.list_jobs("123", 1042)
    assert err.value.kind is ErrorKind.INVALID_RESPONSE  # before: a bare ValueError


def test_github_link_loop_is_detected(mock_api) -> None:
    url = f"{GH}/repos/acme/app/actions/runs/7/jobs"
    loop = {"Link": f'<{url}?filter=all&per_page=100>; rel="next"'}
    route = mock_api.get(url).mock(
        side_effect=lambda req: httpx.Response(200, json={"jobs": []}, headers=loop)
    )
    with GitHubConnector(GH, "t", sleep=lambda _: None) as c, pytest.raises(ConnectorError) as err:
        list(c._paginate("/repos/acme/app/actions/runs/7/jobs", "jobs", {"filter": "all"}))
    assert err.value.kind is ErrorKind.INVALID_RESPONSE
    assert route.call_count == 2


def test_github_attestation_store_loop_is_detected(mock_api) -> None:
    digest = "a" * 64
    url = f"{GH}/repos/acme/app/attestations/sha256:{digest}"
    loop = {"Link": f'<{url}?per_page=100>; rel="next"'}
    mock_api.get(url).mock(
        side_effect=lambda req: httpx.Response(200, json={"attestations": []}, headers=loop)
    )
    with GitHubConnector(GH, "t", sleep=lambda _: None) as c, pytest.raises(ConnectorError) as err:
        c.fetch_attestations("acme/app", digest)
    assert err.value.kind is ErrorKind.INVALID_RESPONSE


def test_bitbucket_next_loop_is_detected(mock_api) -> None:
    api = "https://api.bitbucket.org/2.0"
    url = f"{api}/repositories/ws/app/pipelines/"
    mock_api.get(url).respond(200, json={"values": [{}], "next": url})
    with (
        BitbucketConnector(api, "t", sleep=lambda _: None) as c,
        pytest.raises(ConnectorError) as err,
    ):
        list(c._paginate(url, "pipelines"))
    assert err.value.kind is ErrorKind.INVALID_RESPONSE


def test_pagination_loop_makes_verify_indeterminate(mock_api, tmp_path, monkeypatch) -> None:
    mock_api.get(f"{API}/projects/123/pipelines/1042").respond(
        200, json={"id": 1042, "sha": "a" * 40, "ref": "main", "status": "success"}
    )
    mock_api.get(JOBS).respond(200, json=[JOB], headers={"x-next-page": "1"})
    policy = tmp_path / "p.yaml"
    policy.write_text(
        "apiVersion: scanproof.dev/v1alpha1\nkind: PipelineAssurancePolicy\n"
        "project: {provider: gitlab, id: '123'}\nrequirements:\n"
        "  - {id: SAST, tool: semgrep, job_name: sast, report_path: s.json}\n"
    )
    monkeypatch.setenv("GITLAB_TOKEN", TOKEN)
    result = CliRunner().invoke(
        app, ["verify", "-P", str(policy), "--pipeline", "1042", "--gitlab-url", BASE]
    )
    assert result.exit_code == EXIT_INDETERMINATE
    assert TOKEN not in result.output + result.stderr


# ---------------------------------------------------------------- time


def test_slow_drip_api_page_hits_the_deadline_and_is_not_retried(mock_api) -> None:
    clock = Clock()
    route = mock_api.get(JOBS).mock(
        side_effect=lambda req: httpx.Response(200, stream=Drip(clock, step=50))
    )
    with gitlab(clock=clock, request_deadline=300) as gl, pytest.raises(ConnectorError) as err:
        gl.list_jobs("123", 1042)
    assert err.value.kind is ErrorKind.NETWORK
    assert "took longer than 300s" in err.value.message
    assert route.call_count == 1  # a server that drips gets no second 300 s


def test_slow_drip_artifact_download_hits_the_deadline(mock_api) -> None:
    clock = Clock()
    url = f"{API}/projects/123/jobs/7/artifacts/semgrep.json"
    mock_api.get(url).mock(side_effect=lambda req: httpx.Response(200, stream=Drip(clock, 100)))
    with gitlab(clock=clock) as gl, pytest.raises(ConnectorError) as err:
        gl.download_artifact_file("123", 7, "semgrep.json")
    assert err.value.kind is ErrorKind.NETWORK


def test_a_body_just_inside_the_deadline_is_fine(mock_api) -> None:
    clock = Clock()
    mock_api.get(JOBS).mock(side_effect=lambda req: httpx.Response(200, stream=Drip(clock, 29)))
    with gitlab(clock=clock, request_deadline=300) as gl:
        assert gl.list_jobs("123", 1042) == []


def test_run_budget_interrupts_streamed_api_body(mock_api) -> None:
    clock = Clock()
    route = mock_api.get(JOBS).mock(
        side_effect=lambda req: httpx.Response(200, stream=Drip(clock, step=10, chunks=10))
    )
    with (
        gitlab(clock=clock, run_budget=25, request_deadline=300) as gl,
        pytest.raises(ConnectorError) as err,
    ):
        gl.list_jobs("123", 1042)
    assert err.value.kind is ErrorKind.NETWORK
    assert "time budget" in err.value.message
    assert route.call_count == 1


def test_run_budget_interrupts_streamed_artifact(mock_api) -> None:
    clock = Clock()
    url = f"{API}/projects/123/jobs/7/artifacts/semgrep.json"
    route = mock_api.get(url).mock(
        side_effect=lambda req: httpx.Response(200, stream=Drip(clock, step=10, chunks=10))
    )
    with (
        gitlab(clock=clock, run_budget=25, request_deadline=300) as gl,
        pytest.raises(ConnectorError) as err,
    ):
        gl.download_artifact_file("123", 7, "semgrep.json")
    assert err.value.kind is ErrorKind.NETWORK
    assert "time budget" in err.value.message
    assert route.call_count == 1


@pytest.mark.parametrize(
    ("run_budget", "request_deadline", "expected"),
    [(1800, 25, "took longer than 25s"), (25, 300, "time budget")],
)
def test_empty_slow_api_stream_checks_deadline_at_end(
    mock_api, run_budget, request_deadline, expected
) -> None:
    clock = Clock()
    route = mock_api.get(JOBS).mock(
        side_effect=lambda req: httpx.Response(200, stream=SlowEmpty(clock, 40))
    )
    with (
        gitlab(clock=clock, run_budget=run_budget, request_deadline=request_deadline) as gl,
        pytest.raises(ConnectorError) as err,
    ):
        gl.list_jobs("123", 1042)
    assert err.value.kind is ErrorKind.NETWORK
    assert expected in err.value.message
    assert route.call_count == 1


def test_empty_slow_artifact_stream_checks_run_budget_at_end(mock_api) -> None:
    clock = Clock()
    url = f"{API}/projects/123/jobs/7/artifacts/semgrep.json"
    route = mock_api.get(url).mock(
        side_effect=lambda req: httpx.Response(200, stream=SlowEmpty(clock, 40))
    )
    with (
        gitlab(clock=clock, run_budget=25, request_deadline=300) as gl,
        pytest.raises(ConnectorError) as err,
    ):
        gl.download_artifact_file("123", 7, "semgrep.json")
    assert err.value.kind is ErrorKind.NETWORK
    assert "time budget" in err.value.message
    assert route.call_count == 1


def test_run_budget_stops_further_requests(mock_api) -> None:
    clock = Clock()
    route = mock_api.get(JOBS).respond(200, json=[JOB])
    with gitlab(clock=clock, run_budget=1800) as gl:
        assert len(gl.list_jobs("123", 1042)) == 1
        clock.now += 1801
        with pytest.raises(ConnectorError) as err:
            gl.list_jobs("123", 1042)
    assert err.value.kind is ErrorKind.NETWORK
    assert "time budget" in err.value.message
    assert route.call_count == 1  # no request once the budget is spent


# ---------------------------------------------------------------- size


def test_oversized_api_page_is_capped(mock_api) -> None:
    mock_api.get(JOBS).respond(200, json=[JOB] * 200)
    with gitlab(max_artifact_bytes=1000) as gl, pytest.raises(ConnectorError) as err:
        gl.list_jobs("123", 1042)
    assert err.value.kind is ErrorKind.LIMIT_EXCEEDED


# ---------------------------------------------------------------- partial downloads


CONNECTORS = {
    "gitlab": lambda: GitLabConnector(BASE, TOKEN, sleep=lambda _: None),
    "github": lambda: GitHubConnector(GH, "t", sleep=lambda _: None),
    "azure-devops": lambda: AzureDevOpsConnector(
        "https://dev.azure.com", "pat", sleep=lambda _: None
    ),
    "bitbucket": lambda: BitbucketConnector(
        "https://api.bitbucket.org/2.0", "t", sleep=lambda _: None
    ),
    "jenkins": lambda: JenkinsConnector(
        "https://jenkins.example.com", "t", username="u", sleep=lambda _: None
    ),
}


@pytest.mark.parametrize("name", list(CONNECTORS))
def test_download_that_keeps_dropping_is_a_network_error(mock_api, name) -> None:
    with CONNECTORS[name]() as c:
        url = f"{c.api_url}/some/artifact"
        route = mock_api.get(url).mock(side_effect=lambda req: httpx.Response(200, stream=Drops()))
        with pytest.raises(ConnectorError) as err:
            c._download(url, "artifact")
    assert err.value.kind is ErrorKind.NETWORK
    assert route.call_count == c.max_retries + 1  # retried, then given up: never partial bytes


@pytest.mark.parametrize("name", list(CONNECTORS))
def test_download_dropping_once_is_retried(mock_api, name) -> None:
    calls = {"n": 0}

    def flaky(req):
        calls["n"] += 1
        return (
            httpx.Response(200, stream=Drops())
            if calls["n"] == 1
            else httpx.Response(200, content=b'{"complete": true}')
        )

    with CONNECTORS[name]() as c:
        url = f"{c.api_url}/some/artifact"
        mock_api.get(url).mock(side_effect=flaky)
        assert c._download(url, "artifact") == b'{"complete": true}'


@pytest.mark.parametrize("name", list(CONNECTORS))
def test_api_page_dropping_mid_body_is_a_network_error(mock_api, name) -> None:
    with CONNECTORS[name]() as c:
        url = f"{c.api_url}/some/page"
        mock_api.get(url).mock(side_effect=lambda req: httpx.Response(200, stream=Drops()))
        with pytest.raises(ConnectorError) as err:
            c._send(url)
    assert err.value.kind is ErrorKind.NETWORK


# ---------------------------------------------------------------- compression bombs


def _gzip_bomb(mib: int) -> bytes:
    import gzip
    import io

    raw = io.BytesIO()
    with gzip.GzipFile(fileobj=raw, mode="wb", compresslevel=9) as g:
        for _ in range(mib):
            g.write(b"\0" * (1 << 20))
    return raw.getvalue()


BOMB = _gzip_bomb(256)  # about 250 KiB on the wire, 256 MiB decoded


class Network(httpx.SyncByteStream):
    """Deliver the body as an HTTP/1.1 connection does: reads of at most 64 KiB."""

    def __iter__(self):
        for i in range(0, len(BOMB), 65536):
            yield BOMB[i : i + 65536]


@pytest.mark.parametrize("kind", ["api page", "artifact"])
def test_gzip_bomb_stops_at_the_cap_with_bounded_memory(mock_api, kind) -> None:
    import tracemalloc

    headers = {"Content-Encoding": "gzip"}
    mock_api.get(JOBS).mock(
        side_effect=lambda r: httpx.Response(200, headers=headers, stream=Network())
    )
    url = f"{API}/projects/123/jobs/7/artifacts/r.json"
    mock_api.get(url).mock(
        side_effect=lambda r: httpx.Response(200, headers=headers, stream=Network())
    )
    tracemalloc.start()
    try:
        with gitlab(max_artifact_bytes=1 << 20) as gl, pytest.raises(ConnectorError) as err:
            if kind == "api page":
                gl.list_jobs("123", 1042)
            else:
                gl.download_artifact_file("123", 7, "r.json")
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert err.value.kind is ErrorKind.LIMIT_EXCEEDED
    # One 64 KiB read inflates to at most ~64 MiB (deflate's ratio is about 1000:1); the cap
    # stops reading right after. Without the cap, the whole 256 MiB would be decoded.
    assert peak < 160 * 2**20
