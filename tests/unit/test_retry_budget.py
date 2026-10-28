"""Phase 3 (#46): retries are bounded by the server's Retry-After AND the run budget.

A retry the server has told us is premature, or that cannot finish inside the remaining
run budget, is not attempted: the connector reports the real status (RATE_LIMITED /
SERVER) at once instead of sleeping and then misreporting a NETWORK budget overrun.
Every path still ends INDETERMINATE, never VERIFIED.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from email.utils import format_datetime

import httpx
import pytest

from scanproof.connectors.base import ConnectorError, ErrorKind
from scanproof.connectors.github import GitHubConnector
from scanproof.connectors.gitlab import GitLabConnector
from tests.conftest import BASE, TOKEN
from tests.unit.test_hostile_providers import JOB, JOBS, Clock

GH_API = "https://api.github.com"


class Sleeper:
    """Records sleeps and advances the shared clock, like real time passing."""

    def __init__(self, clock: Clock) -> None:
        self.clock, self.calls = clock, []

    def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)
        self.clock.now += seconds


def gitlab(clock: Clock, sleeper: Sleeper, **kw) -> GitLabConnector:
    kw.setdefault("max_retries", 3)
    return GitLabConnector(BASE, TOKEN, sleep=sleeper, clock=clock, backoff_seconds=1.0, **kw)


def _expect(kind: ErrorKind, code: int, fn) -> ConnectorError:
    with pytest.raises(ConnectorError) as err:
        fn()
    assert err.value.kind is kind
    assert err.value.status_code == code
    return err.value


def test_retry_after_beyond_cap_fails_fast_as_rate_limited(mock_api) -> None:
    clock = Clock()
    sleeper = Sleeper(clock)
    route = mock_api.get(JOBS).respond(429, headers={"Retry-After": "3600"})
    with gitlab(clock, sleeper) as gl:
        _expect(ErrorKind.RATE_LIMITED, 429, lambda: gl.list_jobs("123", 1042))
    assert sleeper.calls == []  # never slept 60s just to be told to wait again
    assert route.call_count == 1


def test_retry_after_within_cap_is_honored_then_succeeds(mock_api) -> None:
    clock = Clock()
    sleeper = Sleeper(clock)
    mock_api.get(JOBS).mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "20"}),
            httpx.Response(200, json=[JOB]),
        ]
    )
    with gitlab(clock, sleeper) as gl:
        assert len(gl.list_jobs("123", 1042)) == 1
    assert sleeper.calls == [20.0]


def test_wait_that_would_overrun_run_budget_is_not_slept(mock_api) -> None:
    clock = Clock()
    sleeper = Sleeper(clock)
    route = mock_api.get(JOBS).respond(429, headers={"Retry-After": "30"})
    with gitlab(clock, sleeper, run_budget=100) as gl:
        clock.now += 80  # 20s of budget left; a 30s wait cannot fit
        _expect(ErrorKind.RATE_LIMITED, 429, lambda: gl.list_jobs("123", 1042))
    assert sleeper.calls == []
    assert route.call_count == 1


def test_total_retry_sleep_never_exceeds_run_budget(mock_api) -> None:
    clock = Clock()
    sleeper = Sleeper(clock)
    mock_api.get(JOBS).respond(503, headers={"Retry-After": "40"})
    with gitlab(clock, sleeper, run_budget=100, max_retries=10) as gl:
        start = clock.now
        _expect(ErrorKind.SERVER, 503, lambda: gl.list_jobs("123", 1042))
    assert sum(sleeper.calls) <= 100
    assert clock.now - start <= 100
    assert sleeper.calls == [40.0, 40.0]  # a third 40s wait would end past the budget


@pytest.mark.parametrize("offset", [15, -30])
def test_http_date_retry_after_is_understood(mock_api, offset) -> None:
    clock = Clock()
    sleeper = Sleeper(clock)
    when = format_datetime(datetime.now(UTC) + timedelta(seconds=offset), usegmt=True)
    mock_api.get(JOBS).mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": when}),
            httpx.Response(200, json=[JOB]),
        ]
    )
    with gitlab(clock, sleeper) as gl:
        assert len(gl.list_jobs("123", 1042)) == 1
    assert len(sleeper.calls) == 1
    # A date in the past means "now": fall back to the normal 1s backoff.
    expected = (offset - 3, offset + 1) if offset > 0 else (1.0, 1.0)
    assert expected[0] <= sleeper.calls[0] <= expected[1]


@pytest.mark.parametrize("header", ["soon", "-5", "1e9", "", "  ", "4.5"])
def test_unparseable_retry_after_uses_bounded_backoff(mock_api, header) -> None:
    clock = Clock()
    sleeper = Sleeper(clock)
    mock_api.get(JOBS).respond(429, headers={"Retry-After": header})
    with gitlab(clock, sleeper, max_retries=3) as gl:
        _expect(ErrorKind.RATE_LIMITED, 429, lambda: gl.list_jobs("123", 1042))
    assert sleeper.calls == [1.0, 2.0, 4.0]


def test_github_secondary_rate_limit_beyond_cap_fails_fast(mock_api) -> None:
    clock = Clock()
    sleeper = Sleeper(clock)
    url = f"{GH_API}/repos/acme/app/actions/runs/7"
    route = mock_api.get(url).respond(403, headers={"retry-after": "900"})
    gh = GitHubConnector(GH_API, "ghp-x", sleep=sleeper, clock=clock, max_retries=3)
    with gh, pytest.raises(ConnectorError) as err:
        gh.get_pipeline("acme/app", 7)
    # A secondary rate limit is not an authorization problem.
    assert err.value.kind is ErrorKind.RATE_LIMITED
    assert sleeper.calls == []
    assert route.call_count == 1


def test_transport_errors_stop_when_budget_cannot_cover_backoff(mock_api) -> None:
    clock = Clock()
    sleeper = Sleeper(clock)
    route = mock_api.get(JOBS).mock(side_effect=httpx.ConnectError("refused"))
    gl = gitlab(clock, sleeper, run_budget=5, max_retries=10)
    with gl, pytest.raises(ConnectorError) as err:
        gl.list_jobs("123", 1042)
    assert err.value.kind is ErrorKind.NETWORK
    assert sum(sleeper.calls) <= 5
    assert sleeper.calls == [1.0, 2.0]  # the 4s backoff would end past the 5s budget
    assert route.call_count == 3
