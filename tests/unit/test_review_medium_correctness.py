"""Regression coverage for fail-closed release-gate edge cases from review §9.5."""

import pytest

from scanproof.connectors.base import ConnectorError, ErrorKind
from scanproof.connectors.bitbucket import BitbucketConnector
from scanproof.models import Job, JobStatus
from scanproof.policy.results import Outcome, combine


def test_unknown_future_outcome_never_defaults_to_pass() -> None:
    assert combine(["future-status"]) is Outcome.UNKNOWN


def test_bitbucket_unavailable_commit_is_unknown_not_report_missing() -> None:
    job = Job(id=1, name="security", status=JobStatus.SUCCESS, commit_sha="")
    with BitbucketConnector("https://api.bitbucket.org/2.0", "token") as connector:
        with pytest.raises(ConnectorError) as exc:
            connector.fetch_report("workspace/repo", job, "report")
    assert exc.value.kind is ErrorKind.INVALID_RESPONSE
