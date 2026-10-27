"""Complex GitLab scenarios: monorepos with child pipelines, multi-project downstreams, parallel
and matrix jobs, retries in every order, gates that run mid-pipeline, many simultaneous faults,
flaky networks and large pipelines. Reports are REAL scanner output (tests/fixtures/)."""

from __future__ import annotations

import json
import time

import httpx
import pytest

from scanproof.policy.engine import Decision, Outcome
from scanproof.policy.models import Policy
from scanproof.verification import verify_pipeline
from tests.conftest import BASE, FIXTURES
from tests.fake_gitlab import FakeGitLab

SEMGREP = (FIXTURES / "semgrep/semgrep-findings.json").read_bytes()
SEMGREP_ERRORS = (FIXTURES / "semgrep/semgrep-errors.json").read_bytes()
TRIVY = (FIXTURES / "trivy/trivy-python.json").read_bytes()
OTHER_SHA = "f" * 40


def policy(*reqs: dict, **extra) -> Policy:
    return Policy.model_validate(
        {
            "apiVersion": "scanproof.dev/v1alpha1",
            "kind": "PipelineAssurancePolicy",
            "project": {"provider": "gitlab", "id": "123"},
            "requirements": list(reqs),
            **extra,
        }
    )


def sast(job: str = "semgrep-sast", rid: str = "SAST", **checks) -> dict:
    return {
        "id": rid,
        "tool": "semgrep",
        "job_name": job,
        "report_path": "semgrep.json",
        "checks": {"scanner_errors_allowed": 0, "minimum_scanned_files": 1, **checks},
    }


@pytest.fixture
def gl(mock_api) -> FakeGitLab:
    return FakeGitLab(mock_api)


def verify(connector, gl: FakeGitLab, pol: Policy):
    gl.install()
    return verify_pipeline(connector, pol, instance_url=BASE, project="123", pipeline_id=1042)


def codes(report, rid: str = "SAST") -> dict[str, str]:
    req = next(r for r in report.requirements if r.id == rid)
    return {c.check: c.code for c in req.checks if c.outcome is not Outcome.PASS}


# ---------------------------------------------------------------- monorepo / child pipelines


def test_monorepo_one_service_masks_its_scan(connector, gl) -> None:
    """3 services, each scanned in its own child pipeline; service B's scan failed under
    allow_failure. The whole release is blocked, and only B is named."""
    for i, svc in enumerate(["svc-a", "svc-b", "svc-c"]):
        child = gl.child(f"{svc}:trigger", pipeline_id=2000 + i)
        failed = svc == "svc-b"
        child.job(
            3000 + i,
            "semgrep-sast",
            status="failed" if failed else "success",
            allow_failure=failed,
            files={"semgrep.json": SEMGREP},
        )
    report = verify(connector, gl, policy(sast()))
    assert report.decision is Decision.BLOCKED
    req = report.requirements[0]
    assert req.instances == [f"{s}:trigger > semgrep-sast" for s in ("svc-a", "svc-b", "svc-c")]
    assert codes(report) == {
        "job_success [svc-b:trigger > semgrep-sast]": "FAILURE_MASKED_BY_ALLOW_FAILURE"
    }


def test_monorepo_all_services_clean(connector, gl) -> None:
    for i in range(3):
        gl.child(f"svc-{i}:trigger", pipeline_id=2000 + i).job(
            3000 + i, "semgrep-sast", files={"semgrep.json": SEMGREP}
        )
    report = verify(connector, gl, policy(sast()))
    assert report.decision is Decision.VERIFIED
    assert report.requirements[0].findings["total"] == 18  # 6 findings x 3 services, summed


def test_unreadable_child_makes_absence_unknown_not_failure(connector, gl) -> None:
    """Real gitlab.com case: a downstream pipeline the token can't read (403). The scan may be
    in it, so 'job absent' would be a guess: INDETERMINATE, not BLOCKED."""
    gl.child("security:trigger", pipeline_id=2000, readable=False)
    report = verify(connector, gl, policy(sast()))
    assert report.decision is Decision.INDETERMINATE
    assert codes(report) == {"job_present": "JOB_MAYBE_IN_UNREADABLE_PIPELINE"}
    assert any("could not be read" in w for w in report.warnings)


def test_trigger_that_never_started_a_pipeline(connector, gl) -> None:
    gl.failed_trigger("security:trigger")
    report = verify(connector, gl, policy(sast()))
    assert report.decision is Decision.BLOCKED
    assert codes(report) == {"job_present": "REQUIRED_JOB_ABSENT"}
    assert any("did not start a downstream pipeline" in w for w in report.warnings)


def test_nested_children_and_qualified_name(connector, gl) -> None:
    grandchild = gl.child("platform", pipeline_id=2000).child("security", pipeline_id=2001)
    grandchild.job(3000, "semgrep-sast", files={"semgrep.json": SEMGREP})
    report = verify(connector, gl, policy(sast("platform > security > semgrep-sast")))
    assert report.decision is Decision.VERIFIED
    assert report.requirements[0].instances is None  # exact (qualified) match, single job


def test_multi_project_downstream_uses_child_project_and_checks_commit(connector, gl, mock_api):
    """Multi-project downstream (also seen on gitlab.com): artifacts must be fetched from the
    child's project, and its different commit is reported, not silently accepted."""
    child = gl.child("scan:other-repo", project="777", pipeline_id=5000, sha=OTHER_SHA)
    child.job(6000, "semgrep-sast", sha=OTHER_SHA, files={"semgrep.json": SEMGREP})
    report = verify(connector, gl, policy(sast()))
    assert report.decision is Decision.BLOCKED
    assert codes(report) == {"same_commit": "COMMIT_MISMATCH"}
    source = report.evidence["SAST"].source
    assert source is not None
    assert source.project == "777"
    assert source.pipeline_id == 5000
    assert source.pipeline_sha == OTHER_SHA
    assert any(
        c.request.url.path == "/api/v4/projects/777/jobs/6000/artifacts/semgrep.json"
        for c in mock_api.calls
    )

    report = verify(connector, gl, policy(sast(same_commit=False)))
    assert report.decision is Decision.VERIFIED


def test_multi_project_attestation_bundle_fetched_from_child(connector, gl, mock_api, monkeypatch):
    """A bundled attestation must come from the same project as its scan report."""
    child = gl.child("scan:other-repo", project="777", pipeline_id=5000)
    child.job(
        6000,
        "semgrep-sast",
        files={"semgrep.json": SEMGREP, "semgrep.sigstore.json": b"{}"},
    )
    monkeypatch.setattr("scanproof.verification.verify_bundles", lambda *args, **kwargs: [])
    requirement = sast()
    requirement["attestation"] = {
        "source": "artifact",
        "bundle_path": "semgrep.sigstore.json",
        "signer": {
            "issuer": "https://gitlab.com",
            "repository": "https://gitlab.example.com/777",
        },
    }
    verify(connector, gl, policy(requirement))
    fetched = [str(call.request.url.path) for call in mock_api.calls]
    assert "/api/v4/projects/777/jobs/6000/artifacts/semgrep.sigstore.json" in fetched
    assert "/api/v4/projects/123/jobs/6000/artifacts/semgrep.sigstore.json" not in fetched


# ---------------------------------------------------------------- parallel / matrix


def test_parallel_instance_missing_is_detected(connector, gl) -> None:
    """GitLab names parallel jobs 'sast 1/3'..; the total tells us 2/3 is missing."""
    gl.job(1, "semgrep-sast 1/3", files={"semgrep.json": SEMGREP})
    gl.job(3, "semgrep-sast 3/3", files={"semgrep.json": SEMGREP})
    report = verify(connector, gl, policy(sast()))
    assert report.decision is Decision.BLOCKED
    assert codes(report) == {"job_present [semgrep-sast 2/3]": "REQUIRED_JOB_ABSENT"}


def test_parallel_all_instances_pass_including_a_retry(connector, gl) -> None:
    gl.job(1, "semgrep-sast 1/2", files={"semgrep.json": SEMGREP})
    gl.job(2, "semgrep-sast 2/2", status="failed", files={})
    gl.job(9, "semgrep-sast 2/2", files={"semgrep.json": SEMGREP})  # retry of 2/2 succeeded
    report = verify(connector, gl, policy(sast()))
    assert report.decision is Decision.VERIFIED


def test_matrix_instance_with_missing_report(connector, gl) -> None:
    gl.job(1, "trivy: [amd64]", files={"trivy.json": TRIVY})
    gl.job(2, "trivy: [arm64]", files={})
    req = {"id": "IMG", "tool": "trivy", "job_name": "trivy", "report_path": "trivy.json"}
    report = verify(connector, gl, policy(req))
    assert report.decision is Decision.BLOCKED
    assert codes(report, "IMG") == {"report [trivy: [arm64]]": "REPORT_MISSING"}


def test_exact_name_does_not_hide_failing_instances(connector, gl) -> None:
    """#59: this used to be VERIFIED ('exact name wins'), and the parallel job was assumed to
    be unrelated. ScanProof can't tell an unrelated 'semgrep-sast 1/2' from a hidden leg, so
    every job the name covers is evaluated. More cases: test_exact_name_instances.py."""
    gl.job(1, "semgrep-sast", files={"semgrep.json": SEMGREP})
    gl.job(2, "semgrep-sast 1/2", status="failed")
    report = verify(connector, gl, policy(sast()))
    assert report.decision is Decision.BLOCKED
    assert codes(report) == {
        "job_success [semgrep-sast 1/2]": "JOB_NOT_SUCCESS",
        "report [semgrep-sast 1/2]": "REPORT_MISSING",
        "job_present [semgrep-sast 2/2]": "REQUIRED_JOB_ABSENT",
    }


# ---------------------------------------------------------------- retries


@pytest.mark.parametrize(
    ("attempts", "decision"),
    [
        ([("failed", True), ("failed", True), ("success", True)], Decision.VERIFIED),
        ([("success", True), ("canceled", True)], Decision.BLOCKED),  # re-run then canceled
        ([("success", True), ("success", False)], Decision.BLOCKED),  # latest has no report
    ],
)
def test_retry_orders(connector, gl, attempts, decision) -> None:
    for i, (status, with_report) in enumerate(attempts):
        gl.job(
            100 + i,
            "semgrep-sast",
            status=status,
            files={"semgrep.json": SEMGREP} if with_report else {},
        )
    report = verify(connector, gl, policy(sast()))
    assert report.decision is decision
    assert report.requirements[0].job_id == 100 + len(attempts) - 1  # always the latest attempt


# ---------------------------------------------------------------- timing / many faults


def test_gate_running_before_scans_finish_is_not_ready_not_failed(connector, gl) -> None:
    gl.job(1, "semgrep-sast", status="running", files={})
    gl.job(2, "trivy-image", status="pending", files={})
    report = verify(
        connector,
        gl,
        policy(
            sast(),
            {"id": "IMG", "tool": "trivy", "job_name": "trivy-image", "report_path": "t.json"},
        ),
    )
    assert report.decision is Decision.INDETERMINATE and report.exit_code == 2
    assert codes(report)["report"] == "REPORT_NOT_YET_AVAILABLE"


def test_six_requirements_six_different_faults(connector, gl) -> None:
    gl.job(1, "a", status="failed", allow_failure=True, sha=OTHER_SHA, files={})
    gl.job(2, "b", files={"semgrep.json": 403})
    gl.job(3, "c", status="running", files={})
    gl.job(4, "d", files={"semgrep.json": b'{"results": [ trunc'})
    gl.job(5, "e", files={"semgrep.json": SEMGREP_ERRORS})
    report = verify(connector, gl, policy(*(sast(j, rid=j.upper()) for j in "abcdef")))
    assert report.decision is Decision.BLOCKED
    got = {r.id: r.outcome for r in report.requirements}
    assert got == {
        "A": Outcome.FAIL,
        "B": Outcome.UNKNOWN,
        "C": Outcome.UNKNOWN,
        "D": Outcome.FAIL,
        "E": Outcome.FAIL,
        "F": Outcome.FAIL,
    }
    assert set(codes(report, "A").values()) == {
        "FAILURE_MASKED_BY_ALLOW_FAILURE",
        "COMMIT_MISMATCH",
        "REPORT_MISSING",
    }
    assert codes(report, "E") == {"scanner_errors": "SCANNER_ERRORS"}  # real syntax-error report
    assert codes(report, "D") == {"report": "REPORT_UNPARSEABLE"}
    assert codes(report, "F") == {"job_present": "REQUIRED_JOB_ABSENT"}
    json.loads(report.model_dump_json())  # the full report serializes


def test_merge_request_pipeline_with_main_only_policy(connector, gl) -> None:
    gl.ref = "refs/merge-requests/12/head"
    gl.job(1, "semgrep-sast", files={"semgrep.json": SEMGREP})
    req = {**sast(), "applies_to": {"refs": ["main", "release/*"]}}
    assert verify(connector, gl, policy(req)).decision is Decision.INDETERMINATE
    allowed = policy(req, enforcement={"on_nothing_applicable": "allow"})
    assert verify(connector, gl, allowed).decision is Decision.VERIFIED


# ---------------------------------------------------------------- flaky network


class _DropsMidBody(httpx.SyncByteStream):
    def __iter__(self):
        yield b'{"results": ['
        raise httpx.ReadError("connection reset by peer")


def test_download_dropping_once_is_retried(connector, gl) -> None:
    calls = {"n": 0}

    def flaky(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(200, stream=_DropsMidBody())
        return httpx.Response(200, content=SEMGREP)

    gl.job(1, "semgrep-sast", files={"semgrep.json": flaky})
    report = verify(connector, gl, policy(sast()))
    assert report.decision is Decision.VERIFIED and calls["n"] == 2


def test_download_that_keeps_dropping_is_indeterminate(connector, gl) -> None:
    gl.job(
        1,
        "semgrep-sast",
        files={"semgrep.json": lambda request: httpx.Response(200, stream=_DropsMidBody())},
    )
    report = verify(connector, gl, policy(sast()))
    assert report.decision is Decision.INDETERMINATE
    assert codes(report) == {"report": "EVIDENCE_UNAVAILABLE"}


def test_rate_limit_in_the_middle_of_pagination(connector, gl, mock_api) -> None:
    for i in range(1, 301):
        gl.job(i, f"lint-{i}", files={})
    gl.job(999, "semgrep-sast", files={"semgrep.json": SEMGREP})
    gl.jobs_pages = 3
    gl.install()
    jobs_route = next(
        r for r in mock_api.routes if r.pattern and "pipelines/1042/jobs" in repr(r.pattern)
    )
    original = jobs_route.side_effect
    hits = {"page2": 0}

    def limited(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("page") == "2" and hits["page2"] == 0:
            hits["page2"] += 1
            return httpx.Response(429, headers={"Retry-After": "1"})
        return original(request)

    jobs_route.mock(side_effect=limited)
    report = verify_pipeline(
        connector, policy(sast()), instance_url=BASE, project="123", pipeline_id=1042
    )
    assert report.decision is Decision.VERIFIED  # the job on the last page was still found
    assert hits["page2"] == 1


# ---------------------------------------------------------------- scale


def test_large_pipeline_with_wide_parallelism(connector, gl) -> None:
    """2,000 lint jobs over 20 pages plus a 50-way parallel scan, each with a real report."""
    for i in range(1, 2001):
        gl.job(i, f"lint-{i}", files={})
    for i in range(1, 51):
        gl.job(10000 + i, f"semgrep-sast {i}/50", files={"semgrep.json": SEMGREP})
    gl.jobs_pages = 21
    started = time.monotonic()
    report = verify(connector, gl, policy(sast()))
    assert report.decision is Decision.VERIFIED
    assert len(report.requirements[0].instances) == 50
    assert time.monotonic() - started < 10  # ~0.2 s locally, with coverage
