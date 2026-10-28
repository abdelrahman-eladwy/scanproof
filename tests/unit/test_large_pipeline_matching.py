"""#46: large job inventories must preserve matrix and parallel completeness.

This is a correctness regression over a realistic-sized synthetic *inventory*,
not a provider/network or full release-gate performance qualification.
"""

from __future__ import annotations

from scanproof.evidence.collector import match_jobs
from scanproof.models import InspectedJob, Job, JobStatus

SHA = "a" * 40
COPIES = [f"svc-{i:02d}" for i in range(20)]
INSTANCES = [f"lang-{i:02d}" for i in range(50)]


def inspected(number: int, name: str) -> InspectedJob:
    job = Job(id=number, name=name, status=JobStatus.SUCCESS, commit_sha=SHA)
    return InspectedJob(
        name=name,
        stage=None,
        latest=job,
        attempt_ids=[number],
        commit_matches_pipeline=True,
    )


def large_inventory() -> list[InspectedJob]:
    names = [f"{copy} > sast: [{label}]" for copy in COPIES for label in INSTANCES]
    names.extend(f"unrelated-{i:04d}" for i in range(1000))
    return [inspected(i, name) for i, name in enumerate(names, 1)]


def test_two_thousand_jobs_with_fifty_way_matrices_are_complete():
    jobs = large_inventory()
    assert len(jobs) == 2000
    match = match_jobs(jobs, "sast", instances=INSTANCES, copies=COPIES)
    assert len(match.jobs) == 1000
    assert not match.missing
    assert not match.missing_declared
    assert not match.missing_copies
    assert not match.undeclared_copies


def test_one_missing_matrix_leg_remains_a_failure_with_two_thousand_jobs():
    jobs = [j for j in large_inventory() if j.name != "svc-07 > sast: [lang-19]"]
    jobs.append(inspected(3000, "unrelated-replacement"))
    assert len(jobs) == 2000
    match = match_jobs(jobs, "sast", instances=INSTANCES, copies=COPIES)
    assert match.missing_declared == [("svc-07 > sast: [lang-19]", "lang-19")]
    assert len(match.jobs) == 999


def test_parallel_two_thousand_leg_completeness_is_bounded():
    jobs = [inspected(i, f"sast {i}/2000") for i in range(1, 2001)]
    good = match_jobs(jobs, "sast")
    assert len(good.jobs) == 2000
    assert good.missing == []
    missing = match_jobs([j for j in jobs if j.name != "sast 777/2000"], "sast")
    assert len(missing.jobs) == 1999
    assert len(missing.missing) == 1
    assert "missing 1 of 2000 parallel legs" in missing.missing[0]
    assert len(missing.missing[0]) < 180


def test_qualified_large_matrix_does_not_match_other_copies():
    jobs = large_inventory()
    match = match_jobs(jobs, "svc-07 > sast", instances=INSTANCES)
    assert len(match.jobs) == 50
    assert not match.missing_declared
    assert not match.missing_copies
