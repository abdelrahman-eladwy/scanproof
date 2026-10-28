"""#44 fuzz/property gap: properties of the decision and of its serialized form, over seeded
random policies and evidence (real fixtures, fuzzed reports, missing jobs, provider errors,
matrix instances, waivers).

For every generated case:
- the decision follows from the requirement outcomes, and exit_code from the decision;
- every requirement's outcome is the combination of its checks; FAIL is never VERIFIED;
- the report is strict JSON (no NaN / Infinity), round-trips to an equal model, and keeps its
  decision and exit code through that round trip;
- the console summary renders without raising.
"""

from __future__ import annotations

import json
import random
from datetime import UTC, datetime, timedelta

import pytest

from scanproof import __version__
from scanproof.models import InspectedJob, Job, JobStatus, Pipeline
from scanproof.policy.engine import Decision, Outcome, RequirementInput, combine, evaluate
from scanproof.policy.models import Policy
from scanproof.reporting.console import print_verification_summary
from scanproof.scanners import ADAPTERS, get_adapter
from scanproof.verification import VerificationReport
from tests.conftest import FIXTURES
from tests.unit.test_robustness import SAMPLES, _mutate

NOW = datetime(2026, 10, 28, 12, tzinfo=UTC)
SHA = "c" * 40
PIPELINE = Pipeline(id=9, sha=SHA, ref="main", status="success")
TOOLS = ["semgrep", "trivy", "sarif", "cyclonedx", "checkov", "gitleaks", "zap", "nuclei"]
CASES = 400


def _reject_constant(name: str):
    raise ValueError(f"non-standard JSON constant {name}")


def strict_json(text: str):
    return json.loads(text, parse_constant=_reject_constant)


def random_job(rng: random.Random, name: str) -> InspectedJob:
    status = rng.choice(list(JobStatus))
    sha = rng.choice([SHA, SHA, "d" * 40, None])
    finished = NOW - timedelta(hours=rng.choice([1, 50, 500])) if status.is_terminal else None
    job = Job(
        id=rng.randint(1, 10**6),
        name=name,
        status=status,
        allow_failure=rng.random() < 0.2,
        commit_sha=sha,
        finished_at=finished,
    )
    return InspectedJob(
        name=name,
        stage=None,
        latest=job,
        attempt_ids=[job.id],
        commit_matches_pipeline=None if sha is None else sha == SHA,
    )


def random_evidence(rng: random.Random, tool: str):
    adapter = ADAPTERS[tool]
    base = json.loads((FIXTURES / rng.choice(SAMPLES[tool])).read_text())
    roll = rng.random()
    if roll < 0.5:
        return adapter.parse(json.dumps(base).encode())
    if roll < 0.8:
        return adapter.parse(json.dumps(_mutate(rng, base)).encode())
    if roll < 0.9:
        return adapter.parse(None)
    return adapter.parse(rng.choice([b"", b"{}", b"[]", b"\xff\xfe", b'{"x": 1e999}']))


def random_input(rng: random.Random, req: dict, depth: int = 0) -> RequirementInput:
    roll = rng.random()
    if roll < 0.08:
        return RequirementInput()  # job absent
    if roll < 0.12:
        return RequirementInput(absence_unknown="a downstream pipeline returned 403")
    if roll < 0.2 and depth == 0:
        legs = [
            (f"{req['job_name']} ({leg})", random_input(rng, req, depth + 1))
            for leg in rng.sample(["py", "js", "go"], rng.randint(1, 3))
        ]
        return RequirementInput(instances=legs)
    job = random_job(rng, req["job_name"])
    if rng.random() < 0.1:
        return RequirementInput(job=job, evidence_error="HTTP 503 fetching the report")
    return RequirementInput(job=job, evidence=random_evidence(rng, req["tool"]))


def random_case(rng: random.Random) -> tuple[Policy, dict[str, RequirementInput]]:
    requirements = []
    for i in range(rng.randint(1, 4)):
        tool = rng.choice(TOOLS)
        checks: dict = {}
        if rng.random() < 0.4:
            checks["scanner_errors_allowed"] = rng.choice([0, 1])
        if rng.random() < 0.3:
            checks["minimum_scanned_files"] = rng.choice([0, 1, 5])
        if rng.random() < 0.2:
            checks["max_age_hours"] = rng.choice([24.0, 168.0])
        if rng.random() < 0.15:
            checks["job_success"] = False
        if rng.random() < 0.15:
            checks["report_required"] = False
        req = {
            "id": f"R{i}",
            "tool": tool,
            "job_name": f"job{i}",
            "report_path": "r.json",
            "checks": checks,
        }
        if rng.random() < 0.15:
            req["applies_to"] = {"refs": [rng.choice(["main", "release/*"])]}
        requirements.append(req)
    enforcement = {
        "on_unknown": rng.choice(["block", "block", "warn"]),
        "on_nothing_applicable": rng.choice(["block", "block", "allow"]),
    }
    waivers = []
    if rng.random() < 0.2:
        waivers.append(
            {
                "requirement": "R0",
                "check": rng.choice(["job_success", "report", "scanner_errors"]),
                "reason": "accepted until the scanner fix ships",
                "approved_by": "security",
                "expires": (NOW + timedelta(days=rng.choice([-1, 30]))).date().isoformat(),
            }
        )
    policy = Policy.model_validate(
        {
            "apiVersion": "scanproof.dev/v1alpha1",
            "kind": "PipelineAssurancePolicy",
            "project": {"provider": "gitlab", "id": "1"},
            "requirements": requirements,
            "enforcement": enforcement,
            "waivers": waivers,
        }
    )
    inputs = {r["id"]: random_input(rng, r) for r in requirements}
    return policy, inputs


def expected_decision(policy: Policy, outcomes: list[Outcome]) -> Decision:
    if all(o is Outcome.NOT_APPLICABLE for o in outcomes):
        allow = policy.enforcement.on_nothing_applicable == "allow"
        return Decision.VERIFIED if allow else Decision.INDETERMINATE
    if Outcome.FAIL in outcomes:
        return Decision.BLOCKED
    if Outcome.UNKNOWN in outcomes:
        warn = policy.enforcement.on_unknown == "warn"
        return Decision.VERIFIED if warn else Decision.INDETERMINATE
    return Decision.VERIFIED


@pytest.mark.parametrize("seed", range(4))
def test_decision_and_report_properties(seed, capsys) -> None:
    rng = random.Random(f"scanproof-properties-{seed}")  # noqa: S311 - reproducible, not crypto
    seen: set[Decision] = set()
    for _ in range(CASES // 4):
        policy, inputs = random_case(rng)
        evaluation = evaluate(policy, PIPELINE, inputs, now=NOW)
        outcomes = [r.outcome for r in evaluation.requirements]

        # The decision follows from the outcomes; the exit code from the decision.
        assert evaluation.decision is expected_decision(policy, outcomes)
        seen.add(evaluation.decision)
        for result in evaluation.requirements:
            checks = [c.outcome for c in result.checks]
            # Waived checks count as passing: that is what a waiver is for.
            effective = [Outcome.PASS if o is Outcome.WAIVED else o for o in checks]
            assert result.outcome is combine(effective), result
            if Outcome.FAIL in checks:
                assert evaluation.decision is not Decision.VERIFIED

        report = VerificationReport(
            scanproof_version=__version__,
            generated_at=NOW,
            policy=policy.name,
            provider="gitlab",
            instance_url="https://gitlab.example.com",
            project="1",
            pipeline=PIPELINE,
            decision=evaluation.decision,
            exit_code=evaluation.decision.exit_code,
            requirements=evaluation.requirements,
            evidence={rid: i.evidence for rid, i in inputs.items() if i.evidence is not None},
            warnings=evaluation.warnings,
        )
        text = report.model_dump_json(indent=2)
        doc = strict_json(text)  # no NaN / Infinity, whatever the scanners reported
        assert doc["decision"] == report.decision.value
        assert (
            doc["exit_code"] == {"VERIFIED": 0, "BLOCKED": 1, "INDETERMINATE": 2}[doc["decision"]]
        )
        again = VerificationReport.model_validate_json(text)
        assert again.decision is report.decision and again.exit_code == report.exit_code
        assert again.model_dump_json(indent=2) == text  # stable round trip
        print_verification_summary(report)
    capsys.readouterr()
    assert seen == set(Decision)  # the generator reaches every decision


def test_non_finite_numbers_in_reports_serialize_as_strict_json() -> None:
    raw = b'{"results": [], "errors": [], "paths": {"scanned": []}, "time": 1e999}'
    ev = get_adapter("semgrep").parse(raw)
    strict_json(ev.model_dump_json())
