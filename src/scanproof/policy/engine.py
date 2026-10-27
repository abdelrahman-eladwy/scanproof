"""Policy evaluation. Pure functions: no I/O, no CI provider or scanner-format knowledge.

Inputs are the inspected pipeline and, per requirement, the job (if present) and the
normalized evidence (or the reason it could not be obtained). Output is a decision with
a machine-readable code and a human message for every check.
"""

from __future__ import annotations

from enum import StrEnum
from fnmatch import fnmatchcase

from pydantic import BaseModel, Field

from scanproof.evidence.models import ScanEvidence
from scanproof.models import InspectedJob, JobStatus, Pipeline
from scanproof.policy.models import Policy, Requirement

_WARNING_LEVELS = {"warn", "warning", "info"}


class Outcome(StrEnum):
    PASS = "PASS"  # noqa: S105 - outcome name, not a password
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class Decision(StrEnum):
    VERIFIED = "VERIFIED"
    BLOCKED = "BLOCKED"
    INDETERMINATE = "INDETERMINATE"

    @property
    def exit_code(self) -> int:
        return {Decision.VERIFIED: 0, Decision.BLOCKED: 1, Decision.INDETERMINATE: 2}[self]


class CheckResult(BaseModel):
    check: str
    outcome: Outcome
    code: str
    message: str


class RequirementInput(BaseModel):
    """What the orchestrator gathered for one requirement (or one instance of it)."""

    job: InspectedJob | None = None
    evidence: ScanEvidence | None = None
    evidence_error: str | None = Field(
        default=None, description="Why evidence could not be fetched (auth, network...)"
    )
    absence_unknown: str | None = Field(
        default=None,
        description="Job not found, but it may live in a pipeline that couldn't be read",
    )
    instances: list[tuple[str, RequirementInput]] | None = Field(
        default=None,
        description="Parallel / matrix / downstream instances; every one must pass",
    )


class RequirementResult(BaseModel):
    id: str
    description: str | None
    tool: str
    job_name: str
    job_id: int | None
    outcome: Outcome
    checks: list[CheckResult]
    findings: dict[str, int] | None = Field(
        default=None, description="Reported for context only; findings are never judged"
    )
    instances: list[str] | None = Field(
        default=None, description="Job instances evaluated when job_name matched several"
    )


class Evaluation(BaseModel):
    decision: Decision
    requirements: list[RequirementResult]
    warnings: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------- aggregation


def combine(outcomes: list[Outcome]) -> Outcome:
    if not outcomes:
        return Outcome.NOT_APPLICABLE
    if Outcome.FAIL in outcomes:
        return Outcome.FAIL
    if Outcome.UNKNOWN in outcomes:
        return Outcome.UNKNOWN
    if all(o is Outcome.NOT_APPLICABLE for o in outcomes):
        return Outcome.NOT_APPLICABLE
    return Outcome.PASS


def evaluate(policy: Policy, pipeline: Pipeline, inputs: dict[str, RequirementInput]) -> Evaluation:
    results = [
        evaluate_requirement(req, pipeline, inputs.get(req.id, RequirementInput()))
        for req in policy.requirements
    ]
    outcomes = [r.outcome for r in results]
    warnings: list[str] = []

    if all(o is Outcome.NOT_APPLICABLE for o in outcomes):
        message = f"No requirement applies to ref '{pipeline.ref}'; nothing was verified."
        if policy.enforcement.on_nothing_applicable == "allow":
            return Evaluation(
                decision=Decision.VERIFIED,
                requirements=results,
                warnings=[f"{message} on_nothing_applicable=allow treats this as verified."],
            )
        return Evaluation(
            decision=Decision.INDETERMINATE,
            requirements=results,
            warnings=[
                f"{message} Blocking (set enforcement.on_nothing_applicable: allow, or limit "
                "when the gate runs, if this ref legitimately needs no checks)."
            ],
        )

    if Outcome.FAIL in outcomes:
        decision = Decision.BLOCKED
    elif Outcome.UNKNOWN in outcomes:
        if policy.enforcement.on_unknown == "warn":
            decision = Decision.VERIFIED
            warnings.append(
                "Some requirements could not be verified; on_unknown=warn treats them as passing."
            )
        else:
            decision = Decision.INDETERMINATE
    else:
        decision = Decision.VERIFIED

    return Evaluation(decision=decision, requirements=results, warnings=warnings)


# ---------------------------------------------------------------- one requirement


def evaluate_requirement(
    req: Requirement, pipeline: Pipeline, data: RequirementInput
) -> RequirementResult:
    def result(checks: list[CheckResult]) -> RequirementResult:
        ev = data.evidence
        return RequirementResult(
            id=req.id,
            description=req.description,
            tool=req.tool,
            job_name=req.job_name,
            job_id=data.job.latest.id if data.job else None,
            outcome=combine([c.outcome for c in checks]),
            checks=checks,
            findings=(ev.findings.by_severity | {"total": ev.findings.total})
            if ev and ev.findings
            else None,
        )

    if req.applies_to is not None:
        ref = pipeline.ref or ""
        if not any(fnmatchcase(ref, pattern) for pattern in req.applies_to.refs):
            return result(
                [
                    CheckResult(
                        check="applies_to",
                        outcome=Outcome.NOT_APPLICABLE,
                        code="REF_NOT_IN_SCOPE",
                        message=f"Ref '{ref}' does not match {req.applies_to.refs}",
                    )
                ]
            )

    if data.instances:
        return _evaluate_instances(req, pipeline, data.instances)

    if data.job is None and data.absence_unknown:
        return result(
            [
                CheckResult(
                    check="job_present",
                    outcome=Outcome.UNKNOWN,
                    code="JOB_MAYBE_IN_UNREADABLE_PIPELINE",
                    message=f"No job named '{req.job_name}' was found, but {data.absence_unknown}",
                )
            ]
        )

    if data.job is None:
        return result(
            [
                CheckResult(
                    check="job_present",
                    outcome=Outcome.FAIL,
                    code="REQUIRED_JOB_ABSENT",
                    message=(
                        f"No job named '{req.job_name}' in pipeline {pipeline.id}. "
                        "It may have been removed, renamed, or excluded by rules."
                    ),
                )
            ]
        )

    checks = [*_job_checks(req, data.job), *_evidence_checks(req, data)]
    return result(checks)


def _evaluate_instances(
    req: Requirement, pipeline: Pipeline, instances: list[tuple[str, RequirementInput]]
) -> RequirementResult:
    """Evaluate every instance as its own job; the requirement holds only if all of them do."""
    single = req.model_copy(update={"applies_to": None})
    checks: list[CheckResult] = []
    findings: dict[str, int] = {}
    for name, data in instances:
        sub = evaluate_requirement(single, pipeline, data.model_copy(update={"instances": None}))
        if data.job is None:
            sub.checks = [
                c.model_copy(update={"message": f"Expected instance '{name}' is missing"})
                for c in sub.checks
            ]
        checks.extend(c.model_copy(update={"check": f"{c.check} [{name}]"}) for c in sub.checks)
        for key, value in (sub.findings or {}).items():
            findings[key] = findings.get(key, 0) + value
    return RequirementResult(
        id=req.id,
        description=req.description,
        tool=req.tool,
        job_name=req.job_name,
        job_id=None,
        outcome=combine([c.outcome for c in checks]),
        checks=checks,
        findings=findings or None,
        instances=[name for name, _ in instances],
    )


def _job_checks(req: Requirement, job: InspectedJob) -> list[CheckResult]:
    out: list[CheckResult] = []
    latest = job.latest
    c = req.checks

    if c.job_success:
        status = latest.status
        if status is JobStatus.SUCCESS and latest.masking_checked is False:
            out.append(
                _r(
                    "job_success",
                    Outcome.UNKNOWN,
                    "STEP_MASKING_UNKNOWN",
                    f"Job {latest.id} reports success, but its check-run annotations could not "
                    "be read to rule out a step hidden by continue-on-error (grant checks:read)",
                )
            )
        elif status is JobStatus.SUCCESS:
            retried = f" after {job.attempts} attempts" if job.attempts > 1 else ""
            out.append(
                _r(
                    "job_success",
                    Outcome.PASS,
                    "JOB_SUCCEEDED",
                    f"Job {latest.id} succeeded{retried}",
                )
            )
        elif status in {JobStatus.FAILED, JobStatus.CANCELED} and latest.allow_failure:
            out.append(
                _r(
                    "job_success",
                    Outcome.FAIL,
                    "FAILURE_MASKED_BY_ALLOW_FAILURE",
                    f"Job {latest.id} {_how_it_was_masked(status, latest.raw_status)}",
                )
            )
        elif status.is_terminal or status is JobStatus.MANUAL:
            out.append(
                _r(
                    "job_success",
                    Outcome.FAIL,
                    "JOB_NOT_SUCCESS",
                    f"Job {latest.id} ended '{status.value}'",
                )
            )
        elif status is JobStatus.UNKNOWN:
            out.append(
                _r(
                    "job_success",
                    Outcome.UNKNOWN,
                    "JOB_STATUS_UNKNOWN",
                    f"Job {latest.id} has unrecognized status '{latest.raw_status}'",
                )
            )
        else:
            out.append(
                _r(
                    "job_success",
                    Outcome.UNKNOWN,
                    "JOB_NOT_FINISHED",
                    f"Job {latest.id} is '{latest.raw_status or status.value}'; result not final",
                )
            )

    if c.same_commit:
        if job.commit_matches_pipeline is True:
            out.append(
                _r("same_commit", Outcome.PASS, "COMMIT_MATCHES", "Job ran on the pipeline commit")
            )
        elif job.commit_matches_pipeline is False:
            out.append(
                _r(
                    "same_commit",
                    Outcome.FAIL,
                    "COMMIT_MISMATCH",
                    f"Job ran on {latest.commit_sha}, not the pipeline commit",
                )
            )
        else:
            out.append(
                _r(
                    "same_commit",
                    Outcome.UNKNOWN,
                    "COMMIT_UNKNOWN",
                    "Job did not report its commit",
                )
            )
    return out


def _evidence_checks(req: Requirement, data: RequirementInput) -> list[CheckResult]:
    c = req.checks
    wants_evidence = any(
        [
            c.report_required,
            c.scanner_errors_allowed is not None,
            c.minimum_scanned_files is not None,
            c.required_paths,
            c.image_digest_must_match,
            c.expected_scanner,
            c.minimum_components is not None,
            c.minimum_resources is not None,
        ]
    )
    if not wants_evidence:
        return []

    if data.evidence_error is not None:
        return [_r("report", Outcome.UNKNOWN, "EVIDENCE_UNAVAILABLE", data.evidence_error)]

    ev = data.evidence
    if ev is None or not ev.present:
        reason = (ev.parse_error if ev else None) or "No report obtained"
        status = data.job.latest.status if data.job else None
        if (
            c.report_required
            and status is not None
            and not status.is_terminal
            and (status is not JobStatus.MANUAL)
        ):
            # The job hasn't finished: its report may simply not exist yet. That is "not
            # ready" (exit 2), not "the control failed" (exit 1).
            return [
                _r(
                    "report",
                    Outcome.UNKNOWN,
                    "REPORT_NOT_YET_AVAILABLE",
                    f"{req.report_path}: job is still '{status.value}'",
                )
            ]
        if c.report_required:
            return [_r("report", Outcome.FAIL, "REPORT_MISSING", f"{req.report_path}: {reason}")]
        return [_r("report", Outcome.NOT_APPLICABLE, "REPORT_OPTIONAL_ABSENT", reason)]

    if not ev.parseable:
        return [
            _r("report", Outcome.FAIL, "REPORT_UNPARSEABLE", f"{req.report_path}: {ev.parse_error}")
        ]

    if ev.tool != req.tool.lower():
        return [
            _r(
                "report",
                Outcome.FAIL,
                "WRONG_TOOL",
                f"Report is from {ev.tool}, requirement expects {req.tool}",
            )
        ]

    out = [
        _r(
            "report",
            Outcome.PASS,
            "REPORT_VALID",
            f"{req.report_path} parsed ({ev.report_bytes} bytes)",
        )
    ]

    if c.scanner_errors_allowed is not None:
        out.append(_scanner_errors(ev, c.scanner_errors_allowed, c.ignore_scanner_warnings))
    if c.minimum_scanned_files is not None:
        out.append(_min_files(ev, c.minimum_scanned_files))
    if c.required_paths:
        out.append(_required_paths(ev, c.required_paths))
    if c.image_digest_must_match:
        out.append(_image_digest(ev, c.image_digest_must_match))
    if c.expected_scanner:
        out.append(_expected_scanner(ev, c.expected_scanner))
    if c.minimum_components is not None:
        out.append(_min_components(ev, c.minimum_components))
    if c.minimum_resources is not None:
        out.append(_min_resources(ev, c.minimum_resources))
    return out


# ---------------------------------------------------------------- individual checks


def _r(check: str, outcome: Outcome, code: str, message: str) -> CheckResult:
    return CheckResult(check=check, outcome=outcome, code=code, message=message)


def _scanner_errors(ev: ScanEvidence, allowed: int, ignore_warnings: bool) -> CheckResult:
    name = "scanner_errors"
    if ev.scanner_errors is None:
        return _r(
            name,
            Outcome.UNKNOWN,
            "SCANNER_ERRORS_UNKNOWN",
            f"{ev.tool} does not report its own errors",
        )
    counted = [
        e
        for e in ev.scanner_errors
        if not (ignore_warnings and (e.level or "").lower() in _WARNING_LEVELS)
    ]
    if len(counted) > allowed:
        sample = "; ".join(f"{e.type or 'error'}: {e.message.splitlines()[0]}" for e in counted[:3])
        return _r(
            name,
            Outcome.FAIL,
            "SCANNER_ERRORS",
            f"{len(counted)} scanner error(s), {allowed} allowed ({sample})",
        )
    return _r(
        name,
        Outcome.PASS,
        "SCANNER_ERRORS_OK",
        f"{len(counted)} scanner error(s), {allowed} allowed",
    )


def _min_files(ev: ScanEvidence, minimum: int) -> CheckResult:
    name = "minimum_scanned_files"
    files = ev.scope.files_scanned if ev.scope else None
    if files is None:
        return _r(
            name,
            Outcome.UNKNOWN,
            "SCOPE_UNKNOWN",
            "Report does not state how many files were scanned",
        )
    if files < minimum:
        return _r(
            name,
            Outcome.FAIL,
            "SCOPE_TOO_SMALL",
            f"{files} file(s) scanned, at least {minimum} required",
        )
    return _r(name, Outcome.PASS, "SCOPE_OK", f"{files} file(s) scanned")


def _norm(path: str) -> str:
    path = path.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path


def _required_paths(ev: ScanEvidence, prefixes: list[str]) -> CheckResult:
    name = "required_paths"
    scanned = ev.scope.scanned_paths if ev.scope else None
    if scanned is None:
        return _r(name, Outcome.UNKNOWN, "SCOPE_UNKNOWN", "Report does not list scanned paths")
    normalized = [_norm(p) for p in scanned]
    missing = [p for p in prefixes if not any(s.startswith(_norm(p)) for s in normalized)]
    if missing:
        return _r(
            name,
            Outcome.FAIL,
            "REQUIRED_PATH_NOT_SCANNED",
            f"No scanned file under: {', '.join(missing)}",
        )
    return _r(name, Outcome.PASS, "REQUIRED_PATHS_SCANNED", f"All of {prefixes} were scanned")


def _image_digest(ev: ScanEvidence, expected: str) -> CheckResult:
    name = "image_digest_must_match"
    target = ev.target
    known = (
        (target.digests() | ({target.image_id} if target.image_id else set())) if target else set()
    )
    if not known:
        return _r(
            name,
            Outcome.UNKNOWN,
            "IMAGE_DIGEST_UNKNOWN",
            "Report does not identify the image digest",
        )
    if expected not in known:
        scanned = target.artifact_name if target else None
        return _r(
            name,
            Outcome.FAIL,
            "IMAGE_DIGEST_MISMATCH",
            f"Scanned {scanned or 'an image'} ({', '.join(sorted(known))}), expected {expected}",
        )
    return _r(name, Outcome.PASS, "IMAGE_DIGEST_MATCHES", f"Scanned image has digest {expected}")


def _expected_scanner(ev: ScanEvidence, expected: str) -> CheckResult:
    name = "expected_scanner"
    if not ev.scanner_name:
        return _r(
            name, Outcome.UNKNOWN, "SCANNER_UNKNOWN", "Report does not name the engine that ran"
        )
    produced = {n.strip().lower() for n in ev.scanner_name.split(",")}
    if produced != {expected.strip().lower()}:
        return _r(
            name,
            Outcome.FAIL,
            "SCANNER_MISMATCH",
            f"Report was produced by {ev.scanner_name}, expected {expected}",
        )
    return _r(name, Outcome.PASS, "SCANNER_MATCHES", f"Report produced by {ev.scanner_name}")


def _min_components(ev: ScanEvidence, minimum: int) -> CheckResult:
    name = "minimum_components"
    count = ev.scope.components if ev.scope else None
    if count is None:
        return _r(name, Outcome.UNKNOWN, "COMPONENTS_UNKNOWN", "Report does not list components")
    if count < minimum:
        return _r(
            name,
            Outcome.FAIL,
            "SBOM_TOO_SMALL",
            f"{count} component(s) in SBOM, at least {minimum} required",
        )
    return _r(name, Outcome.PASS, "SBOM_COMPONENTS_OK", f"{count} component(s) in SBOM")


def _min_resources(ev: ScanEvidence, minimum: int) -> CheckResult:
    name = "minimum_resources"
    count = ev.scope.resources if ev.scope else None
    if count is None:
        return _r(name, Outcome.UNKNOWN, "RESOURCES_UNKNOWN", "Report does not state resources")
    if count < minimum:
        return _r(
            name,
            Outcome.FAIL,
            "TOO_FEW_RESOURCES",
            f"{count} resource(s) evaluated, at least {minimum} required",
        )
    return _r(name, Outcome.PASS, "RESOURCES_OK", f"{count} resource(s) evaluated")


def _how_it_was_masked(status: JobStatus, raw: str | None) -> str:
    """The platform's own account when it says more than the status (GitHub masked steps)."""
    if raw and raw != status.value:
        return raw
    return (
        f"ended '{status.value}', and allow_failure / continue-on-error let the pipeline continue"
    )


RequirementInput.model_rebuild()
