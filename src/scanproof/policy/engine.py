"""Policy evaluation. Pure functions: no I/O, no CI provider or scanner-format knowledge.

Inputs are the inspected pipeline and, per requirement, the job (if present) and the
normalized evidence (or the reason it could not be obtained). Output is a decision with
a machine-readable code and a human message for every check.
"""

from __future__ import annotations

import re
from datetime import UTC, date, datetime
from enum import StrEnum
from fnmatch import fnmatchcase
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from scanproof.attestation.models import AttestationEvidence, AttestationStatus
from scanproof.evidence.models import ScanEvidence
from scanproof.models import InspectedJob, Job, JobStatus, Pipeline
from scanproof.policy.models import (
    AttestationRequirement,
    Policy,
    Requirement,
    normalize_scan_path,
)

_WARNING_LEVELS = {"warn", "warning", "info"}


class Outcome(StrEnum):
    PASS = "PASS"  # noqa: S105 - outcome name, not a password
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    WAIVED = "WAIVED"  # failed or unknown, but covered by an unexpired waiver in the policy


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
    declared_instance: str | None = Field(
        default=None,
        description="This missing instance is a label the requirement declares in `instances`",
    )
    undeclared_instances: list[str] | None = Field(
        default=None,
        description="Matrix legs matched while the requirement declares no `instances`: a "
        "removed leg would go unnoticed (#60)",
    )
    missing_copy: str | None = Field(
        default=None,
        description="This missing instance is a path the requirement declares in `copies`",
    )
    undeclared_copies: list[str] | None = Field(
        default=None,
        description="Prefixed copies matched while the requirement declares no `copies`: a "
        "removed copy would go unnoticed (#65)",
    )
    copies_unbounded: str | None = Field(
        default=None,
        description="The job was found, but pipelines that could not be read may hold more "
        "copies of it, and the requirement declares no `copies` (#71)",
    )
    attestations: list[AttestationEvidence] | None = Field(
        default=None, description="Every bundle found for the attestation subject"
    )
    attestation_error: str | None = Field(
        default=None, description="Why attestations could not be fetched (auth, network...)"
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


def evaluate(
    policy: Policy,
    pipeline: Pipeline,
    inputs: dict[str, RequirementInput],
    now: datetime | None = None,
) -> Evaluation:
    """`now` is injected (the engine does no I/O and reads no clock of its own when given one);
    it decides scan freshness and waiver expiry."""
    now = now or datetime.now(UTC)
    results = [
        evaluate_requirement(
            req,
            pipeline,
            inputs.get(req.id, RequirementInput()),
            now=now,
            minimum_assurance=policy.assurance.minimum_level,
            profile=policy.assurance.profile,
        )
        for req in policy.requirements
    ]
    _cross_requirement_checks(policy, inputs, results)
    warnings: list[str] = _apply_waivers(policy, results, now.date())
    warnings += _undeclared_instance_warnings(policy, inputs, results)
    warnings += _undeclared_copy_warnings(policy, inputs, results)
    outcomes = [r.outcome for r in results]

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
    req: Requirement,
    pipeline: Pipeline,
    data: RequirementInput,
    *,
    now: datetime | None = None,
    minimum_assurance: str = "report",
    profile: str = "compatible",
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
        ref = (pipeline.ref or "").strip()
        if not ref and not any(fnmatchcase("", pattern) for pattern in req.applies_to.refs):
            # Unknown is never pass: without a ref we cannot show the requirement is out of
            # scope, and treating it as NOT_APPLICABLE would let the other requirements pass.
            return result(
                [
                    CheckResult(
                        check="applies_to",
                        outcome=Outcome.UNKNOWN,
                        code="REF_UNKNOWN",
                        message=(
                            f"Pipeline {pipeline.id} reports no ref; cannot tell whether "
                            f"{req.applies_to.refs} applies"
                        ),
                    )
                ]
            )
        if ref and not any(fnmatchcase(ref, pattern) for pattern in req.applies_to.refs):
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

    declaration = [
        *_instance_declaration_checks(req, data, profile),
        *_copy_declaration_checks(req, data, profile),
    ]
    if data.instances:
        combined = _evaluate_instances(
            req, pipeline, data.instances, now, minimum_assurance=minimum_assurance
        )
        checks = [*combined.checks, *declaration]
        return combined.model_copy(
            update={"checks": checks, "outcome": combine([c.outcome for c in checks])}
        )

    if data.job is None and data.missing_copy is not None:
        where = f"'{data.missing_copy}'" if data.missing_copy else "the pipeline itself"
        if data.absence_unknown:
            return result(
                [
                    CheckResult(
                        check="job_present",
                        outcome=Outcome.UNKNOWN,
                        code="JOB_MAYBE_IN_UNREADABLE_PIPELINE",
                        message=(
                            f"Declared copy {where} of '{req.job_name}' was not found, but "
                            f"{data.absence_unknown}"
                        ),
                    )
                ]
            )
        return result(
            [
                CheckResult(
                    check="job_present",
                    outcome=Outcome.FAIL,
                    code="REQUIRED_COPY_ABSENT",
                    message=(
                        f"Declared copy {where} of '{req.job_name}' has no job in pipeline "
                        f"{pipeline.id}. The downstream pipeline, calling workflow or stage may "
                        "have been removed or excluded by rules."
                    ),
                )
            ]
        )

    if data.job is None and data.declared_instance:
        return result(
            [
                CheckResult(
                    check="job_present",
                    outcome=Outcome.FAIL,
                    code="REQUIRED_INSTANCE_ABSENT",
                    message=(
                        f"Declared instance '{data.declared_instance}' of '{req.job_name}' has "
                        f"no job in pipeline {pipeline.id}. The matrix leg may have been "
                        "removed or excluded by rules."
                    ),
                )
            ]
        )

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

    checks = [
        *_job_checks(req, data.job),
        *_freshness_checks(req, data.job, now),
        *_evidence_checks(req, data, minimum_assurance=minimum_assurance),
        *_attestation_checks(req, pipeline, data),
        *declaration,
    ]
    return result(checks)


def _instance_declaration_checks(
    req: Requirement, data: RequirementInput, profile: str
) -> list[CheckResult]:
    """Under `assurance.profile: production`, matrix legs need a declared `instances` set.

    Matrix job names carry no total, so without the declaration a removed leg is invisible
    and the remaining legs would pass (#60). Whether a job runs as a matrix is only known
    from the pipeline, so this is checked here rather than when the policy is loaded.
    """
    if profile != "production" or req.instances or not data.undeclared_instances:
        return []
    legs = ", ".join(f"'{n}'" for n in data.undeclared_instances)
    return [
        CheckResult(
            check="instances_declared",
            outcome=Outcome.UNKNOWN,
            code="INSTANCES_UNDECLARED",
            message=(
                f"'{req.job_name}' ran as matrix legs ({legs}) but the requirement declares no "
                "`instances`, so a removed leg cannot be detected. assurance.profile: "
                "production requires the declaration, e.g. instances: [py, js]"
            ),
        )
    ]


def _copy_declaration_checks(
    req: Requirement, data: RequirementInput, profile: str
) -> list[CheckResult]:
    """Under `assurance.profile: production`, prefixed copies need a declared `copies` set.

    Copies told apart only by a prefix ('svc-a > sast', 'api / sast') carry no total, so
    without the declaration a removed copy is invisible and the rest would pass (#65).
    """
    if profile != "production" or req.copies:
        return []
    if not data.undeclared_copies:
        if not data.copies_unbounded:
            return []
        return [
            CheckResult(
                check="copies_bounded",
                outcome=Outcome.UNKNOWN,
                code="COPIES_UNBOUNDED",
                message=(
                    f"'{req.job_name}' was found, but {data.copies_unbounded}, and they may hold "
                    "more copies of it that must also pass. assurance.profile: production "
                    'requires declaring the copies that must run: copies: [""] for only this '
                    'pipeline\'s own job, or e.g. copies: ["", svc-a]'
                ),
            )
        ]
    names = ", ".join(f"'{n}'" for n in data.undeclared_copies)
    return [
        CheckResult(
            check="copies_declared",
            outcome=Outcome.UNKNOWN,
            code="COPIES_UNDECLARED",
            message=(
                f"'{req.job_name}' ran as prefixed copies ({names}) but the requirement declares "
                "no `copies`, so a removed copy cannot be detected. assurance.profile: "
                "production requires the declaration, e.g. copies: [svc-a, svc-b] "
                '("" for the unprefixed job)'
            ),
        )
    ]


def _undeclared_copy_warnings(
    policy: Policy, inputs: dict[str, RequirementInput], results: list[RequirementResult]
) -> list[str]:
    """Compatible profile: say, without changing the decision, that a removed copy is unseen."""
    if policy.assurance.profile == "production":
        return []  # a COPIES_UNDECLARED check already reports it
    out = []
    for req, res in zip(policy.requirements, results, strict=True):
        data = inputs.get(req.id, RequirementInput())
        names = data.undeclared_copies
        if (
            data.copies_unbounded
            and not names
            and not req.copies
            and res.outcome is not Outcome.NOT_APPLICABLE
        ):
            out.append(
                f"{req.id}: '{req.job_name}' may have copies in pipelines that could not be read "
                'and were not judged. Declare the required copies (copies: [...]; "" for this '
                "pipeline's own job) to make that explicit."
            )
        if names and not req.copies and res.outcome is not Outcome.NOT_APPLICABLE:
            out.append(
                f"{req.id}: '{req.job_name}' ran as {len(names)} prefixed cop(ies) and declares "
                "no `copies`; a removed downstream pipeline, caller or stage would not be "
                "detected. Declare the required paths (copies: [...]) to fail on a missing copy."
            )
    return out


def _undeclared_instance_warnings(
    policy: Policy, inputs: dict[str, RequirementInput], results: list[RequirementResult]
) -> list[str]:
    """Compatible profile: say, without changing the decision, that a removed leg is unseen."""
    if policy.assurance.profile == "production":
        return []  # an INSTANCES_UNDECLARED check already reports it
    out = []
    for req, res in zip(policy.requirements, results, strict=True):
        legs = inputs.get(req.id, RequirementInput()).undeclared_instances
        if legs and not req.instances and res.outcome is not Outcome.NOT_APPLICABLE:
            out.append(
                f"{req.id}: '{req.job_name}' ran as {len(legs)} matrix leg(s) and declares no "
                "`instances`; a removed leg would not be detected. Declare the required "
                "labels (instances: [...]) to fail on a missing leg."
            )
    return out


def _evaluate_instances(
    req: Requirement,
    pipeline: Pipeline,
    instances: list[tuple[str, RequirementInput]],
    now: datetime | None = None,
    *,
    minimum_assurance: str = "report",
) -> RequirementResult:
    """Evaluate every instance as its own job; the requirement holds only if all of them do."""
    single = req.model_copy(update={"applies_to": None})
    checks: list[CheckResult] = []
    findings: dict[str, int] = {}
    for name, data in instances:
        sub = evaluate_requirement(
            single,
            pipeline,
            data.model_copy(update={"instances": None}),
            now=now,
            minimum_assurance=minimum_assurance,
        )
        if data.job is None and not data.declared_instance and data.missing_copy is None:
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


def _masking_unknown_cause(job: Job) -> str:
    """Why a continue-on-error step could not be ruled out, with the matching remedy.

    The outcome is UNKNOWN either way; only the diagnosis differs (#117). A connector
    that refused the evidence for a specific reason records it in ``raw_status``;
    otherwise the annotations were unreadable.
    """
    if job.raw_status and job.raw_status not in ("success", JobStatus.SUCCESS.value):
        return (
            f"a step hidden by continue-on-error cannot be ruled out: {job.raw_status} "
            "(re-run all jobs, not only the gate)"
        )
    return (
        "its check-run annotations could not be read to rule out a step hidden by "
        "continue-on-error (grant checks:read, or retry if the API was unavailable)"
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
                    f"Job {latest.id} reports success, but {_masking_unknown_cause(latest)}",
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


def _evidence_checks(
    req: Requirement, data: RequirementInput, *, minimum_assurance: str = "report"
) -> list[CheckResult]:
    c = req.checks
    wants_evidence = (
        c.report_required or minimum_assurance == "reported_scope" or bool(c.evidence_checks())
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

    if minimum_assurance == "reported_scope":
        out.append(_reported_scope(ev))
    if c.scanner_errors_allowed is not None:
        out.append(_scanner_errors(ev, c.scanner_errors_allowed, c.ignore_scanner_warnings))
    if c.minimum_scanned_files is not None:
        out.append(_min_files(ev, c.minimum_scanned_files))
    if c.suppressed_findings_allowed is not None:
        out.append(_suppressed(ev, c.suppressed_findings_allowed))
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
    if c.target_url_must_match:
        out.append(_target_url(ev, c.target_url_must_match))
    if c.minimum_endpoints is not None:
        out.append(_min_endpoints(ev, c.minimum_endpoints))
    return out


# ---------------------------------------------------------------- individual checks


def _reported_scope(ev: ScanEvidence) -> CheckResult:
    """Require nonempty *scanner-reported* scan scope, not merely well-formed JSON.

    This evaluates claims in the report, not independently attested execution.
    Empty, missing, or internally inconsistent scopes cannot satisfy a release
    policy that explicitly opts into this assurance level.
    """
    name = "reported_scope"
    if ev.results_reported is False:
        return _r(
            name,
            Outcome.FAIL,
            "SCAN_RESULTS_MISSING",
            "Scanner report has no results section; scan coverage is not demonstrated",
        )

    scope = ev.scope
    if scope is None:
        return _r(
            name,
            Outcome.UNKNOWN,
            "SCAN_SCOPE_UNKNOWN",
            "Scanner report does not identify examined files, targets or resources",
        )

    counters = {
        "files": scope.files_scanned,
        "components": scope.components,
        "resources": scope.resources,
        "endpoints": scope.endpoints,
    }
    reported_counts = [value for value in counters.values() if value is not None]
    # Strings such as 'None' must not count as a scanned target.
    paths = scope.scanned_paths
    valid_paths = (
        [p for p in paths if isinstance(p, str) and p.strip() and p.strip().lower() != "none"]
        if paths is not None
        else None
    )
    if paths is not None and len(valid_paths or []) != len(paths):
        return _r(
            name,
            Outcome.FAIL,
            "SCAN_SCOPE_INVALID",
            "Scanner lists an empty or invalid scanned target",
        )
    if reported_counts and any(count < 0 for count in reported_counts):
        return _r(name, Outcome.FAIL, "SCAN_SCOPE_INVALID", "Negative scan scope count")
    if reported_counts and any(count == 0 for count in reported_counts):
        if any(count > 0 for count in reported_counts) or valid_paths:
            return _r(
                name,
                Outcome.UNKNOWN,
                "SCAN_SCOPE_CONFLICT",
                "Scanner-reported scope counts conflict (zero and nonzero)",
            )
        return _r(name, Outcome.FAIL, "SCAN_SCOPE_EMPTY", "Scanner reported no scanned targets")
    if paths is not None and not valid_paths:
        if reported_counts:
            return _r(
                name,
                Outcome.UNKNOWN,
                "SCAN_SCOPE_CONFLICT",
                "Scanner reports positive counts but no scanned paths",
            )
        return _r(name, Outcome.FAIL, "SCAN_SCOPE_EMPTY", "Scanner reported no scanned targets")
    if reported_counts or valid_paths:
        return _r(
            name,
            Outcome.PASS,
            "REPORTED_SCOPE_PRESENT",
            "Scanner report claims nonempty examined scope (not independently verified)",
        )
    return _r(
        name,
        Outcome.UNKNOWN,
        "SCAN_SCOPE_UNKNOWN",
        "Scanner report does not provide verifiable scan scope metadata",
    )


def _origin_and_path(url: str) -> tuple[tuple[str, str, int], str] | None:
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        return None
    path = parts.path.rstrip("/") or ""
    return (parts.scheme, parts.hostname.lower(), port), path


def _min_endpoints(ev: ScanEvidence, minimum: int) -> CheckResult:
    found = ev.scope.endpoints if ev.scope else None
    if found is None:
        return _r(
            "minimum_endpoints",
            Outcome.UNKNOWN,
            "COVERAGE_UNKNOWN",
            "The report does not say how many endpoints were tested",
        )
    if found < minimum:
        return _r(
            "minimum_endpoints",
            Outcome.FAIL,
            "COVERAGE_TOO_SMALL",
            f"{found} endpoints tested, policy requires at least {minimum}",
        )
    return _r("minimum_endpoints", Outcome.PASS, "COVERAGE_OK", f"{found} endpoints tested")


def _target_url(ev: ScanEvidence, expected: str) -> CheckResult:
    """The DAST scan must have targeted the deployment: same origin, path inside expected."""
    urls = ev.target.urls if ev.target else None
    if not urls:
        return _r(
            "target_url",
            Outcome.UNKNOWN,
            "TARGET_UNKNOWN",
            "The report does not say which URL was scanned",
        )
    want = _origin_and_path(expected)
    if want is None:  # validated at load time; defensive
        return _r("target_url", Outcome.UNKNOWN, "TARGET_UNKNOWN", f"Bad expected URL {expected}")
    for url in urls:
        got = _origin_and_path(url)
        if got and got[0] == want[0] and (got[1] + "/").startswith(want[1] + "/"):
            return _r("target_url", Outcome.PASS, "TARGET_MATCHES", f"Scanned {url}")
    shown = ", ".join(urls[:5])
    return _r("target_url", Outcome.FAIL, "TARGET_MISMATCH", f"Scanned {shown}, not {expected}")


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


def _suppressed(ev: ScanEvidence, allowed: int) -> CheckResult:
    """Cap findings the scanned code or its config told the scanner to hide (#123)."""
    name = "suppressed_findings_allowed"
    count = ev.findings.suppressed if ev.findings else None
    if count is None:
        return _r(
            name,
            Outcome.UNKNOWN,
            "SUPPRESSIONS_UNKNOWN",
            f"{ev.tool} report does not state how many findings were suppressed",
        )
    if count > allowed:
        return _r(
            name,
            Outcome.FAIL,
            "SUPPRESSED_FINDINGS_EXCEEDED",
            f"{count} finding(s) suppressed, at most {allowed} allowed",
        )
    return _r(name, Outcome.PASS, "SUPPRESSIONS_OK", f"{count} finding(s) suppressed")


def _covers(required: str, scanned: str) -> bool:
    """`scanned` is the required file or directory, or lies inside it (whole path segments)."""
    return scanned == required or scanned.startswith(required + "/")


def _required_paths(ev: ScanEvidence, prefixes: list[str]) -> CheckResult:
    name = "required_paths"
    scanned = ev.scope.scanned_paths if ev.scope else None
    if scanned is None:
        return _r(name, Outcome.UNKNOWN, "SCOPE_UNKNOWN", "Report does not list scanned paths")
    # Empty, absolute or root-escaping paths (/repo/x, C:\x, src/../../x) prove nothing.
    normalized = [n for p in scanned if isinstance(p, str) and (n := normalize_scan_path(p))]
    missing = []
    for prefix in prefixes:
        want = normalize_scan_path(prefix)
        if want is None or not any(_covers(want, s) for s in normalized):
            missing.append(prefix)
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


# ---------------------------------------------------------------- freshness, cross checks, waivers


def _freshness_checks(
    req: Requirement, job: InspectedJob, now: datetime | None
) -> list[CheckResult]:
    limit = req.checks.max_age_hours
    if limit is None:
        return []
    finished = job.latest.finished_at
    if finished is None:
        return [
            _r(
                "max_age",
                Outcome.UNKNOWN,
                "SCAN_AGE_UNKNOWN",
                f"Job {job.latest.id} has no finish time; cannot tell how old the scan is",
            )
        ]
    if finished.tzinfo is None:
        finished = finished.replace(tzinfo=UTC)
    age_seconds = ((now or datetime.now(UTC)) - finished).total_seconds()
    # Provider clocks can differ slightly. Larger future offsets are not proof
    # of freshness and must never silently satisfy a release-gating check.
    allowed_clock_skew_seconds = 5 * 60
    if age_seconds < -allowed_clock_skew_seconds:
        return [
            _r(
                "max_age",
                Outcome.UNKNOWN,
                "SCAN_TIMESTAMP_IN_FUTURE",
                f"Scan finish time {finished.isoformat()} is "
                f"{-age_seconds / 60:.1f} min in the future (tolerance: 5 min)",
            )
        ]
    if age_seconds < 0:
        return [
            _r(
                "max_age",
                Outcome.PASS,
                "SCAN_FRESH",
                f"Scan finish time is {-age_seconds / 60:.1f} min ahead "
                "of verification time, within the 5 min clock-skew tolerance",
            )
        ]
    age = age_seconds / 3600
    if age > limit:
        return [
            _r(
                "max_age",
                Outcome.FAIL,
                "SCAN_TOO_OLD",
                f"Scan finished {age:.1f} h ago ({finished.isoformat()}); policy allows {limit} h",
            )
        ]
    return [_r("max_age", Outcome.PASS, "SCAN_FRESH", f"Scan finished {age:.1f} h ago")]


def _target_keys(ev: ScanEvidence | None) -> set[str]:
    if ev is None or ev.target is None:
        return set()
    keys = set(ev.target.digests())
    if ev.target.image_id:
        keys.add(ev.target.image_id)
    for url in ev.target.urls or []:
        got = _origin_and_path(url)
        if got:
            keys.add("{}://{}:{}".format(*got[0]))
    return keys


def _cross_requirement_checks(
    policy: Policy, inputs: dict[str, RequirementInput], results: list[RequirementResult]
) -> None:
    """same_target_as: two requirements' scans must be about one image (or one DAST origin)."""
    by_id = {r.id: r for r in results}
    for req in policy.requirements:
        other = req.checks.same_target_as
        res = by_id[req.id]
        if other is None or res.outcome is Outcome.NOT_APPLICABLE:
            continue
        mine, theirs = inputs.get(req.id), inputs.get(other)
        if (mine and mine.instances) or (theirs and theirs.instances):
            check = _r(
                "same_target",
                Outcome.UNKNOWN,
                "TARGET_UNKNOWN",
                "same_target_as is not supported for parallel / matrix requirements",
            )
        else:
            a = _target_keys(mine.evidence if mine else None)
            b = _target_keys(theirs.evidence if theirs else None)
            if not a or not b:
                check = _r(
                    "same_target",
                    Outcome.UNKNOWN,
                    "TARGET_UNKNOWN",
                    f"Cannot compare targets with {other}: one of the reports names no target",
                )
            elif a & b:
                shared = sorted(a & b)[0]
                check = _r("same_target", Outcome.PASS, "SAME_TARGET", f"Same as {other}: {shared}")
            else:
                check = _r(
                    "same_target",
                    Outcome.FAIL,
                    "TARGET_DIFFERS",
                    f"Scanned {', '.join(sorted(a)[:3])}; "
                    f"{other} scanned {', '.join(sorted(b)[:3])}",
                )
        res.checks.append(check)
        res.outcome = combine([c.outcome for c in res.checks])


def _apply_waivers(policy: Policy, results: list[RequirementResult], today: date) -> list[str]:
    warnings: list[str] = []
    used: set[int] = set()
    by_id = {r.id: r for r in results}
    for i, w in enumerate(policy.waivers):
        res = by_id.get(w.requirement)
        if res is None:
            continue
        matched = False
        for n, check in enumerate(res.checks):
            if check.outcome not in (Outcome.FAIL, Outcome.UNKNOWN):
                continue
            if not (check.check == w.check or check.check.startswith(f"{w.check} [")):
                continue
            if w.code is not None and check.code != w.code:
                continue
            matched = True
            if w.expires < today:
                continue
            if w.created is not None and w.created > today:
                continue
            res.checks[n] = check.model_copy(
                update={
                    "outcome": Outcome.WAIVED,
                    "message": f"{check.message} [waived until {w.expires} by {w.approved_by}: "
                    f"{w.reason}]",
                }
            )
            used.add(i)
        label = f"{w.requirement}/{w.check}" + (f" ({w.code})" if w.code else "")
        if matched and w.expires < today:
            warnings.append(f"Waiver {label} expired on {w.expires}; not applied.")
        elif matched and w.created is not None and w.created > today:
            warnings.append(f"Waiver {label} starts on {w.created}; not applied yet.")
        elif not matched:
            warnings.append(f"Waiver {label} matched nothing; remove it if the risk is gone.")
        if i in used:
            warnings.append(f"Waiver {label} applied (expires {w.expires}, by {w.approved_by}).")
        res.outcome = combine([c.outcome for c in res.checks])
    return warnings


# ---------------------------------------------------------------- attestations


def _attestation_checks(
    req: Requirement, pipeline: Pipeline, data: RequirementInput
) -> list[CheckResult]:
    """A signed attestation must bind the report (or image) to an accepted signer.

    Several bundles may exist for one subject (re-runs, other workflows); one acceptable
    bundle is enough. Claims come from bundles the attestation module already verified.
    """
    spec = req.attestation
    if spec is None:
        return []
    if data.attestation_error is not None:
        return [
            _r("attestation", Outcome.UNKNOWN, "ATTESTATION_UNAVAILABLE", data.attestation_error)
        ]
    if spec.subject == "image":
        expected = (req.checks.image_digest_must_match or "").removeprefix("sha256:")
        what = f"image sha256:{expected}"
    else:
        ev = data.evidence
        expected = ev.report_sha256 if ev and ev.present else None
        what = f"{req.report_path} (sha256:{expected})"
    if not expected:
        return [
            _r(
                "attestation",
                Outcome.UNKNOWN,
                "ATTESTATION_NO_SUBJECT",
                f"No report bytes to bind an attestation to ({req.report_path})",
            )
        ]
    if data.attestations is None:
        return [
            _r(
                "attestation",
                Outcome.UNKNOWN,
                "ATTESTATION_NOT_CHECKED",
                f"Attestations for {what} were not looked up",
            )
        ]
    bundles = data.attestations
    if not bundles:
        return [
            _r("attestation", Outcome.FAIL, "ATTESTATION_MISSING", f"No attestation for {what}")
        ]
    judged = [_judge_attestation(spec, pipeline, att, expected.lower()) for att in bundles]
    for res in judged:
        if res.outcome is Outcome.PASS:
            extra = f" (1 of {len(judged)} bundles)" if len(judged) > 1 else ""
            return [res.model_copy(update={"message": res.message + extra})]
    outcome = Outcome.FAIL if any(r.outcome is Outcome.FAIL for r in judged) else Outcome.UNKNOWN
    first = next(r for r in judged if r.outcome is outcome)
    if len(judged) == 1:
        return [first]
    detail = "; ".join(f"[{i + 1}] {r.code}: {r.message}" for i, r in enumerate(judged[:5]))
    more = f" (+{len(judged) - 5} more)" if len(judged) > 5 else ""
    return [
        _r(
            "attestation",
            outcome,
            first.code,
            f"None of {len(judged)} bundles for {what} is acceptable: {detail}{more}",
        )
    ]


def _judge_attestation(
    spec: AttestationRequirement, pipeline: Pipeline, att: AttestationEvidence, expected: str
) -> CheckResult:
    def bad(code: str, message: str, outcome: Outcome = Outcome.FAIL) -> CheckResult:
        return _r("attestation", outcome, code, message)

    if att.status is AttestationStatus.UNVERIFIABLE:
        return bad("ATTESTATION_UNVERIFIABLE", att.reason or "cannot verify", Outcome.UNKNOWN)
    if att.status is not AttestationStatus.VERIFIED or att.signer is None:
        return bad("ATTESTATION_INVALID", att.reason or "bundle did not verify")
    if expected not in att.subject_digests():
        got = ", ".join(sorted(att.subject_digests())) or "none"
        return bad("ATTESTATION_SUBJECT_MISMATCH", f"Attests sha256 {got}, not {expected}")
    if att.predicate_type != spec.predicate_type:
        return bad(
            "ATTESTATION_PREDICATE_MISMATCH",
            f"Predicate is {att.predicate_type}, policy wants {spec.predicate_type}",
        )

    s, want = att.signer, spec.signer
    if s.issuer != want.issuer:
        return bad("ATTESTATION_SIGNER_MISMATCH", f"Issuer is {s.issuer}, not {want.issuer}")
    if want.repository:
        if s.source_repository_uri is None:
            return bad(
                "ATTESTATION_CLAIM_MISSING",
                "Certificate has no source repository claim",
                Outcome.UNKNOWN,
            )
        if s.source_repository_uri.rstrip("/").lower() != want.repository.rstrip("/").lower():
            return bad(
                "ATTESTATION_SIGNER_MISMATCH",
                f"Signed from repository {s.source_repository_uri}, not {want.repository}",
            )
    if want.workflow:
        if s.build_signer_uri is None:
            return bad(
                "ATTESTATION_CLAIM_MISSING", "Certificate has no Build Signer URI", Outcome.UNKNOWN
            )
        if not re.fullmatch(want.workflow, s.build_signer_uri):
            return bad(
                "ATTESTATION_SIGNER_MISMATCH",
                f"Signed by {s.build_signer_uri}, which does not match {want.workflow!r}",
            )
    if spec.same_commit:
        if s.source_repository_digest is None:
            return bad(
                "ATTESTATION_CLAIM_MISSING",
                "Certificate has no source commit claim",
                Outcome.UNKNOWN,
            )
        if s.source_repository_digest.lower() != (pipeline.sha or "").lower():
            return bad(
                "ATTESTATION_WRONG_COMMIT",
                f"Signed at commit {s.source_repository_digest}, pipeline is {pipeline.sha}",
            )
    if spec.same_run:
        if att.run_matches is None:
            return bad(
                "ATTESTATION_RUN_UNKNOWN",
                f"Cannot tell whether {s.run_invocation_uri} is pipeline {pipeline.id}",
                Outcome.UNKNOWN,
            )
        if not att.run_matches:
            return bad(
                "ATTESTATION_WRONG_RUN",
                f"Signed in {s.run_invocation_uri}, not in pipeline {pipeline.id}",
            )
    return _r(
        "attestation",
        Outcome.PASS,
        "ATTESTATION_VERIFIED",
        f"{att.predicate_type} for sha256:{expected[:12]}... signed by "
        f"{s.build_signer_uri or s.san} ({s.issuer})",
    )


def _how_it_was_masked(status: JobStatus, raw: str | None) -> str:
    """The platform's own account when it says more than the status (GitHub masked steps)."""
    if raw and raw != status.value:
        return raw
    return (
        f"ended '{status.value}', and allow_failure / continue-on-error let the pipeline continue"
    )


RequirementInput.model_rebuild()
