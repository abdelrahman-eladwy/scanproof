"""Assurance-weakening policy opt-ins and the `production` profile that rejects them.

Every item here is a *legal* v1alpha1 setting: the engine evaluates it exactly as documented.
Each one, though, lets a weaker pipeline reach VERIFIED (a failed scan job, a report from
another commit, a replayable signature, an unbounded waiver, ...). `assurance.profile:
production` turns them into load-time errors (exit 3); `scanproof validate --explain` lists
them for any profile. Both read the same list, so what is reported is what is rejected.

Pure: no I/O, no engine import. See issue #52 and docs/advanced-policy.md.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from scanproof.policy.models import Policy, Requirement

PRODUCTION = "production"
# Longest enforcement.max_waiver_days the production profile accepts. A policy choice, not a
# platform limit: long enough for a quarterly remediation cycle, short enough that a waiver
# must be re-approved.
PRODUCTION_MAX_WAIVER_DAYS = 90


@dataclass(frozen=True)
class OptIn:
    """One assurance-weakening setting (or documented limitation) found in a policy."""

    code: str
    location: str
    message: str
    # reject: a load error under `profile: production`. note: a limitation of the platform or
    # the policy language that no setting can remove; reported, never rejected.
    production: Literal["reject", "note"] = "reject"


def _req(req: Requirement) -> str:
    return f"requirements[{req.id}]"


def assurance_opt_ins(policy: Policy) -> list[OptIn]:
    """Every assurance-weakening opt-in in `policy`, in policy order."""
    out: list[OptIn] = []
    enf = policy.enforcement

    if enf.on_unknown == "warn":
        out.append(
            OptIn(
                "ON_UNKNOWN_WARN",
                "enforcement.on_unknown",
                "'warn' lets an INDETERMINATE result (evidence that cannot be proven) pass",
            )
        )
    if enf.on_nothing_applicable == "allow":
        out.append(
            OptIn(
                "NOTHING_APPLICABLE_ALLOW",
                "enforcement.on_nothing_applicable",
                "'allow' returns VERIFIED when applies_to excludes every requirement, "
                "i.e. when nothing was verified",
            )
        )

    for req in policy.requirements:
        out.extend(_requirement_opt_ins(policy, req))

    if policy.waivers and enf.max_waiver_days is None:
        out.append(
            OptIn(
                "WAIVER_UNBOUNDED",
                "enforcement.max_waiver_days",
                f"{len(policy.waivers)} waiver(s) with no max_waiver_days: 'expires' can be "
                "any date (e.g. 9999-12-31)",
            )
        )
    if enf.max_waiver_days is not None and enf.max_waiver_days > PRODUCTION_MAX_WAIVER_DAYS:
        out.append(
            OptIn(
                "WAIVER_LIMIT_TOO_LONG",
                "enforcement.max_waiver_days",
                f"{enf.max_waiver_days} days exceeds the production ceiling of "
                f"{PRODUCTION_MAX_WAIVER_DAYS}; a very large limit makes waivers effectively "
                "permanent",
            )
        )
    for i, w in enumerate(policy.waivers):
        if w.check == "job_present" or w.check.startswith("job_present ["):
            out.append(
                OptIn(
                    "WAIVER_REMOVES_REQUIREMENT",
                    f"waivers[{i}] ({w.requirement}/{w.check})",
                    "waiving job_present accepts a pipeline in which the required scan job "
                    "does not exist; remove or scope the requirement instead",
                )
            )
    return out


def _requirement_opt_ins(policy: Policy, req: Requirement) -> list[OptIn]:
    out: list[OptIn] = []
    c = req.checks
    where = _req(req)

    if not c.job_success:
        out.append(
            OptIn(
                "JOB_SUCCESS_DISABLED",
                f"{where}.checks.job_success",
                "a failed, cancelled or still-running scan job's report counts",
            )
        )
    if not c.same_commit:
        out.append(
            OptIn(
                "SAME_COMMIT_DISABLED",
                f"{where}.checks.same_commit",
                "evidence from a job that ran on another commit counts",
            )
        )
    if not c.report_required:
        dropped = c.evidence_checks()
        if dropped:
            out.append(
                OptIn(
                    "REPORT_OPTIONAL_DROPS_CHECKS",
                    f"{where}.checks.report_required",
                    "with no report the requirement records REPORT_OPTIONAL_ABSENT and these "
                    f"configured checks silently do not run: {', '.join(dropped)}",
                )
            )
        else:
            out.append(
                OptIn(
                    "REPORT_OPTIONAL",
                    f"{where}.checks.report_required",
                    "a missing report is accepted (REPORT_OPTIONAL_ABSENT)",
                )
            )

    nothing_checked = (
        not c.job_success
        and not c.same_commit
        and not c.report_required
        and policy.assurance.minimum_level != "reported_scope"
        and not c.evidence_checks()
        and c.max_age_hours is None
        and req.attestation is None
    )
    if nothing_checked:
        out.append(
            OptIn(
                "ALL_CHECKS_DISABLED",
                where,
                "every check is disabled: the outcome is NOT_APPLICABLE whatever the job did, "
                "so this requirement only notices a missing job and never blocks on its result",
            )
        )

    att = req.attestation
    if att is not None:
        if not att.same_commit:
            out.append(
                OptIn(
                    "ATTESTATION_SAME_COMMIT_DISABLED",
                    f"{where}.attestation.same_commit",
                    "a valid signature made for another commit is accepted (cross-commit replay)",
                )
            )
        if not att.same_run:
            out.append(
                OptIn(
                    "ATTESTATION_SAME_RUN_DISABLED",
                    f"{where}.attestation.same_run",
                    "a valid signature from another pipeline run is accepted (cross-run replay)",
                )
            )
        if att.signer.repository is None:
            out.append(
                OptIn(
                    "SIGNER_REPOSITORY_UNPINNED",
                    f"{where}.attestation.signer.repository",
                    "only the workflow regex pins the signer; a loose pattern (e.g. '.*') "
                    "accepts any repository under the issuer. Pin repository as well",
                )
            )
        if policy.project.provider == "gitlab" and att.same_run:
            out.append(
                OptIn(
                    "GITLAB_SAME_RUN_IS_PIPELINE_WIDE",
                    f"{where}.attestation.same_run",
                    "GitLab's Fulcio identity names the pipeline, not the job: any job of the "
                    "verified pipeline can produce an accepted signature. Protect who can edit "
                    "the pipeline (docs/attestations.md)",
                    production="note",
                )
            )
    return out


def production_violations(policy: Policy) -> list[OptIn]:
    """The opt-ins that make `policy` invalid under `assurance.profile: production`."""
    return [o for o in assurance_opt_ins(policy) if o.production == "reject"]
