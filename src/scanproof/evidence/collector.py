"""Fetch a job's report from the CI platform and turn it into ScanEvidence.

Missing evidence (job uploaded no artifacts, file not in the archive) is a *fact*
and comes back as `present=False`. Inability to look (auth, network, server) raises
ConnectorError so callers can treat it as UNKNOWN rather than as a missing report.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from scanproof.connectors.base import (
    AuthError,
    CIConnector,
    ConnectorError,
    ErrorKind,
    NotFoundError,
)
from scanproof.evidence.models import EvidenceSource, ScanEvidence
from scanproof.models import InspectedJob, Pipeline, normalize_instance_label
from scanproof.scanners.base import ScannerAdapter


def collect_evidence(
    connector: CIConnector,
    *,
    project: str,
    pipeline: Pipeline,
    job: InspectedJob,
    report_path: str,
    adapter: ScannerAdapter,
    artifact_name: str | None = None,
) -> ScanEvidence:
    # A downstream job's artifacts belong to its own project/pipeline, not to the
    # parent pipeline passed to verify_pipeline(). The job metadata was populated
    # while walking the downstream graph in inspect_pipeline().
    source_project = job.latest.project or project
    source_pipeline_id = (
        job.latest.pipeline_id if job.latest.pipeline_id is not None else pipeline.id
    )
    source_sha = job.latest.commit_sha if job.latest.project else pipeline.sha
    source = EvidenceSource(
        provider=connector.provider,
        project=source_project,
        pipeline_id=source_pipeline_id,
        pipeline_sha=source_sha,
        job_id=job.latest.id,
        job_name=job.name,
        job_commit_sha=job.latest.commit_sha,
        artifact_path=report_path,
    )

    try:
        raw = connector.fetch_report(source_project, job.latest, report_path, artifact_name)
    except NotFoundError as exc:
        evidence = adapter.parse(None)
        evidence.parse_error = exc.message
    except AuthError as exc:
        # GitLab 17+ restricts security-scan artifacts (artifacts:access) to Developer+.
        raise AuthError(
            f"{exc.message} Report artifacts may be restricted with artifacts:access; "
            "security scan templates need a Developer-role token.",
            exc.status_code,
        ) from None
    except ConnectorError as exc:
        if exc.kind is not ErrorKind.INTEGRITY:
            raise
        # The platform recorded a digest and the bytes don't match: tampered or corrupt.
        evidence = adapter.parse(b"")
        evidence.parse_error = exc.message
    else:
        evidence = adapter.parse(raw)

    evidence.source = source
    return evidence


def find_job(jobs: list[InspectedJob], name: str) -> InspectedJob | None:
    return next((j for j in jobs if j.name == name), None)


_PARALLEL = re.compile(r"^(?P<base>.+) (?P<index>\d+)/(?P<total>\d+)$")
# Bound only diagnostic enumeration, NEVER the check that all advertised legs exist.
_MAX_PARALLEL_ENUMERATE = 1000
# Avoid unbounded decimal conversion (Python raises for >4300 digits); malformed API job
# names must fail closed rather than raising or silently bypassing missing-leg checks.
_MAX_PARALLEL_DIGITS = 12
_TAIL_SEPARATORS = (" > ", " / ")  # ScanProof downstream prefix; GitHub reusable workflows


def _tail(job_name: str) -> tuple[str, str]:
    """Split 'trigger > child' / 'caller / callee' into (prefix, last segment)."""
    cut = max(job_name.rfind(sep) + len(sep) if sep in job_name else 0 for sep in _TAIL_SEPARATORS)
    return job_name[:cut], job_name[cut:]


def _matrix_label(tail: str, name: str) -> tuple[str, str] | None:
    """(style, label) if `tail` is a matrix leg of `name`: GitLab 'name: [label]' or GitHub
    'name (label)'. Unlike 'name i/N', these names carry no total."""
    if tail.startswith(f"{name}: [") and tail.endswith("]"):
        return "gitlab", tail[len(name) + 3 : -1]
    if tail.startswith(f"{name} (") and tail.endswith(")"):
        return "github", tail[len(name) + 2 : -1]
    return None


def _is_instance(tail: str, name: str) -> bool:
    if tail == name:
        return True
    m = _PARALLEL.match(tail)
    if m and m.group("base") == name:
        return True
    return _matrix_label(tail, name) is not None


def _leg_name(prefix: str, name: str, label: str, style: str | None) -> str:
    if style == "gitlab":
        return f"{prefix}{name}: [{label}]"
    if style == "github":
        return f"{prefix}{name} ({label})"
    return f"{prefix}{name} [{label}]"  # no leg of the matrix ran at all: style unknown


@dataclass
class JobMatch:
    """What a requirement's job_name covers in an inspected pipeline (see match_jobs)."""

    jobs: list[InspectedJob] = field(default_factory=list)
    # 'name i/N' indices absent although other legs report the total N.
    missing: list[str] = field(default_factory=list)
    # (job name the leg would have, label): declared `instances` with no matching leg.
    missing_declared: list[tuple[str, str]] = field(default_factory=list)
    # Matrix legs matched while the requirement declares no `instances`: their set has no
    # known size, so a removed leg cannot be detected (#60).
    undeclared_legs: list[str] = field(default_factory=list)
    # (job name the copy would have, copy path): declared `copies` with no matching job.
    missing_copies: list[tuple[str, str]] = field(default_factory=list)
    # Prefixed copies matched while the requirement declares no `copies`: their set has no
    # known size, so a removed copy cannot be detected (#65).
    undeclared_copies: list[str] = field(default_factory=list)


def find_jobs(jobs: list[InspectedJob], name: str) -> tuple[list[InspectedJob], list[str]]:
    """All jobs a requirement's job_name covers, and missing 'name i/N' instances.

    Kept for callers that only need the jobs; see match_jobs.
    """
    match = match_jobs(jobs, name)
    return match.jobs, match.missing


def is_qualified(name: str) -> bool:
    """A path-qualified job_name covers only that exact prefix and its job instances.

    It never matches copies in another child/caller, even if they share the final job
    name. The qualifier replaces a broad copies declaration (#62, #71).
    """
    return any(sep in name for sep in _TAIL_SEPARATORS)


def _copy_path(job_name: str, name: str) -> str:
    """The path that qualifies a matched job: '' for the named job itself, 'svc-a' for
    'svc-a > sast', 'Scan / Matrix - X / sast' -> 'Scan / Matrix - X'."""
    if job_name == name:
        return ""
    prefix = _tail(job_name)[0]
    for sep in _TAIL_SEPARATORS:
        if prefix.endswith(sep):
            return prefix[: -len(sep)]
    return prefix  # pragma: no cover - a prefix always ends with a separator


def _copy_name(path: str, name: str, matches: list[InspectedJob]) -> str:
    """The job name a missing copy would have, using the separator the other copies use."""
    if not path:
        return name
    seps = [s for j in matches for s in _TAIL_SEPARATORS if _tail(j.name)[0].endswith(s)]
    return f"{path}{seps[0] if seps else ' > '}{name}"


def match_jobs(
    jobs: list[InspectedJob],
    name: str,
    instances: list[str] | None = None,
    copies: list[str] | None = None,
) -> JobMatch:
    """All jobs a requirement's job_name covers, and expected instances that are missing.

    Every job the name covers counts and every one must pass: the exact name itself, parallel
    ('sast 2/3'), GitLab matrix ('sast: [py]'), GitHub matrix ('sast (py)'), downstream
    ('trigger > sast') and GitHub reusable workflow ('caller / sast') jobs. GitLab parallel
    names carry the total, so missing indices are reported. For totals above 1,000
    a compact missing-leg diagnostic replaces enumeration; the completeness check
    itself is never skipped (#88). Invalid indices and inconsistent totals fail closed.

    Matrix names carry no total, so a removed leg is invisible from the names alone (#60).
    `instances` (the requirement's declared labels, normalized) closes that gap: within every
    prefix ('' or 'trigger > ') that ran matrix legs, each declared label must have a leg; if
    no matrix leg ran at all, every declared label is missing. Extra, undeclared legs are
    allowed (they are still evaluated). Without a declaration, matched matrix legs are
    reported in `undeclared_legs`.

    Copies told apart only by a prefix (several downstream pipelines, reusable-workflow
    callers, Jenkins stage paths) carry no total either (#65). `copies` (the declared
    qualifying paths, '' for the unprefixed job) must each have a matching job; extra copies
    are allowed. With `instances` as well, every declared copy that ran must run every
    declared leg. Without a declaration, prefixed copies are reported in `undeclared_copies`.

    An exact match does not hide instances (#59). ScanProof cannot tell a deliberate,
    unrelated 'sast 1/2' from a leg of 'sast', and letting a passing 'sast' stand in for a
    failing leg would be a false VERIFIED. A qualified name ('child > sast') covers only
    that child's 'sast' job and its parallel/matrix instances (#62), not other children.
    """
    qualified = is_qualified(name)
    required_prefix, base_name = _tail(name) if qualified else ("", name)
    matches = [
        j
        for j in jobs
        if (not qualified or _tail(j.name)[0] == required_prefix)
        and _is_instance(_tail(j.name)[1], base_name)
    ]
    present: dict[tuple[str, int], set[int]] = {}
    invalid_parallel: set[str] = set()
    legs: dict[str, tuple[set[str], str]] = {}  # prefix -> (labels present, naming style)
    undeclared: list[str] = []
    for j in matches:
        prefix, tail = _tail(j.name)
        m = _PARALLEL.match(tail)
        if m and m.group("base") == base_name:
            index_raw, total_raw = m.group("index"), m.group("total")
            if len(index_raw) > _MAX_PARALLEL_DIGITS or len(total_raw) > _MAX_PARALLEL_DIGITS:
                invalid_parallel.add(f"{prefix}{base_name} [invalid parallel index/total]")
            else:
                index, total = int(index_raw), int(total_raw)
                if not 1 <= index <= total:
                    invalid_parallel.add(f"{prefix}{base_name} [invalid parallel index/total]")
                else:
                    present.setdefault((prefix, total), set()).add(index)
        leg = _matrix_label(tail, base_name)
        if leg is not None:
            style, label = leg
            legs.setdefault(prefix, (set(), style))[0].add(normalize_instance_label(label))
            undeclared.append(j.name)

    # A conflicting total in one pipeline copy is ambiguous, even if both sets happen
    # to be individually complete. Different downstream copies may have different totals.
    totals_by_prefix: dict[str, set[int]] = {}
    for prefix, total in present:
        totals_by_prefix.setdefault(prefix, set()).add(total)
    for prefix, totals in totals_by_prefix.items():
        if len(totals) > 1:
            invalid_parallel.add(f"{prefix}{base_name} [conflicting parallel totals]")

    missing = sorted(invalid_parallel)
    for (prefix, total), indices in sorted(present.items()):
        if total <= _MAX_PARALLEL_ENUMERATE:
            missing.extend(
                f"{prefix}{base_name} {i}/{total}"
                for i in range(1, total + 1)
                if i not in indices
            )
        elif len(indices) != total:
            # A 1/1001 job must not become VERIFIED just because enumerating 1,000 missing
            # names was capped. Checking the observed count is O(number of visible jobs).
            missing.append(
                f"{prefix}{base_name} [missing {total - len(indices)} of {total} parallel legs]"
            )
    present_copies: dict[str, str] = {}  # copy path -> its name prefix
    for j in matches:
        present_copies.setdefault(_copy_path(j.name, base_name), _tail(j.name)[0])
    missing_copies = [
        (_copy_name(c, base_name, matches), c) for c in copies or [] if c not in present_copies
    ]
    undeclared_copies = (
        [] if copies or qualified else [j.name for j in matches if _copy_path(j.name, base_name)]
    )
    if not instances:
        return JobMatch(
            jobs=matches,
            missing=missing,
            undeclared_legs=undeclared,
            missing_copies=missing_copies,
            undeclared_copies=undeclared_copies,
        )
    if matches and not legs:
        # The job runs, but not as a matrix: every declared leg is gone.
        legs = {prefix: (set(), "") for prefix in sorted({_tail(j.name)[0] for j in matches})}
    leg_style = next(iter(legs.values()))[1] if legs else ""
    for path in copies or []:
        if path in present_copies:  # a declared copy that ran must run every declared leg
            legs.setdefault(present_copies[path], (set(), leg_style))
    missing_declared = [
        (_leg_name(prefix, base_name, label, style or None), label)
        for prefix, (labels, style) in sorted(legs.items())
        for label in instances
        if label not in labels
    ]
    return JobMatch(
        jobs=matches,
        missing=missing,
        missing_declared=missing_declared,
        missing_copies=missing_copies,
        undeclared_copies=undeclared_copies,
    )
