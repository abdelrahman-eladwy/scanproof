"""Pure scanner-reported scope evaluation (not independent scan provenance)."""

from __future__ import annotations

from scanproof.evidence.models import ScanEvidence
from scanproof.policy.results import CheckResult, Outcome, _r


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
