"""Time-bounded waiver application and explicit audit warnings."""

from __future__ import annotations

from datetime import date
from scanproof.policy.models import Policy
from scanproof.policy.results import Outcome, RequirementResult, combine


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
            if check.outcome is Outcome.UNKNOWN:
                warnings.append(
                    f"WAIVED_UNKNOWN: {w.requirement}/{check.check} ({check.code}) "
                    f"was UNKNOWN, not verified; risk accepted by {w.approved_by} "
                    f"until {w.expires}."
                )
            res.checks[n] = check.model_copy(
                update={
                    "waived_unknown": check.outcome is Outcome.UNKNOWN,
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
