"""Source-only consistency checks for the defect-to-regression evidence ledger.

Not a substitute for behavioral or live-provider security tests. Wheel/Docker
suites intentionally lack repository documentation and must not depend on it.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LEDGER = ROOT / "docs/development/defect-triage.md"
REQUIRED_CASES = {23, 50, 59, 60, 62, 65, 68, 69, 71, 88, 90}
REQUIRED_FIX_PRS = {20, 21, 22, 78, 80, 81, 82}


def test_defect_ledger_cites_existing_regression_tests() -> None:
    if os.environ.get("SCANPROOF_TEST_INSTALLED") == "1":
        return

    rows = [
        line for line in LEDGER.read_text(encoding="utf-8").splitlines() if line.startswith("| [#")
    ]
    observed: set[int] = set()
    for row in rows:
        cells = [cell.strip() for cell in row.strip("|").split("|")]
        assert len(cells) == 4, row
        issue = re.search(
            r"^\[#(\d+)\]\(https://github\.com/abdelrahman-eladwy/scanproof/issues/\1\)",
            cells[0],
        )
        assert issue is not None, row
        number = int(issue.group(1))
        assert number not in observed, f"Duplicate ledger issue #{number}"
        observed.add(number)
        assert re.fullmatch(r"P[012](?: .*)?", cells[1]), f"Unclassified #{number}"
        paths = re.findall(r"`(tests/unit/test_[a-z0-9_]+\.py)`", cells[2])
        assert paths, f"No regression file for #{number}"
        for path in paths:
            assert (ROOT / path).is_file(), f"#{number} references missing {path}"
        assert cells[3], f"#{number} has no release disposition"
    assert observed >= REQUIRED_CASES, (
        f"Missing known regression mappings: {REQUIRED_CASES - observed}"
    )


def test_early_fix_pr_regressions_remain_auditable() -> None:
    """Early fixes were PRs, not separate issues; require test paths for each."""
    if os.environ.get("SCANPROOF_TEST_INSTALLED") == "1":
        return

    content = LEDGER.read_text(encoding="utf-8")
    rows = [line for line in content.splitlines() if line.startswith("| [PR #")]
    observed: set[int] = set()
    for row in rows:
        cells = [cell.strip() for cell in row.strip("|").split("|")]
        assert len(cells) == 4, row
        pr = re.fullmatch(
            r"\[PR #(\d+)\]\(https://github\.com/abdelrahman-eladwy/scanproof/pull/\1\)"
            r"(?: .*)?",
            cells[0],
        )
        assert pr is not None, row
        number = int(pr.group(1))
        assert number not in observed, f"Duplicate fix PR #{number}"
        observed.add(number)
        assert re.fullmatch(r"P[012](?: .*)?", cells[1]), f"Unclassified PR #{number}"
        paths = re.findall(r"`(tests/unit/test_[a-z0-9_]+\.py)`", cells[2])
        assert paths, f"No regression path for PR #{number}"
        for path in paths:
            assert (ROOT / path).is_file(), f"PR #{number} references missing {path}"
        assert cells[3], f"PR #{number} lacks a validation limitation"
    assert observed >= REQUIRED_FIX_PRS, (
        f"Missing historical fix PR mappings: {REQUIRED_FIX_PRS - observed}"
    )


def test_ledger_does_not_claim_complete_security_qualification() -> None:
    if os.environ.get("SCANPROOF_TEST_INSTALLED") == "1":
        return
    content = LEDGER.read_text(encoding="utf-8")
    assert "not every historical commit" in content
    assert "independent release gates" in content
    assert "Phase 1 #44" in content


def test_defect_triage_keeps_security_disclosure_boundary() -> None:
    if os.environ.get("SCANPROOF_TEST_INSTALLED") == "1":
        return

    content = LEDGER.read_text(encoding="utf-8")
    assert "security/advisories/new" in content
    assert "Do not put a new, exploitable P0" in content
    for severity in ("**P0", "**P1", "**P2"):
        assert severity in content
