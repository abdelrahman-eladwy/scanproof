"""Regression for a silently disabled requirement via applies_to.refs: [] (#148)."""

import pytest
from pydantic import ValidationError

from scanproof.policy.models import AppliesTo


def test_empty_refs_cannot_make_every_requirement_inapplicable() -> None:
    with pytest.raises(ValidationError, match="at least 1 item"):
        AppliesTo(refs=[])


def test_nonempty_ref_pattern_is_accepted() -> None:
    assert AppliesTo(refs=["main"]).refs == ["main"]
