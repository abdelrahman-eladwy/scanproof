"""Temporary negative test for protected-branch enforcement; DO NOT MERGE."""


def test_intentional_ruleset_failure():
    assert False, "EXPECTED FAILURE: verify required CI blocks PR merging"
