"""Regression: mutable tags must not be treated as immutable image digests (#149)."""

from scanproof.evidence.models import ScanTarget


def test_mutable_tag_never_counts_as_digest() -> None:
    target = ScanTarget(repo_digests=["python:3.12-slim", "registry/app:latest"])
    assert target.digests() == set()


def test_only_well_formed_repo_digest_is_accepted() -> None:
    digest = "sha256:" + "a" * 64
    target = ScanTarget(
        repo_digests=[
            "registry/app@" + digest,
            "registry/app@" + "sha256:" + "z" * 64,
            "registry/app@sha256:123",
            digest,
            "@" + digest,
            "registry/app@sha512:" + "a" * 128,
        ]
    )
    assert target.digests() == {digest}


def test_digest_comparison_is_case_insensitive() -> None:
    target = ScanTarget(repo_digests=["registry/app@sha256:" + "A" * 64])
    assert target.digests() == {"sha256:" + "a" * 64}
