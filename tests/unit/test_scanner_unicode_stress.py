"""Regression: scanner reports must never emit unserializable evidence."""

from __future__ import annotations

import json

import pytest

from scanproof.scanners import ADAPTERS


@pytest.mark.parametrize(
    ("tool", "report"),
    [
        ("trivy", {"SchemaVersion": 2, "ArtifactName": "\\ud800", "Results": []}),
        ("semgrep", {"results": [{"check_id": "\\ud800", "path": "a.py", "start": {"line": 1}, "extra": {"message": "x", "severity": "ERROR"}}], "errors": []}),
        ("gitlab-sast", {"version": "15.0.0", "vulnerabilities": [], "scan": {"scanner": {"id": "\\ud800", "name": "test"}, "type": "sast", "status": "success"}}),
    ],
)
def test_unpaired_unicode_surrogate_never_escapes_to_serialized_evidence(tool, report):
    # json.dumps(ensure_ascii=True) produces a syntactically valid byte stream,
    # but a lone surrogate is not a Unicode scalar value and breaks JSON output.
    raw = json.dumps(report, ensure_ascii=True).encode("ascii")
    evidence = ADAPTERS[tool].parse(raw)
    evidence.model_dump_json()  # must not throw PydanticSerializationError
    assert not evidence.parseable
    assert evidence.parse_error


def test_valid_escaped_unicode_surrogate_pair_is_accepted():
    report = b'{"SchemaVersion":2,"ArtifactName":"\\\\ud83d\\\\ude00","Results":[]}'
    evidence = ADAPTERS["trivy"].parse(report)
    assert evidence.parseable
    evidence.model_dump_json()
