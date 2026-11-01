from scanproof.scanners.semgrep import SemgrepAdapter


def test_oversized_json_integer_is_unparseable_evidence():
    raw = b'{"results": [], "oversized": ' + b"9" * 5000 + b"}"
    evidence = SemgrepAdapter().parse(raw)
    assert evidence.present
    assert not evidence.parseable
    assert evidence.parse_error
