"""#44 fuzz/compression gap: zip archives with oversized central directories are refused before
`zipfile` builds one object per entry (a 33 MiB, 400,000-entry artifact took 18 s and 219 MiB
just to open). Artifacts and Fortify FPRs come from the pipeline being judged."""

from __future__ import annotations

import io
import time
import zipfile

import pytest

from scanproof.archives import (
    MAX_ZIP_DIRECTORY_BYTES,
    MAX_ZIP_ENTRIES,
    ZipTooLarge,
    check_zip_directory,
    zip_directory,
)
from scanproof.connectors.base import ConnectorError, ErrorKind
from scanproof.connectors.gitlab import GitLabConnector
from scanproof.scanners import get_adapter
from tests.conftest import FIXTURES


def make_zip(entries: int, report: bytes = b'{"results": [], "errors": []}') -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr("semgrep.json", report)
        for i in range(entries):
            z.writestr(str(i), b"")
    return buf.getvalue()


MANY = make_zip(MAX_ZIP_ENTRIES + 20_000)  # 70,001 entries: written in ZIP64 form


def patched_end(data: bytes, *, entries: int | None = None, size: int | None = None) -> bytes:
    at = data.rfind(b"PK\x05\x06")
    out = bytearray(data)
    if entries is not None:
        out[at + 8 : at + 12] = entries.to_bytes(2, "little") * 2
    if size is not None:
        out[at + 12 : at + 16] = size.to_bytes(4, "little")
    return bytes(out)


@pytest.fixture
def gl():
    with GitLabConnector("https://gitlab.example.com", "t", sleep=lambda _: None) as c:
        yield c


def test_small_archives_pass(gl) -> None:
    data = make_zip(10)
    assert zip_directory(data)[0] == 11
    check_zip_directory(data)
    assert gl._extract(data, "semgrep.json", "a").startswith(b'{"results"')


def test_zip64_end_record_is_read() -> None:
    entries, size = zip_directory(MANY)
    assert entries == MAX_ZIP_ENTRIES + 20_001
    assert size > 0


def test_too_many_entries_is_refused_fast(gl) -> None:
    started = time.perf_counter()
    with pytest.raises(ConnectorError) as err:
        gl._extract(MANY, "semgrep.json", "semgrep-report")
    assert err.value.kind is ErrorKind.LIMIT_EXCEEDED
    assert "entries" in err.value.message
    assert time.perf_counter() - started < 0.5  # no zipfile.ZipFile on the full directory


def test_lying_entry_count_is_caught_by_the_directory_size() -> None:
    """zipfile reads until the declared directory SIZE is used up; the count can lie."""
    data = patched_end(make_zip(5), entries=1, size=MAX_ZIP_DIRECTORY_BYTES + 1)
    with pytest.raises(ZipTooLarge, match="directory is"):
        check_zip_directory(data)


@pytest.mark.parametrize("data", [b"", b"not a zip", b"PK\x05\x06", b"x" * 100])
def test_no_end_record_is_left_to_zipfile(gl, data) -> None:
    assert zip_directory(data) is None
    with pytest.raises(ConnectorError) as err:
        gl._extract(data, "semgrep.json", "a")
    assert err.value.kind is ErrorKind.INTEGRITY  # BadZipFile, as before


def test_broken_zip64_locator_is_left_to_zipfile() -> None:
    data = patched_end(make_zip(2), entries=0xFFFF)  # claims ZIP64, has no locator
    assert zip_directory(data) is None


def test_fortify_adapter_refuses_a_huge_fpr_without_raising() -> None:
    real = (FIXTURES / "fortify/hello_world.fpr").read_bytes()
    assert get_adapter("fortify").parse(real).parseable
    bomb = make_zip(MAX_ZIP_ENTRIES + 1, report=b"")
    ev = get_adapter("fortify").parse(bomb)  # adapters never raise
    assert not ev.parseable
    assert "entries" in (ev.parse_error or "")
