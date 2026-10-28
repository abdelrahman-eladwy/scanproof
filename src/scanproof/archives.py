"""Refuse zip archives whose central directory is too big to open safely.

`zipfile.ZipFile` reads the whole central directory up front and builds one object per entry,
reading until the directory's declared *size* is used up (the declared entry *count* can lie).
A 33 MiB artifact of 400,000 empty members took 18 s and 219 MiB just to open. Artifacts and
Fortify FPRs come from the pipeline being judged, so whoever can change that pipeline controls
them. `check_zip_directory` reads only the end-of-central-directory record (and its ZIP64
form) and rejects directories over the limits before `ZipFile` touches them.

Pure and stdlib only; used by connectors/http.py and scanners/fortify.py.
"""

from __future__ import annotations

MAX_ZIP_ENTRIES = 50_000
MAX_ZIP_DIRECTORY_BYTES = 8 * 1024 * 1024

_EOCD = b"PK\x05\x06"
_ZIP64_LOCATOR = b"PK\x06\x07"
_ZIP64_EOCD = b"PK\x06\x06"
_EOCD_SIZE = 22
_MAX_COMMENT = 65535


class ZipTooLarge(ValueError):
    """The archive's central directory exceeds MAX_ZIP_ENTRIES or MAX_ZIP_DIRECTORY_BYTES."""


def _u(data: bytes, start: int, size: int) -> int:
    return int.from_bytes(data[start : start + size], "little")


def zip_directory(data: bytes) -> tuple[int, int] | None:
    """(entries, central directory bytes) from the end record, or None if there is none (then
    `zipfile` itself rejects the archive)."""
    tail_start = max(0, len(data) - (_EOCD_SIZE + _MAX_COMMENT))
    tail = data[tail_start:]
    at = tail.rfind(_EOCD)
    if at < 0 or len(tail) - at < _EOCD_SIZE:
        return None
    entries, size = _u(tail, at + 10, 2), _u(tail, at + 12, 4)
    if entries == 0xFFFF or size == 0xFFFFFFFF:  # ZIP64: the real values are elsewhere
        locator = tail_start + at - 20
        if locator < 0 or data[locator : locator + 4] != _ZIP64_LOCATOR:
            return None
        record = _u(data, locator + 8, 8)
        if data[record : record + 4] != _ZIP64_EOCD:
            return None
        entries, size = _u(data, record + 32, 8), _u(data, record + 40, 8)
    return entries, size


def check_zip_directory(data: bytes) -> None:
    found = zip_directory(data)
    if found is None:
        return
    entries, size = found
    if entries > MAX_ZIP_ENTRIES:
        raise ZipTooLarge(f"archive lists {entries} entries; limit is {MAX_ZIP_ENTRIES}")
    if size > MAX_ZIP_DIRECTORY_BYTES:
        raise ZipTooLarge(f"archive directory is {size} bytes; limit is {MAX_ZIP_DIRECTORY_BYTES}")
