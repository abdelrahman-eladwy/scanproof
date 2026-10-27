"""Nuclei findings, as a JSON export (`-je file.json`, an array) or JSON lines (`-jsonl -o`),
tested with Nuclei v3.11.

  template-id, info.severity   one entry per finding
  host / matched-at            what was hit (target_url_must_match)

Prefer `-je`: it writes `[]` when nothing was found, while `-jsonl` writes an empty file, which
cannot be told apart from a scan that never ran (it is reported as an empty, unparseable
report). With no findings Nuclei does not record the target, so target_url is UNKNOWN.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit

from scanproof.evidence.models import FindingsSummary, ScanTarget, ScanType
from scanproof.scanners.base import INVALID_JSON, ReportLoadError, ScannerAdapter, count_by

MAX_LINES = 200_000


class NucleiAdapter(ScannerAdapter):
    tool = "nuclei"
    scan_type = ScanType.DAST

    def load(self, raw: bytes) -> Any:
        try:
            return json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            pass
        try:
            lines = raw.decode("utf-8").splitlines()
            if len(lines) > MAX_LINES:
                raise ReportLoadError(f"more than {MAX_LINES} lines")
            return [json.loads(line) for line in lines if line.strip()]
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise ReportLoadError(f"{INVALID_JSON} (nor JSON lines): {exc}") from None

    def shape_problem(self, data: Any) -> str | None:
        if not isinstance(data, list):
            return "Nuclei report must be a JSON array (-je) or JSON lines (-jsonl)"
        for f in data:
            if not isinstance(f, dict) or "template-id" not in f:
                return "Not Nuclei output: findings need a template-id"
        return None

    def extract(self, data: list[dict[str, Any]]) -> dict[str, Any]:
        severities = [str((f.get("info") or {}).get("severity") or "unknown").upper() for f in data]
        urls: list[str] = []
        for f in data:
            for candidate in (f.get("matched-at"), f.get("host"), f.get("url")):
                if isinstance(candidate, str):
                    parts = urlsplit(candidate)
                    if parts.scheme in ("http", "https") and parts.hostname:
                        origin = f"{parts.scheme}://{parts.netloc}"
                        if origin not in urls:
                            urls.append(origin)
                        break
        return {
            "scanner_name": "nuclei",
            "scanner_errors": None,
            "results_reported": True,
            "findings": FindingsSummary(total=len(data), by_severity=count_by(severities)),
            "target": ScanTarget(urls=urls or None, artifact_type="web_application"),
        }
