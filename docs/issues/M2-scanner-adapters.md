# M2 — Scanner adapters (Semgrep, Trivy) and evidence model

**Goal:** turn raw report bytes into a provider-neutral `ScanEvidence` object that M3 can judge.

## Design

- `scanners/base.py`: `ScannerAdapter` protocol: `tool: str`, `scan_type: ScanType`,
  `parse(raw: bytes) -> ScanEvidence`. Adapters never raise on bad input; they return evidence
  with `parseable=False` and a reason.
- `evidence/models.py`: `ScanEvidence` with: tool, tool_version, scan_type, report_sha256,
  present, parseable, parse_error, scanner_errors (count + messages), scope (see below),
  findings_count (+ by severity), target (Trivy: artifact name, image id, repo digests).
  Every field that the report does not provide is `None` (= unknown), not 0.
- `scope` for Semgrep: `paths.scanned` list and count, `paths.skipped` if present.
- Registry: `scanners/__init__.py` maps tool name -> adapter. Adding a tool = one new file.

## Acceptance criteria

- [ ] Semgrep: valid report, zero-findings report, report with `errors[]`, truncated JSON,
      empty file, non-JSON, wrong-tool JSON (a Trivy report) — each covered by a test
- [ ] Semgrep: `scanned_files` derived from `paths.scanned`; missing key -> `None`, not 0
- [ ] Trivy: image report parses `ArtifactName`, `Metadata.ImageID`, `Metadata.RepoDigests`
- [ ] Trivy: `Results` missing vs empty list are distinguished
- [ ] `report_sha256` computed over the exact downloaded bytes
- [ ] Fixtures are **real** reports from the demo project (sanitized), not hand-written
- [ ] New command `scanproof evidence -p .. --pipeline .. --job semgrep-sast --report semgrep.json`
      downloads and prints the evidence JSON (exit 2 on download failure)
- [ ] Tolerant of unknown extra fields; pin tested scanner versions in `docs/compatibility.md`
