"""SARIF 2.1.0 adapter: one adapter for every tool that exports SARIF.

Tested against real SARIF from Semgrep 1.181.1, Trivy 0.76.1, gitleaks 8.30.1 and Checkov 3.3.30.
Because SARIF can come from anything, pair it with `expected_scanner` in the policy
(e.g. `tool: sarif` + `expected_scanner: CodeQL`).

Mapping (all runs combined):
  runs[].tool.driver.name            scanner_name (comma-joined if runs differ)
  runs[].invocations[]               scanner errors: executionSuccessful=false, plus
                                     tool{Execution,Configuration}Notifications at error/warning
                                     level. No invocations in any run = errors unknown.
  runs[].artifacts[].location.uri    scope (scanned files), when the producer lists them
  runs[].results[]                   findings by level; a result without `level` takes its
                                     rule's defaultConfiguration.level, else SARIF's default
                                     "warning". A result with a suppression whose status is
                                     not "rejected" (e.g. `# nosemgrep` -> kind inSource) is
                                     counted in `suppressed`, not in the total (#123)
  runs[].properties.repoDigests etc. container target (Trivy image scans)
"""

from __future__ import annotations

from typing import Any

from scanproof.evidence.models import (
    FindingsSummary,
    ScannerError,
    ScanScope,
    ScanTarget,
    ScanType,
)
from scanproof.scanners.base import ScannerAdapter, count_by

_LEVEL_MAP = {"error": "error", "warning": "warn"}


class SarifAdapter(ScannerAdapter):
    tool = "sarif"
    scan_type = ScanType.OTHER

    def shape_problem(self, data: Any) -> str | None:
        if not isinstance(data, dict):
            return "SARIF log must be a JSON object"
        if not str(data.get("version", "")).startswith("2."):
            return f"Not a SARIF 2.x log (version={data.get('version')!r})"
        runs = data.get("runs")
        if not isinstance(runs, list) or not runs:
            return "SARIF log has no runs"
        if not all(isinstance(r, dict) and isinstance(r.get("tool"), dict) for r in runs):
            return "Every SARIF run must have a tool"
        return None

    def extract(self, data: dict[str, Any]) -> dict[str, Any]:
        runs: list[dict[str, Any]] = data["runs"]
        drivers = [r["tool"].get("driver") or {} for r in runs]
        names = list(dict.fromkeys(str(d.get("name")) for d in drivers if d.get("name")))
        versions = list(
            dict.fromkeys(
                str(d.get("version") or d.get("semanticVersion"))
                for d in drivers
                if d.get("version") or d.get("semanticVersion")
            )
        )

        severities: list[str] = []
        suppressed = 0
        for run, driver in zip(runs, drivers, strict=True):
            rules = driver.get("rules") or []
            by_id = {r.get("id"): r for r in rules if isinstance(r, dict)}
            for result in run.get("results") or []:
                if _is_suppressed(result):
                    suppressed += 1
                    continue
                severities.append(_result_level(result, rules, by_id).upper())

        return {
            "tool_version": ", ".join(versions) or None,
            "scanner_name": ", ".join(names) or None,
            "scanner_errors": _errors(runs),
            "scope": _scope(runs),
            "results_reported": all("results" in r for r in runs),
            "findings": FindingsSummary(
                total=len(severities), by_severity=count_by(severities), suppressed=suppressed
            ),
            "target": _target(runs),
        }


def _result_level(result: dict[str, Any], rules: list, by_id: dict) -> str:
    if result.get("level"):
        return str(result["level"])
    rule = None
    idx = result.get("ruleIndex")
    if isinstance(idx, int) and 0 <= idx < len(rules):
        rule = rules[idx]
    elif result.get("ruleId") in by_id:
        rule = by_id[result["ruleId"]]
    default = ((rule or {}).get("defaultConfiguration") or {}).get("level")
    return str(default or "warning")


def _errors(runs: list[dict[str, Any]]) -> list[ScannerError] | None:
    if not any(isinstance(r.get("invocations"), list) for r in runs):
        return None
    errors: list[ScannerError] = []
    for run in runs:
        for inv in run.get("invocations") or []:
            if inv.get("executionSuccessful") is False:
                errors.append(
                    ScannerError(
                        level="error",
                        type="invocation",
                        message=str(
                            inv.get("exitCodeDescription")
                            or f"executionSuccessful=false (exit code {inv.get('exitCode')})"
                        ),
                    )
                )
            for key in ("toolExecutionNotifications", "toolConfigurationNotifications"):
                for note in inv.get(key) or []:
                    level = str(note.get("level", "warning"))
                    if level not in _LEVEL_MAP:
                        continue
                    msg = (note.get("message") or {}).get("text") or "(no message)"
                    locs = note.get("locations") or []
                    uri = (
                        ((locs[0].get("physicalLocation") or {}).get("artifactLocation") or {}).get(
                            "uri"
                        )
                        if locs
                        else None
                    )
                    errors.append(
                        ScannerError(level=_LEVEL_MAP[level], type=key, message=str(msg), path=uri)
                    )
    return errors


def _scope(runs: list[dict[str, Any]]) -> ScanScope | None:
    if not any(isinstance(r.get("artifacts"), list) for r in runs):
        return None
    uris = [
        str((a.get("location") or {}).get("uri"))
        for r in runs
        for a in r.get("artifacts") or []
        if (a.get("location") or {}).get("uri")
    ]
    return ScanScope(files_scanned=len(uris), scanned_paths=uris)


def _target(runs: list[dict[str, Any]]) -> ScanTarget | None:
    for run in runs:
        props = run.get("properties") or {}
        if any(k in props for k in ("imageName", "repoDigests", "imageID")):
            digests = props.get("repoDigests")
            tags = props.get("repoTags")
            return ScanTarget(
                artifact_name=props.get("imageName"),
                artifact_type="container_image",
                image_id=props.get("imageID"),
                repo_digests=[str(d) for d in digests] if isinstance(digests, list) else None,
                repo_tags=[str(t) for t in tags] if isinstance(tags, list) else None,
            )
    return None


def _is_suppressed(result: Any) -> bool:
    """SARIF 3.35: any suppression not explicitly rejected hides the result.

    A malformed `suppressions` value counts as suppressed: a report that tries to hide a
    result must not have it silently counted as an ordinary, unsuppressed finding instead.
    """
    if not isinstance(result, dict) or "suppressions" not in result:
        return False
    items = result["suppressions"]
    if not isinstance(items, list):
        return True
    return any(not (isinstance(i, dict) and i.get("status") == "rejected") for i in items)
