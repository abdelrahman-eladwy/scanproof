"""Adapters must never raise on hostile or malformed input (CLAUDE.md: "Never raise on bad
input"). These tests pin the bugs a fuzzing audit found, and keep a seeded fuzz run in CI."""

from __future__ import annotations

import copy
import json
import random

import pytest

from scanproof.scanners import ADAPTERS
from tests.conftest import FIXTURES

SAMPLES = {
    "semgrep": ["semgrep/semgrep-findings.json", "semgrep/semgrep-errors.json"],
    "trivy": ["trivy/trivy-python.json", "trivy/trivy-fs.json"],
    "gitlab-sast": ["gitlab-reports/gl-sast-report.json"],
    "gitlab-container-scanning": ["gitlab-reports/gl-container-scanning-report.json"],
    "gitlab-dependency-scanning": ["gitlab-reports/gl-dependency-scanning-report.json"],
    "gitlab-secret-detection": ["gitlab-reports/gl-secret-detection-report.json"],
    "sarif": ["sarif/semgrep.sarif", "sarif/trivy-image.sarif", "sarif/checkov.sarif"],
    "cyclonedx": ["cyclonedx/trivy-image.cdx.json", "cyclonedx/syft-alpine.cdx.json"],
    "checkov": ["checkov/checkov.json"],
    "sonatype-iq": ["sonatype/many_vulns.json"],
    "bitbucket-code-insights": ["bitbucket-real/code-insights-git-secrets.json"],
    "gitleaks": ["gitleaks/gitleaks-leak.json"],
    "grype": ["grype/grype-alpine.json"],
    "osv-scanner": ["osv/osv-node.json"],
    "snyk": ["snyk/single_project_one_vuln.json", "snyk/all-projects_many_vulns.json"],
    "kubescape": ["kubescape/kubescape.json"],
    "zap": ["zap/zap-baseline.json"],
    "nuclei": ["nuclei/nuclei-export.json"],
}
WEIRD = [None, 0, -1, 1.5, "", "x", [], {}, [None], {"a": None}, True, "9" * 30, 10**30]


def _paths(obj, prefix=()):
    yield prefix
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _paths(v, (*prefix, k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:3]):
            yield from _paths(v, (*prefix, i))


def _mutate(rng: random.Random, report):
    out = copy.deepcopy(report)
    candidates = [p for p in _paths(out) if p]
    for _ in range(rng.randint(1, 4)):
        path = rng.choice(candidates)
        node = out
        try:
            for key in path[:-1]:
                node = node[key]
            if rng.random() < 0.3 and isinstance(node, dict):
                node.pop(path[-1], None)
            else:
                node[path[-1]] = copy.deepcopy(rng.choice(WEIRD))
        except (KeyError, IndexError, TypeError):
            pass
    return out


@pytest.mark.parametrize("tool", sorted(SAMPLES))
def test_fuzzed_reports_never_raise(tool) -> None:
    rng = random.Random(f"scanproof-{tool}")  # noqa: S311 - reproducible fuzzing, not crypto
    adapter = ADAPTERS[tool]
    for name in SAMPLES[tool]:
        base = json.loads((FIXTURES / name).read_text())
        for _ in range(60):
            ev = adapter.parse(json.dumps(_mutate(rng, base)).encode())
            ev.model_dump_json()  # the result must also serialize
            assert ev.parseable or ev.parse_error


# ---------------------------------------------------------------- pinned audit findings


def test_checkov_absurd_error_count_is_rejected_not_allocated() -> None:
    """Was: one ScannerError allocated per claimed error -> MemoryError (DoS)."""
    data = json.loads((FIXTURES / "checkov/checkov.json").read_text())
    data["summary"]["parsing_errors"] = 10**30
    ev = ADAPTERS["checkov"].parse(json.dumps(data).encode())
    assert not ev.parseable
    assert "implausible parsing_errors" in ev.parse_error


def test_deeply_nested_sbom_does_not_hit_recursion_limit() -> None:
    """Was: recursive component count raised RecursionError at ~500 levels."""
    depth = 800
    raw = (
        '{"bomFormat":"CycloneDX","specVersion":"1.6","components":['
        + '{"name":"n","components":[' * depth
        + '{"name":"leaf"}'
        + "]}" * depth
        + "]}"
    ).encode()
    ev = ADAPTERS["cyclonedx"].parse(raw)
    assert ev.parseable and ev.scope.components == depth + 1


@pytest.mark.parametrize(
    ("tool", "name", "mutation"),
    [
        ("semgrep", "semgrep/semgrep-clean.json", lambda d: d.update(version={"a": None})),
        (
            "gitlab-sast",
            "gitlab-reports/gl-sast-report.json",
            lambda d: d["scan"]["scanner"].update(id=[]),
        ),
        ("trivy", "trivy/trivy-fs.json", lambda d: d.update(SchemaVersion=[2])),
    ],
)
def test_wrong_types_become_unparseable(tool, name, mutation) -> None:
    """Was: pydantic ValidationError / TypeError escaped from shape checks and model building."""
    data = json.loads((FIXTURES / name).read_text())
    mutation(data)
    ev = ADAPTERS[tool].parse(json.dumps(data).encode())
    assert not ev.parseable
    assert "Unexpected" in ev.parse_error
