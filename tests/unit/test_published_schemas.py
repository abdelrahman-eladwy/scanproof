"""Phase 4 (#47): published JSON Schemas are current, versioned and describe real output.

Real CLI/library outputs are validated with an independent JSON Schema validator, and
negative controls prove the schemas reject what they must. The validator (`jsonschema`,
dev extra) is skipped where unavailable (lowest-deps / installed-wheel jobs); the drift
and contract checks always run.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import re
import typing
from pathlib import Path

import pytest
import yaml

from scanproof import contracts
from scanproof.cli import EXIT_INDETERMINATE
from scanproof.inspection import inspect_pipeline
from scanproof.policy.models import Policy
from scanproof.release import Release, load_release, verify_release
from scanproof.scanners import get_adapter
from scanproof.schemas import documents
from scanproof.verification import (
    ConnectorErrorDetail,
    VerificationErrorReport,
    verify_pipeline,
)
from tests.conftest import BASE, FIXTURES
from tests.fake_gitlab import FakeGitLab
from tests.unit.test_provider_error_matrix import TRIVY_OK
from tests.unit.test_release import COMPONENTS, connect, platforms, write_release  # noqa: F401
from tests.unit.test_verify_scenarios import make_policy

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "schemas"
SCRIPT = ROOT / "scripts/export_schemas.py"
_spec = importlib.util.spec_from_file_location("export_schemas", SCRIPT)
assert _spec is not None and _spec.loader is not None
export = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(export)

SEMGREP_OK = (FIXTURES / "semgrep/semgrep-findings.json").read_bytes()
ENV = {
    "RELEASE_IMAGE_DIGEST": "sha256:" + "0" * 64,
    "DEPLOY_URL": "https://staging.example.com",
}


def schema(name: str) -> dict:
    return json.loads((SCHEMAS / name).read_text(encoding="utf-8"))


def validator(name: str):
    js = pytest.importorskip("jsonschema")
    s = schema(name)
    js.Draft202012Validator.check_schema(s)
    return js.Draft202012Validator(s, format_checker=js.FormatChecker())


def errors(name: str, instance) -> list[str]:
    return [e.message for e in validator(name).iter_errors(instance)]


# ------------------------------------------------------------------ drift and contracts


def test_committed_schemas_match_the_catalog() -> None:
    assert export.check() == []


def test_drift_check_catches_a_hand_edited_schema(tmp_path) -> None:
    for p in SCHEMAS.glob("*.json"):
        (tmp_path / p.name).write_bytes(p.read_bytes())
    target = tmp_path / "verification-report.v1alpha1.schema.json"
    target.write_text(target.read_text().replace('"decision"', '"decisionX"', 1))
    assert any("verification-report" in p for p in export.check(tmp_path))
    (tmp_path / "rogue.schema.json").write_text("{}")
    assert any("rogue" in p for p in export.check(tmp_path))


def test_every_document_is_versioned_and_resolvable() -> None:
    docs = documents()
    assert set(docs) == {p.name for p in SCHEMAS.glob("*.schema.json")}
    for name, doc in docs.items():
        assert doc["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert doc["$id"] == contracts.SCHEMA_URL_BASE + name
        tag = doc["x-scanproof-contract"].rsplit("/", 1)[-1]
        assert f".{tag}.schema.json" in name


@pytest.mark.parametrize(
    ("name", "field", "value"),
    [
        (
            "verification-report.v1alpha1.schema.json",
            "schema_version",
            contracts.VERIFICATION_SCHEMA,
        ),
        (
            "verification-error.v1alpha1.schema.json",
            "schema_version",
            contracts.VERIFICATION_SCHEMA,
        ),
        ("release-report.v1alpha1.schema.json", "schema_version", contracts.RELEASE_SCHEMA),
        ("inspection-report.v1alpha1.schema.json", "schema_version", contracts.INSPECTION_SCHEMA),
        ("evidence.v1alpha1.schema.json", "schema_version", contracts.EVIDENCE_SCHEMA),
        ("policy.v1alpha1.schema.json", "apiVersion", contracts.POLICY_API_VERSION),
        ("release.v1alpha1.schema.json", "apiVersion", contracts.POLICY_API_VERSION),
    ],
)
def test_version_field_is_pinned_to_the_contract(name, field, value) -> None:
    assert schema(name)["properties"][field]["const"] == value


def test_model_literals_match_contract_constants() -> None:
    for model in (Policy, Release):
        assert typing.get_args(model.model_fields["apiVersion"].annotation) == (
            contracts.POLICY_API_VERSION,
        )
    assert typing.get_args(VerificationErrorReport.model_fields["exit_code"].annotation) == (
        EXIT_INDETERMINATE,
    )


# ------------------------------------------------------------------ real outputs validate


def _interpolate(text: str) -> str:
    return re.sub(r"\$\{(\w+)\}", lambda m: ENV[m.group(1)], text)


@pytest.mark.parametrize("path", sorted((ROOT / "examples/policies").glob("*.yaml")), ids=str)
def test_example_policies_validate(path) -> None:
    raw = path.read_text(encoding="utf-8")
    for text in (raw, _interpolate(raw)):  # as written, and after ${VAR} substitution
        assert errors("policy.v1alpha1.schema.json", yaml.safe_load(text)) == []


def test_example_release_validates_as_written() -> None:
    doc = yaml.safe_load((ROOT / "examples/release.yaml").read_text(encoding="utf-8"))
    assert errors("release.v1alpha1.schema.json", doc) == []


@pytest.mark.parametrize(
    "pipeline",
    [
        1042,
        "1042",
        " 77 ",
        "${RUN_ID}",
        " ${RUN_ID} ",
        "${1BAD}",
        "$RUN_ID",
        "1_000",
        "+5",
        "-3",
        "007",
        "0x10",
        0,
        -3,
        1.5,
        1.0,
        True,
        False,
        None,
        [],
        "${UNSET_PIPE}",
    ],
)
def test_release_pipeline_schema_agrees_with_loader(monkeypatch, pipeline) -> None:
    from scanproof.release import Component

    monkeypatch.setenv("RUN_ID", "5")
    monkeypatch.delenv("UNSET_PIPE", raising=False)
    try:
        Component.model_validate({"name": "c", "policy": "p.yaml", "pipeline": pipeline})
        loader_ok = True
    except ValueError:
        loader_ok = False
    doc = {
        "apiVersion": contracts.POLICY_API_VERSION,
        "kind": "ReleaseAssurance",
        "metadata": {"name": "r"},
        "components": [{"name": "c", "policy": "p.yaml", "pipeline": pipeline}],
    }
    schema_ok = errors("release.v1alpha1.schema.json", doc) == []
    # Loader stricter than the schema, never the reverse: an unset variable is a runtime
    # failure, and JSON Schema counts 1.0 as an integer while the loader rejects floats.
    if pipeline == "${UNSET_PIPE}" or (type(pipeline) is float and pipeline.is_integer()):
        assert schema_ok and not loader_ok
    else:
        assert schema_ok is loader_ok


@pytest.mark.parametrize("semgrep", [SEMGREP_OK, 404], ids=["verified", "blocked"])
def test_verification_reports_validate(connector, mock_api, semgrep) -> None:
    gl = FakeGitLab(mock_api)
    gl.job(8821, "semgrep-sast", files={"semgrep.json": semgrep})
    gl.job(8830, "trivy-image", files={"trivy.json": TRIVY_OK})
    gl.install()
    report = verify_pipeline(
        connector, make_policy(), instance_url=BASE, project="123", pipeline_id=1042
    )
    doc = json.loads(report.model_dump_json())
    assert errors("verification-report.v1alpha1.schema.json", doc) == []
    # A full report is never mistaken for an error report.
    assert errors("verification-error.v1alpha1.schema.json", doc) != []


def test_inspection_report_validates(connector, mock_api) -> None:
    gl = FakeGitLab(mock_api)
    gl.job(8821, "semgrep-sast")
    gl.install()
    report = inspect_pipeline(connector, instance_url=BASE, project="123", pipeline_id=1042)
    doc = json.loads(report.model_dump_json())
    assert errors("inspection-report.v1alpha1.schema.json", doc) == []


@pytest.mark.parametrize(
    ("tool", "fixture"),
    [("semgrep", "semgrep/semgrep-findings.json"), ("trivy", "trivy/trivy-python.json")],
)
def test_evidence_validates(tool, fixture) -> None:
    ev = get_adapter(tool).parse((FIXTURES / fixture).read_bytes())
    assert errors("evidence.v1alpha1.schema.json", json.loads(ev.model_dump_json())) == []


def test_release_report_validates(tmp_path, platforms, sleeps) -> None:  # noqa: F811
    gl, gh = platforms
    gl.install()
    gh.install()
    path = write_release(tmp_path, COMPONENTS)
    report = verify_release(load_release(path), path.parent, connect(sleeps))
    doc = json.loads(report.model_dump_json())
    assert errors("release-report.v1alpha1.schema.json", doc) == []


def test_cli_error_report_validates(tmp_path, monkeypatch, mock_api) -> None:
    from typer.testing import CliRunner

    from scanproof.cli import app
    from tests.conftest import API, TOKEN

    monkeypatch.setenv("GITLAB_TOKEN", TOKEN)
    policy = tmp_path / "p.yaml"
    policy.write_text(make_policy().model_dump_json(exclude_none=True), encoding="utf-8")
    mock_api.get(f"{API}/projects/123/pipelines/1042").respond(403)
    out = tmp_path / "report.json"
    result = CliRunner().invoke(
        app,
        ["verify", "-P", str(policy), "--pipeline", "1042", "--gitlab-url", BASE, "-o", str(out)],
    )
    assert result.exit_code == EXIT_INDETERMINATE
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert TOKEN not in out.read_text(encoding="utf-8")
    assert doc["error"]["kind"] == "AUTH"
    assert {"scanproof_version", "generated_at"} <= set(doc)
    assert errors("verification-error.v1alpha1.schema.json", doc) == []


# ------------------------------------------------------------------ negative controls


def _error_doc() -> dict:
    return json.loads(
        VerificationErrorReport(
            project="123",
            pipeline_id=1,
            error=ConnectorErrorDetail(kind="NETWORK", message="timeout"),
        ).model_dump_json()
    )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(decision="VERIFIED"),
        lambda d: d.update(exit_code=0),
        lambda d: d.update(schema_version="scanproof.dev/verification/v2"),
        lambda d: d.pop("error"),
        lambda d: d.update(pipeline_id="1"),
        lambda d: d["error"].pop("kind"),
    ],
    ids=["verified", "exit0", "wrong-version", "no-error", "pipeline-type", "no-kind"],
)
def test_error_schema_rejects_forged_or_broken_reports(mutate) -> None:
    doc = _error_doc()
    assert errors("verification-error.v1alpha1.schema.json", doc) == []
    bad = copy.deepcopy(doc)
    mutate(bad)
    assert errors("verification-error.v1alpha1.schema.json", bad) != []


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(apiVersion="scanproof.dev/v2"),
        lambda d: d.update(unknown_top_level=True),
        lambda d: d["requirements"][0].update(typo_field=1),
        lambda d: d["project"].update(provider="circleci"),
    ],
    ids=["api-version", "extra-top", "extra-requirement", "provider"],
)
def test_policy_schema_rejects_what_the_loader_rejects(mutate) -> None:
    doc = json.loads(make_policy().model_dump_json(exclude_none=True))
    assert errors("policy.v1alpha1.schema.json", doc) == []
    bad = copy.deepcopy(doc)
    mutate(bad)
    assert errors("policy.v1alpha1.schema.json", bad) != []
    with pytest.raises(Exception):  # noqa: B017 - pydantic ValidationError
        Policy.model_validate(bad)
