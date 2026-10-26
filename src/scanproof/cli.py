"""ScanProof command-line interface.

Exit codes (stable contract, see README):
  0  VERIFIED, or inspect / evidence completed
  1  BLOCKED: a required control failed
  2  indeterminate: could not obtain evidence (auth, network, not found...)
  3  usage error
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Annotated

import typer

from scanproof import __version__
from scanproof.connectors.base import CIConnector, ConnectorError
from scanproof.connectors.github import DEFAULT_GITHUB_API, GitHubConnector
from scanproof.connectors.gitlab import GitLabConnector
from scanproof.evidence.collector import collect_evidence, find_job
from scanproof.evidence.models import EvidenceSource
from scanproof.inspection import inspect_pipeline
from scanproof.policy.models import PolicyError, load_policy
from scanproof.reporting.console import (
    print_evidence_summary,
    print_inspection_summary,
    print_verification_summary,
)
from scanproof.scanners import ADAPTERS, get_adapter
from scanproof.verification import verify_pipeline

EXIT_OK = 0
EXIT_POLICY_FAILURE = 1
EXIT_INDETERMINATE = 2
EXIT_USAGE = 3

app = typer.Typer(
    name="scanproof",
    help="Verify that required security scans ran and produced valid evidence.",
    no_args_is_help=True,
    add_completion=False,
)

# ---------------------------------------------------------------- shared options

ProjectOpt = Annotated[
    str | None, typer.Option("--project", "-p", help="Project id or full path (group/project).")
]
PipelineOpt = Annotated[int | None, typer.Option("--pipeline", help="Pipeline id.")]
GitLabUrlOpt = Annotated[
    str, typer.Option("--gitlab-url", envvar="GITLAB_URL", help="GitLab base URL.")
]
TokenEnvOpt = Annotated[
    str | None,
    typer.Option(
        "--token-env",
        help="Env var holding the token (default GITLAB_TOKEN / GITHUB_TOKEN by provider). "
        "Tokens are never accepted as arguments.",
    ),
]
GitHubUrlOpt = Annotated[
    str,
    typer.Option(
        "--github-url", envvar="GITHUB_API_URL", help="GitHub API URL (GHES: https://host/api/v3)."
    ),
]
ProviderOpt = Annotated[
    str | None,
    typer.Option("--provider", help="gitlab (default) or github. verify defaults to the policy's."),
]
CaBundleOpt = Annotated[
    Path | None,
    typer.Option(
        "--ca-bundle",
        envvar="SCANPROOF_CA_BUNDLE",
        exists=True,
        dir_okay=False,
        help="CA bundle for self-hosted GitLab with a private CA.",
    ),
]
OutputOpt = Annotated[
    Path | None, typer.Option("--output", "-o", help="Write JSON here instead of stdout.")
]
QuietOpt = Annotated[bool, typer.Option("--quiet", "-q", help="No human summary on stderr.")]
AnonymousOpt = Annotated[
    bool,
    typer.Option(
        "--anonymous", help="No token: read a PUBLIC project's pipelines without authenticating."
    ),
]

DEFAULT_GITLAB = "https://gitlab.com"
DEFAULT_GITHUB = DEFAULT_GITHUB_API
DEFAULT_TOKEN_ENV = {"gitlab": "GITLAB_TOKEN", "github": "GITHUB_TOKEN"}  # env var names


def _fail(code: int, message: str) -> typer.Exit:
    typer.echo(message, err=True)
    return typer.Exit(code)


def _connector(
    provider: str | None,
    gitlab_url: str,
    github_url: str,
    token_env: str | None,
    ca_bundle: Path | None,
    anonymous: bool = False,
) -> CIConnector:
    provider = (provider or "gitlab").lower()
    if provider not in DEFAULT_TOKEN_ENV:
        raise _fail(EXIT_USAGE, f"error: unknown provider {provider!r} (gitlab or github)")
    token_env = token_env or DEFAULT_TOKEN_ENV[provider]
    token = os.environ.get(token_env, "")
    if anonymous:
        token = ""  # never send a token in anonymous mode, even if one is set
    elif not token:
        raise _fail(
            EXIT_USAGE,
            f"error: environment variable {token_env} is not set "
            "(use --anonymous for public projects)",
        )
    ca = str(ca_bundle) if ca_bundle else None
    try:
        if provider == "github":
            return GitHubConnector(github_url, token or None, anonymous=anonymous, ca_bundle=ca)
        return GitLabConnector(gitlab_url, token or None, anonymous=anonymous, ca_bundle=ca)
    except ConnectorError as exc:
        raise _fail(EXIT_INDETERMINATE, f"INDETERMINATE: {exc.kind.value}: {exc.message}") from None


def _emit(payload: str, output: Path | None) -> None:
    if output:
        output.write_text(payload + "\n", encoding="utf-8")
    else:
        typer.echo(payload)


def _require(**values: object) -> None:
    missing = [f"--{k.replace('_', '-')}" for k, v in values.items() if v is None]
    if missing:
        raise _fail(EXIT_USAGE, f"error: missing required option(s): {', '.join(missing)}")


# ---------------------------------------------------------------- commands


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"scanproof {__version__}")
        raise typer.Exit(EXIT_OK)


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version."),
    ] = None,
) -> None:
    """ScanProof - Security Scan Assurance Engine."""


@app.command()
def inspect(
    project: ProjectOpt = None,
    pipeline: PipelineOpt = None,
    gitlab_url: GitLabUrlOpt = DEFAULT_GITLAB,
    github_url: GitHubUrlOpt = DEFAULT_GITHUB,
    provider: ProviderOpt = None,
    token_env: TokenEnvOpt = None,
    ca_bundle: CaBundleOpt = None,
    anonymous: AnonymousOpt = False,
    output: OutputOpt = None,
    quiet: QuietOpt = False,
) -> None:
    """Inspect a GitLab pipeline: jobs, retries and artifacts. No policy is applied."""
    _require(project=project, pipeline=pipeline)
    try:
        with _connector(provider, gitlab_url, github_url, token_env, ca_bundle, anonymous) as gl:
            report = inspect_pipeline(
                gl, instance_url=gl.base_url, project=project, pipeline_id=pipeline
            )
    except ConnectorError as exc:
        raise _fail(EXIT_INDETERMINATE, f"INDETERMINATE: {exc.kind.value}: {exc.message}") from None

    _emit(report.model_dump_json(indent=2), output)
    if not quiet:
        print_inspection_summary(report)
    raise typer.Exit(EXIT_OK)


@app.command()
def evidence(
    tool: Annotated[
        str, typer.Option("--tool", "-t", help=f"Scanner: {', '.join(sorted(ADAPTERS))}.")
    ],
    file: Annotated[
        Path | None,
        typer.Option("--file", "-f", exists=True, dir_okay=False, help="Parse a local report."),
    ] = None,
    project: ProjectOpt = None,
    pipeline: PipelineOpt = None,
    job: Annotated[
        str | None, typer.Option("--job", help="Job name that produced the report.")
    ] = None,
    report: Annotated[
        str | None, typer.Option("--report", help="Report path inside the job's artifacts.")
    ] = None,
    artifact: Annotated[
        str | None,
        typer.Option("--artifact", help="GitHub: run artifact name that contains --report."),
    ] = None,
    gitlab_url: GitLabUrlOpt = DEFAULT_GITLAB,
    github_url: GitHubUrlOpt = DEFAULT_GITHUB,
    provider: ProviderOpt = None,
    token_env: TokenEnvOpt = None,
    ca_bundle: CaBundleOpt = None,
    anonymous: AnonymousOpt = False,
    output: OutputOpt = None,
    quiet: QuietOpt = False,
) -> None:
    """Normalize one scanner report into ScanProof evidence (local file or GitLab job)."""
    try:
        adapter = get_adapter(tool)
    except KeyError as exc:
        raise _fail(EXIT_USAGE, f"error: {exc.args[0]}") from None

    if file is not None:
        if any(v is not None for v in (project, pipeline, job, report, artifact)):
            raise _fail(
                EXIT_USAGE, "error: use either --file or --project/--pipeline/--job/--report"
            )
        ev = adapter.parse(file.read_bytes())
        ev.source = EvidenceSource(local_file=str(file))
    else:
        _require(project=project, pipeline=pipeline, job=job, report=report)
        try:
            with _connector(
                provider, gitlab_url, github_url, token_env, ca_bundle, anonymous
            ) as gl:
                inspection = inspect_pipeline(
                    gl, instance_url=gl.base_url, project=project, pipeline_id=pipeline
                )
                found = find_job(inspection.jobs, job)
                if found is None:
                    raise _fail(
                        EXIT_INDETERMINATE,
                        f"REQUIRED_JOB_ABSENT: no job named '{job}' in pipeline {pipeline}",
                    )
                ev = collect_evidence(
                    gl,
                    project=project,
                    pipeline=inspection.pipeline,
                    job=found,
                    report_path=report,
                    adapter=adapter,
                    artifact_name=artifact,
                )
        except ConnectorError as exc:
            raise _fail(
                EXIT_INDETERMINATE, f"INDETERMINATE: {exc.kind.value}: {exc.message}"
            ) from None

    _emit(ev.model_dump_json(indent=2), output)
    if not quiet:
        print_evidence_summary(ev)
    raise typer.Exit(EXIT_OK)


PolicyOpt = Annotated[
    Path, typer.Option("--policy", "-P", exists=True, dir_okay=False, help="Policy YAML file.")
]


def _load(policy_path: Path):
    try:
        return load_policy(policy_path)
    except PolicyError as exc:
        raise _fail(EXIT_USAGE, f"error: {exc}") from None


@app.command()
def validate(policy: PolicyOpt) -> None:
    """Check a policy file without contacting GitLab."""
    loaded = _load(policy)
    typer.echo(
        f"OK: policy '{loaded.name}' with {len(loaded.requirements)} requirement(s): "
        + ", ".join(r.id for r in loaded.requirements),
        err=True,
    )
    raise typer.Exit(EXIT_OK)


@app.command()
def verify(
    policy: PolicyOpt,
    pipeline: PipelineOpt = None,
    project: Annotated[
        str | None,
        typer.Option("--project", "-p", help="Override the project id/path from the policy."),
    ] = None,
    gitlab_url: GitLabUrlOpt = DEFAULT_GITLAB,
    github_url: GitHubUrlOpt = DEFAULT_GITHUB,
    provider: ProviderOpt = None,
    token_env: TokenEnvOpt = None,
    ca_bundle: CaBundleOpt = None,
    anonymous: AnonymousOpt = False,
    output: OutputOpt = None,
    quiet: QuietOpt = False,
) -> None:
    """Verify a pipeline's security-scan evidence against a policy.

    Exit 0 VERIFIED, 1 BLOCKED, 2 INDETERMINATE, 3 usage/policy error.
    """
    _require(pipeline=pipeline)
    loaded = _load(policy)
    target_project = project or loaded.project.id
    if provider and provider.lower() != loaded.project.provider:
        raise _fail(
            EXIT_USAGE,
            f"error: --provider {provider} contradicts the policy's provider "
            f"'{loaded.project.provider}'",
        )
    provider = loaded.project.provider
    try:
        with _connector(provider, gitlab_url, github_url, token_env, ca_bundle, anonymous) as gl:
            report = verify_pipeline(
                gl, loaded, instance_url=gl.base_url, project=target_project, pipeline_id=pipeline
            )
    except ConnectorError as exc:
        if output:
            output.write_text(
                json.dumps(
                    {
                        "schema_version": "scanproof.dev/verification/v1alpha1",
                        "decision": "INDETERMINATE",
                        "exit_code": EXIT_INDETERMINATE,
                        "project": target_project,
                        "pipeline_id": pipeline,
                        "error": exc.to_dict(),
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
        raise _fail(EXIT_INDETERMINATE, f"INDETERMINATE: {exc.kind.value}: {exc.message}") from None

    _emit(report.model_dump_json(indent=2), output)
    if not quiet:
        print_verification_summary(report)
    raise typer.Exit(report.exit_code)


# ---------------------------------------------------------------- entry point


def run() -> None:
    """Console entry point.

    Click exits with 2 on usage errors, which would collide with our
    INDETERMINATE code and let a typo look like "could not verify". Map usage
    errors to 3 so CI gates can tell them apart.
    """
    try:
        rc = app(standalone_mode=False)
    except _UsageError as exc:
        exc.show()
        sys.exit(EXIT_USAGE)
    except _ClickException as exc:
        exc.show()
        sys.exit(exc.exit_code)
    except typer.Abort:
        typer.echo("Aborted.", err=True)
        sys.exit(130)
    sys.exit(rc if isinstance(rc, int) else EXIT_OK)


def _mro_class(cls: type, name: str) -> type[Exception]:
    # Typer >= 0.20 vendors Click as `typer._click`; older versions use `click`.
    # Resolve the base classes from Typer's own hierarchy so both work.
    return next(c for c in cls.__mro__ if c.__name__ == name)


_UsageError = _mro_class(typer.BadParameter, "UsageError")
_ClickException = _mro_class(typer.BadParameter, "ClickException")


if __name__ == "__main__":  # pragma: no cover
    run()
