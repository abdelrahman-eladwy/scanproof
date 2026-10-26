"""ScanProof command-line interface.

Exit codes (stable contract, see README):
  0  inspection / verification completed
  1  policy failure                     (from milestone 3 onwards)
  2  indeterminate: could not obtain evidence (auth, network, not found...)
  3  usage error
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Annotated

import typer

from scanproof import __version__
from scanproof.connectors.base import ConnectorError
from scanproof.connectors.gitlab import GitLabConnector
from scanproof.inspection import inspect_pipeline
from scanproof.reporting.console import print_inspection_summary

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
    project: Annotated[
        str, typer.Option("--project", "-p", help="Project id or full path (group/project).")
    ],
    pipeline: Annotated[int, typer.Option("--pipeline", help="Pipeline id.")],
    gitlab_url: Annotated[
        str, typer.Option("--gitlab-url", envvar="GITLAB_URL", help="GitLab base URL.")
    ] = "https://gitlab.com",
    token_env: Annotated[
        str,
        typer.Option(
            "--token-env",
            help="Env var holding the token. Tokens are never accepted as arguments.",
        ),
    ] = "GITLAB_TOKEN",  # noqa: S107 - env var name, not a secret
    ca_bundle: Annotated[
        Path | None,
        typer.Option(
            "--ca-bundle",
            envvar="SCANPROOF_CA_BUNDLE",
            exists=True,
            dir_okay=False,
            help="CA bundle for self-hosted GitLab with a private CA.",
        ),
    ] = None,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write JSON here instead of stdout.")
    ] = None,
    quiet: Annotated[
        bool, typer.Option("--quiet", "-q", help="No human summary on stderr.")
    ] = False,
) -> None:
    """Inspect a GitLab pipeline: jobs, retries and artifacts. No policy is applied."""
    token = os.environ.get(token_env, "")
    if not token:
        typer.echo(f"error: environment variable {token_env} is not set", err=True)
        raise typer.Exit(EXIT_USAGE)

    try:
        with GitLabConnector(
            gitlab_url, token, ca_bundle=str(ca_bundle) if ca_bundle else None
        ) as gl:
            report = inspect_pipeline(
                gl, instance_url=gl.base_url, project=project, pipeline_id=pipeline
            )
    except ConnectorError as exc:
        typer.echo(f"INDETERMINATE: {exc.kind.value}: {exc.message}", err=True)
        raise typer.Exit(EXIT_INDETERMINATE) from None

    payload = report.model_dump_json(indent=2)
    if output:
        output.write_text(payload + "\n", encoding="utf-8")
    else:
        typer.echo(payload)
    if not quiet:
        print_inspection_summary(report)
        if output:
            typer.echo(f"\nReport written to {output}", err=True)
    raise typer.Exit(EXIT_OK)


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
