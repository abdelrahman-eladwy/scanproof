"""Bitbucket Cloud Pipelines connector (read-only). Built against real responses from public
Atlassian repositories (tests/fixtures/bitbucket-real/).

Mapping:
  project  = "<workspace>/<repo>"
  pipeline = build number          GET /repositories/{ws}/{repo}/pipelines/{build number}
  jobs     = steps                 GET .../pipelines/{uuid}/steps/
  reports  = Code Insights report  GET .../commit/{sha}/reports, .../reports/{id}/annotations
             `report_path` is the report's title or external id; the newest match wins.

Bitbucket specifics, each handled explicitly:
  * Bitbucket has no public API to download step artifacts. Security pipes (git-secrets-scan,
    Snyk, ...) publish Code Insights reports instead, so those are the evidence. They belong to
    the commit, not to a step: a report from another run on the same commit also counts.
  * `on-fail: strategy: ignore` lets a failed step leave the pipeline successful. A FAILED step
    in a pipeline that did not fail is reported as a failure the pipeline survived.
  * Failed, Error and System error all come back as one result in the API.
  * Access tokens go as Bearer; API tokens with an account email (BITBUCKET_USER) as Basic.
"""

from __future__ import annotations

import json
import re
import time
import uuid
from collections.abc import Callable
from typing import Any
from urllib.parse import quote

import httpx

from scanproof.connectors.base import ConnectorError, ErrorKind, NotFoundError
from scanproof.connectors.http import (
    DEFAULT_MAX_ARTIFACT_BYTES,
    MAX_PAGES,
    HttpConnector,
    origin_of,
)
from scanproof.models import Job, JobStatus, Pipeline

DEFAULT_BITBUCKET_API = "https://api.bitbucket.org/2.0"
_REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
INSIGHTS_FORMAT = "scanproof.dev/bitbucket-code-insights/v1"

_RESULT = {
    "SUCCESSFUL": JobStatus.SUCCESS,
    "FAILED": JobStatus.FAILED,
    "ERROR": JobStatus.FAILED,
    "EXPIRED": JobStatus.FAILED,
    "STOPPED": JobStatus.CANCELED,
    "NOT_RUN": JobStatus.SKIPPED,
}
_STATE = {
    "PENDING": JobStatus.PENDING,
    "READY": JobStatus.PENDING,
    "IN_PROGRESS": JobStatus.RUNNING,
    "PAUSED": JobStatus.MANUAL,
    "HALTED": JobStatus.MANUAL,
}


class BitbucketConnector(HttpConnector):
    provider = "bitbucket"
    label = "Bitbucket"
    auth_hint = "Set BITBUCKET_TOKEN (repository access token with pipelines and repository read)."
    default_auth_scheme = "bearer"

    def __init__(
        self,
        api_url: str,
        token: str | None,
        *,
        username: str | None = None,
        anonymous: bool = False,
        timeout: float = 30.0,
        ca_bundle: str | None = None,
        max_retries: int = 3,
        backoff_seconds: float = 1.0,
        max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        **limits: Any,  # request_deadline, run_budget, clock (see HttpConnector)
    ) -> None:
        super().__init__(
            api_url,
            token,
            api_url=api_url,
            anonymous=anonymous,
            timeout=timeout,
            ca_bundle=ca_bundle,
            max_retries=max_retries,
            backoff_seconds=backoff_seconds,
            max_artifact_bytes=max_artifact_bytes,
            transport=transport,
            sleep=sleep,
            **limits,
            username=username,
            auth_scheme="basic" if username else "bearer",
        )
        self._pipelines: dict[tuple[str, int], dict[str, Any]] = {}

    # ------------------------------------------------------------------ public API

    def get_pipeline(self, project: str, pipeline_id: int) -> Pipeline:
        p = self._pipeline(project, pipeline_id)
        try:
            state = p.get("state") or {}
            status = ((state.get("result") or {}).get("name")) or state.get("name") or "UNKNOWN"
            target = p.get("target") or {}
            return Pipeline(
                id=int(p["build_number"]),
                sha=((target.get("commit") or {}).get("hash")) or "",
                ref=target.get("ref_name"),
                status=str(status).lower(),
                source=(p.get("trigger") or {}).get("type"),
                created_at=p.get("created_on"),
                finished_at=p.get("completed_on"),
            )
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise ConnectorError(ErrorKind.INVALID_RESPONSE, f"Unexpected pipeline: {exc}") from exc

    def list_jobs(self, project: str, pipeline_id: int) -> list[Job]:
        p = self._pipeline(project, pipeline_id)
        pipeline_result = (((p.get("state") or {}).get("result")) or {}).get("name")
        sha = (((p.get("target") or {}).get("commit")) or {}).get("hash")
        path = f"/repositories/{_repo(project)}/pipelines/{quote(str(p['uuid']))}/steps/"
        return [
            self._to_job(s, pipeline_result, sha, int(pipeline_id))
            for s in self._paginate(f"{self.api_url}{path}?pagelen=100", "steps")
        ]

    def fetch_report(
        self, project: str, job: Job, report_path: str, artifact_name: str | None = None
    ) -> bytes:
        """The newest Code Insights report on the job's commit whose title or external id is
        `report_path`, with all of its annotations, as one JSON document for the adapter."""
        if not job.commit_sha:
            raise NotFoundError("The pipeline has no commit to look up reports for", None)
        base = f"{self.api_url}/repositories/{_repo(project)}/commit/{quote(job.commit_sha)}"
        reports = [
            r
            for r in self._paginate(f"{base}/reports?pagelen=100", "Code Insights reports")
            if report_path in (r.get("title"), r.get("external_id"))
        ]
        if not reports:
            raise NotFoundError(
                f"No Code Insights report '{report_path}' on commit {job.commit_sha[:12]}", None
            )
        report = max(reports, key=lambda r: str(r.get("created_on") or ""))
        rid = quote(str(report.get("uuid") or report.get("external_id")))
        notes, complete = [], True
        try:
            for item in self._paginate(f"{base}/reports/{rid}/annotations?pagelen=100", "notes"):
                notes.append(item)
        except ConnectorError as exc:
            if exc.kind is not ErrorKind.LIMIT_EXCEEDED:
                raise
            complete = False
        report.pop("links", None)
        doc = {
            "format": INSIGHTS_FORMAT,
            "report": report,
            "annotations": notes,
            "annotations_complete": complete,
        }
        return json.dumps(doc).encode()

    # ------------------------------------------------------------------ helpers

    def _raise_for_status(self, response: httpx.Response, what: str) -> None:
        self._raise_standard(response, what, self.auth_hint)

    def _pipeline(self, project: str, number: int) -> dict[str, Any]:
        key = (project, int(number))
        if key not in self._pipelines:
            url = f"{self.api_url}/repositories/{_repo(project)}/pipelines/{int(number)}"
            body = self._get_json_capped(url, f"pipeline #{number}")
            if not isinstance(body, dict) or "uuid" not in body:
                raise ConnectorError(ErrorKind.INVALID_RESPONSE, "Unexpected pipeline payload")
            self._pipelines[key] = body
        return self._pipelines[key]

    def _paginate(self, url: str, what: str):
        """Bitbucket pages carry an absolute `next` URL; it must stay on the API origin."""
        seen: set[str] = set()
        for _ in range(MAX_PAGES):
            if url in seen:
                raise ConnectorError(ErrorKind.INVALID_RESPONSE, f"Pagination loop in {what}")
            seen.add(url)
            body = self._get_json_capped(url, what)
            values = body.get("values") if isinstance(body, dict) else None
            if not isinstance(values, list):
                raise ConnectorError(ErrorKind.INVALID_RESPONSE, f"Unexpected page of {what}")
            yield from (v for v in values if isinstance(v, dict))
            nxt = body.get("next")
            if not nxt:
                return
            if origin_of(str(nxt)) != self._origin:
                raise ConnectorError(ErrorKind.UNSAFE_REDIRECT, "Pagination left the API origin")
            url = str(nxt)
        raise ConnectorError(ErrorKind.LIMIT_EXCEEDED, f"More than {MAX_PAGES} pages of {what}")

    def _to_job(
        self, s: dict[str, Any], pipeline_result: str | None, sha: str | None, number: int
    ) -> Job:
        try:
            state = s.get("state") or {}
            name = str(state.get("name"))
            result = (state.get("result") or {}).get("name")
            if name == "COMPLETED":
                status = _RESULT.get(str(result), JobStatus.UNKNOWN)
            else:
                status = _STATE.get(name, JobStatus.UNKNOWN)
                manual = "manual" in str((s.get("trigger") or {}).get("type", ""))
                if status is JobStatus.PENDING and manual:
                    status = JobStatus.MANUAL
            raw = str(result or name).lower()
            allow_failure = False
            if status is JobStatus.FAILED and pipeline_result not in ("FAILED", "ERROR"):
                allow_failure = True
                raw = f"{raw}, but the pipeline did not fail (on-fail: strategy: ignore)"
            step_uuid = str(s["uuid"])
            return Job(
                id=uuid.UUID(step_uuid.strip("{}")).int % (2**53),
                ref=step_uuid,
                name=str(s.get("name") or "(unnamed step)"),
                status=status,
                raw_status=raw,
                allow_failure=allow_failure,
                commit_sha=sha,
                pipeline_id=number,
                started_at=s.get("started_on"),
                finished_at=s.get("completed_on"),
                attempt=s.get("run_number"),
            )
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise ConnectorError(ErrorKind.INVALID_RESPONSE, f"Unexpected step: {exc}") from exc


def _repo(project: str) -> str:
    project = str(project).strip()
    if not _REPO.match(project):
        raise ConnectorError(
            ErrorKind.INVALID_RESPONSE, f"Bitbucket repository must be workspace/repo: {project!r}"
        )
    workspace, repo = project.split("/")
    return f"{quote(workspace)}/{quote(repo)}"
