"""A tiny scriptable GitLab API double built on respx, for scenario tests."""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx
import respx

API = "https://gitlab.example.com/api/v4"
SHA = "a1b2c3d4e5f60718293a4b5c6d7e8f9001122334"


@dataclass
class FakeJob:
    id: int
    name: str
    status: str = "success"
    allow_failure: bool = False
    sha: str | None = SHA
    archive: bool = True
    # artifact path -> bytes (served) or int (HTTP status to return)
    files: dict[str, bytes | int] = field(default_factory=dict)

    def as_api(self) -> dict:
        artifacts = [{"file_type": "trace", "filename": "job.log", "size": 10}]
        if self.archive:
            artifacts.append({"file_type": "archive", "filename": "artifacts.zip", "size": 100})
        return {
            "id": self.id,
            "name": self.name,
            "stage": "security",
            "status": self.status,
            "allow_failure": self.allow_failure,
            "commit": {"id": self.sha} if self.sha else {},
            "pipeline": {"id": 1042},
            "artifacts": artifacts,
        }


@dataclass
class FakeGitLab:
    router: respx.MockRouter
    project: str = "123"
    pipeline_id: int = 1042
    sha: str = SHA
    ref: str = "main"
    pipeline_status: int | None = None  # set to e.g. 403 to fail the pipeline call
    jobs: list[FakeJob] = field(default_factory=list)

    def job(self, *args, **kwargs) -> FakeJob:
        j = FakeJob(*args, **kwargs)
        self.jobs.append(j)
        return j

    def install(self) -> None:
        base = f"{API}/projects/{self.project}"
        pipeline_route = self.router.get(f"{base}/pipelines/{self.pipeline_id}")
        if self.pipeline_status:
            pipeline_route.respond(self.pipeline_status)
        else:
            pipeline_route.respond(
                json={"id": self.pipeline_id, "sha": self.sha, "ref": self.ref, "status": "success"}
            )
        self.router.get(f"{base}/pipelines/{self.pipeline_id}/jobs").respond(
            json=[j.as_api() for j in self.jobs]
        )
        for j in self.jobs:
            for path, payload in j.files.items():
                route = self.router.get(f"{base}/jobs/{j.id}/artifacts/{path}")
                if isinstance(payload, int):
                    route.respond(payload)
                else:
                    route.mock(return_value=httpx.Response(200, content=payload))
            # anything not scripted is "not in the archive"
            self.router.get(url__regex=rf"{base}/jobs/{j.id}/artifacts/.*").respond(404)
