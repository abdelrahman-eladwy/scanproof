"""A scriptable GitLab API double built on respx, for scenario tests.

Supports a root pipeline plus child / multi-project downstream pipelines (bridges), unreadable
children, triggers that never started a pipeline, artifacts per job and per project, and
fault injection on any artifact (HTTP status, or a callable for custom responses).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

import httpx
import respx

API = "https://gitlab.example.com/api/v4"
SHA = "a1b2c3d4e5f60718293a4b5c6d7e8f9001122334"

Payload = bytes | int | Callable[[httpx.Request], httpx.Response]


@dataclass
class FakeJob:
    id: int
    name: str
    status: str = "success"
    allow_failure: bool = False
    sha: str | None = SHA
    archive: bool = True
    stage: str = "security"
    # artifact path -> bytes (served), int (HTTP status), or callable(request) -> Response
    files: dict[str, Payload] = field(default_factory=dict)

    def as_api(self, pipeline_id: int) -> dict:
        artifacts = [{"file_type": "trace", "filename": "job.log", "size": 10}]
        if self.archive:
            artifacts.append({"file_type": "archive", "filename": "artifacts.zip", "size": 100})
        return {
            "id": self.id,
            "name": self.name,
            "stage": self.stage,
            "status": self.status,
            "allow_failure": self.allow_failure,
            "commit": {"id": self.sha} if self.sha else {},
            "pipeline": {"id": pipeline_id},
            "artifacts": artifacts,
        }


@dataclass
class FakePipeline:
    project: str
    pipeline_id: int
    sha: str = SHA
    readable: bool = True  # False -> its jobs endpoint returns 403
    jobs: list[FakeJob] = field(default_factory=list)
    children: list[tuple[str, FakePipeline | None, str]] = field(default_factory=list)

    def job(self, *args, **kwargs) -> FakeJob:
        j = FakeJob(*args, **kwargs)
        self.jobs.append(j)
        return j

    def child(
        self,
        trigger: str,
        *,
        project: str | None = None,
        pipeline_id: int,
        sha: str | None = None,
        readable: bool = True,
    ) -> FakePipeline:
        c = FakePipeline(
            project=project or self.project,
            pipeline_id=pipeline_id,
            sha=sha or self.sha,
            readable=readable,
        )
        self.children.append((trigger, c, "success"))
        return c

    def failed_trigger(self, trigger: str) -> None:
        self.children.append((trigger, None, "failed"))


@dataclass
class FakeGitLab:
    router: respx.MockRouter
    project: str = "123"
    pipeline_id: int = 1042
    sha: str = SHA
    ref: str = "main"
    pipeline_status: int | None = None  # set to e.g. 403 to fail the pipeline call
    jobs_pages: int = 1  # serve the root jobs over this many pages
    jobs: list[FakeJob] = field(default_factory=list)
    root: FakePipeline | None = None

    def __post_init__(self) -> None:
        self.root = FakePipeline(self.project, self.pipeline_id, self.sha, jobs=self.jobs)

    def job(self, *args, **kwargs) -> FakeJob:
        return self.root.job(*args, **kwargs)

    def child(self, trigger: str, **kwargs) -> FakePipeline:
        return self.root.child(trigger, **kwargs)

    def failed_trigger(self, trigger: str) -> None:
        self.root.failed_trigger(trigger)

    # ------------------------------------------------------------------ routes

    def install(self) -> None:
        self.root.sha = self.sha
        base = f"{API}/projects/{self.project}"
        pipeline_route = self.router.get(f"{base}/pipelines/{self.pipeline_id}")
        if self.pipeline_status:
            pipeline_route.respond(self.pipeline_status)
        else:
            pipeline_route.respond(
                json={"id": self.pipeline_id, "sha": self.sha, "ref": self.ref, "status": "success"}
            )

        bridges: dict[tuple[str, int], list[dict]] = {}
        stack = [self.root]
        while stack:
            pipe = stack.pop()
            self._install_pipeline(pipe, paged=pipe is self.root)
            entries = []
            for i, (trigger, child, status) in enumerate(pipe.children):
                downstream = None
                if child is not None:
                    downstream = {
                        "id": child.pipeline_id,
                        "project_id": int(child.project) if child.project.isdigit() else 999,
                        "sha": child.sha,
                        "status": "success",
                    }
                    stack.append(child)
                entries.append(
                    {
                        "id": 900000 + i,
                        "name": trigger,
                        "status": status,
                        "downstream_pipeline": downstream,
                    }
                )
            bridges[(pipe.project, pipe.pipeline_id)] = entries
        # Any artifact path not scripted above is "not in the archive". One route, added last
        # (respx matches in order), so large pipelines don't pay a regex per job per request.
        self.router.get(url__regex=r".*/projects/[^/]+/jobs/\d+/artifacts/.*").respond(404)

        def serve_bridges(request: httpx.Request) -> httpx.Response:
            m = re.search(r"/projects/([^/]+)/pipelines/(\d+)/bridges", request.url.path)
            return httpx.Response(200, json=bridges.get((m.group(1), int(m.group(2))), []))

        if "bridges" in self.router.routes:
            self.router.routes["bridges"].mock(side_effect=serve_bridges)
        else:
            self.router.get(url__regex=r".*/pipelines/\d+/bridges", name="bridges").mock(
                side_effect=serve_bridges
            )

    def _install_pipeline(self, pipe: FakePipeline, *, paged: bool) -> None:
        base = f"{API}/projects/{pipe.project}"
        jobs_route = self.router.get(f"{base}/pipelines/{pipe.pipeline_id}/jobs")
        if not pipe.readable:
            jobs_route.respond(403)
        else:
            payload = [j.as_api(pipe.pipeline_id) for j in pipe.jobs]
            pages = self.jobs_pages if paged else 1
            size = max(1, -(-len(payload) // pages))
            chunks = [payload[i : i + size] for i in range(0, len(payload), size)] or [[]]

            def serve_jobs(request: httpx.Request, chunks=chunks) -> httpx.Response:
                n = int(request.url.params.get("page", "1"))
                nxt = str(n + 1) if n < len(chunks) else ""
                return httpx.Response(200, json=chunks[n - 1], headers={"x-next-page": nxt})

            jobs_route.mock(side_effect=serve_jobs)
        for j in pipe.jobs:
            for path, payload in j.files.items():
                route = self.router.get(f"{base}/jobs/{j.id}/artifacts/{path}")
                if isinstance(payload, int):
                    route.respond(payload)
                elif callable(payload):
                    route.mock(side_effect=payload)
                else:
                    route.mock(return_value=httpx.Response(200, content=payload))
