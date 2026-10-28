"""A scriptable GitHub Actions API double built on respx, for scenario tests.

Shapes follow the real API responses in tests/fixtures/github-real/: runs, jobs (with attempts),
run artifacts (zip + sha256 digest, 302 to blob storage), check-run annotations with Link
pagination, and the attestations API (cursor pagination via Link).
"""

from __future__ import annotations

import hashlib
import io
import zipfile
from dataclasses import dataclass, field

import httpx

API = "https://api.github.com"
REPO = "acme/app"
RUN = 77
SHA = "c" * 40
EXIT1 = {"annotation_level": "failure", "message": "Process completed with exit code 1."}


def zip_of(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


@dataclass
class FakeGitHub:
    router: object
    repo: str = REPO
    run_id: int = RUN
    sha: str = SHA
    run_conclusion: str | None = "success"
    run_attempt: int = 1
    run_started_at: str | None = None
    jobs: list[dict] = field(default_factory=list)
    annotations: dict[int, list] = field(default_factory=dict)  # job id -> pages / HTTP status
    artifacts: list[dict] = field(default_factory=list)
    blobs: dict[int, bytes] = field(default_factory=dict)
    # sha256 hex -> pages of bundles (each page a list of bundle dicts) or an HTTP status
    attestations: dict[str, list | int] = field(default_factory=dict)

    def job(
        self,
        jid,
        name,
        conclusion="success",
        attempt=1,
        notes=None,
        status="completed",
        started_at=None,
    ):
        self.jobs.append(
            {
                "id": jid,
                "run_id": self.run_id,
                "run_attempt": attempt,
                "head_sha": self.sha,
                "name": name,
                "status": status,
                "conclusion": conclusion,
                "started_at": started_at,
                "check_run_url": f"{API}/repos/{self.repo}/check-runs/{jid}",
            }
        )
        self.annotations[jid] = notes if notes is not None else [[]]

    def artifact(self, aid, name, files, *, digest=True):
        data = zip_of(files)
        self.artifacts.append(
            {
                "id": aid,
                "name": name,
                "expired": False,
                "size_in_bytes": len(data),
                "digest": "sha256:" + hashlib.sha256(data).hexdigest() if digest else None,
            }
        )
        self.blobs[aid] = data

    def install(self):
        r, repo, run = self.router, self.repo, self.run_id
        r.get(f"{API}/repos/{repo}/actions/runs/{run}").respond(
            json={
                "id": run,
                "run_attempt": self.run_attempt,
                "run_started_at": self.run_started_at,
                "head_sha": self.sha,
                "head_branch": "main",
                "event": "push",
                "status": "completed" if self.run_conclusion else "in_progress",
                "conclusion": self.run_conclusion,
                "html_url": f"https://github.com/{repo}/actions/runs/{run}",
            }
        )
        r.get(f"{API}/repos/{repo}/actions/runs/{run}/jobs").respond(json={"jobs": self.jobs})
        r.get(f"{API}/repos/{repo}/actions/runs/{run}/artifacts").respond(
            json={"artifacts": self.artifacts}
        )
        for aid, data in self.blobs.items():
            blob = f"https://blob.example.net/{aid}.zip"
            r.get(f"{API}/repos/{repo}/actions/artifacts/{aid}/zip").respond(
                302, headers={"Location": blob}
            )
            r.get(blob).respond(content=data)

        def annotations(request: httpx.Request) -> httpx.Response:
            jid = int(request.url.path.split("/")[-2])
            pages = self.annotations[jid]
            n = int(request.url.params.get("page", "1"))
            page = pages[n - 1]
            if isinstance(page, int):
                return httpx.Response(page)
            headers = {}
            if n < len(pages):
                url = f"{API}/repos/{repo}/check-runs/{jid}/annotations?per_page=100&page={n + 1}"
                headers["Link"] = f'<{url}>; rel="next"'
            return httpx.Response(200, json=page, headers=headers)

        r.get(url__regex=rf"{API}/repos/{repo}/check-runs/\d+/annotations").mock(
            side_effect=annotations
        )

        def attestations(request: httpx.Request) -> httpx.Response:
            digest = request.url.path.rsplit("sha256:", 1)[-1]
            pages = self.attestations.get(digest, 404)
            if isinstance(pages, int):
                return httpx.Response(pages, json={"message": "Not Found"})
            n = int(request.url.params.get("after", "1"))
            headers = {}
            if n < len(pages):
                url = f"{API}/repos/{repo}/attestations/sha256:{digest}?per_page=100&after={n + 1}"
                headers["Link"] = f'<{url}>; rel="next"'
            items = [{"bundle": b, "repository_id": 1, "bundle_url": None} for b in pages[n - 1]]
            return httpx.Response(200, json={"attestations": items}, headers=headers)

        r.get(url__regex=rf"{API}/repos/{repo}/attestations/sha256:[0-9a-f]+").mock(
            side_effect=attestations
        )
