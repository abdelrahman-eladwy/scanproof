"""Collect REAL GitLab API responses and security reports from public gitlab.com projects.

Run in CI (see .github/workflows/gitlab-contract.yml). Anonymous, read-only, stdlib only.
Writes sanitized fixtures to OUT_DIR:

  <slug>/pipeline.json            pipeline (allow-listed fields only)
  <slug>/jobs.json                all job attempts (allow-listed fields; no user/runner/author)
  <slug>/reports/<job>-<type>.json  security reports, if downloadable
  summary.json                    what was found and which download routes worked

Personal data (user objects, commit author names/emails, runner details) is never written.
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

GITLAB = "https://gitlab.com"
API = f"{GITLAB}/api/v4"
UA = {
    "User-Agent": "scanproof-contract-collector (+https://github.com/abdelrahman-eladwy/scanproof)"
}

CANDIDATES = [
    "gitlab-org/security-products/analyzers/semgrep",
    "gitlab-org/security-products/analyzers/container-scanning",
    "gitlab-org/cli",
    "gitlab-org/gitlab-runner",
]
REPORT_TYPES = {
    "sast": "gl-sast-report.json",
    "container_scanning": "gl-container-scanning-report.json",
    "dependency_scanning": "gl-dependency-scanning-report.json",
    "secret_detection": "gl-secret-detection-report.json",
}
MAX_REPORT_BYTES = 5 * 1024 * 1024
JOB_KEYS = {
    "id",
    "name",
    "stage",
    "status",
    "allow_failure",
    "ref",
    "tag",
    "created_at",
    "started_at",
    "finished_at",
    "duration",
    "artifacts",
    "artifacts_expire_at",
    "web_url",
    "failure_reason",
}
PIPELINE_KEYS = {
    "id",
    "iid",
    "project_id",
    "sha",
    "ref",
    "status",
    "source",
    "created_at",
    "updated_at",
    "started_at",
    "finished_at",
    "web_url",
    "tag",
}


def get(url: str, *, raw: bool = False, limit: int | None = None):
    if not url.startswith("https://gitlab.com/"):
        raise ValueError(f"refusing non-gitlab.com URL: {url}")
    req = urllib.request.Request(url, headers=UA)  # noqa: S310 - scheme/host checked above
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 - fixed https host
                body = resp.read(limit + 1 if limit else -1)
                if limit and len(body) > limit:
                    raise ValueError("too large")
                headers = dict(resp.headers)
                return (body if raw else json.loads(body)), headers, resp.status
        except urllib.error.HTTPError as exc:
            if exc.code in (429, 502, 503, 504) and attempt < 3:
                time.sleep(2 * (attempt + 1))
                continue
            return None, dict(exc.headers or {}), exc.code
    return None, {}, 0


def sanitize_job(job: dict) -> dict:
    out = {k: v for k, v in job.items() if k in JOB_KEYS}
    commit = job.get("commit") or {}
    out["commit"] = {"id": commit.get("id"), "short_id": commit.get("short_id")}
    pipeline = job.get("pipeline") or {}
    out["pipeline"] = {k: pipeline.get(k) for k in ("id", "project_id", "sha", "ref", "status")}
    return out


def collect(project: str, out_dir: Path, summary: list) -> None:
    enc = urllib.parse.quote(project, safe="")
    info, _, code = get(f"{API}/projects/{enc}")
    if not info:
        summary.append({"project": project, "error": f"project HTTP {code}"})
        return
    branch = info.get("default_branch")
    pipes, _, code = get(
        f"{API}/projects/{enc}/pipelines?ref={urllib.parse.quote(branch)}&status=success&per_page=5"
    )
    if not pipes:
        summary.append({"project": project, "error": f"pipelines HTTP {code}"})
        return

    for pipe in pipes:
        jobs, page = [], 1
        while page and page <= 20:
            batch, headers, code = get(
                f"{API}/projects/{enc}/pipelines/{pipe['id']}/jobs"
                f"?include_retried=true&per_page=100&page={page}"
            )
            if batch is None:
                break
            jobs.extend(batch)
            nxt = {k.lower(): v for k, v in headers.items()}.get("x-next-page", "")
            page = int(nxt) if nxt.strip() else 0
        report_jobs = [
            j
            for j in jobs
            if any(a.get("file_type") in REPORT_TYPES for a in j.get("artifacts") or [])
        ]
        if not report_jobs:
            continue

        slug = project.split("/")[-1]
        d = out_dir / slug
        (d / "reports").mkdir(parents=True, exist_ok=True)
        full_pipe, _, _ = get(f"{API}/projects/{enc}/pipelines/{pipe['id']}")
        (d / "pipeline.json").write_text(
            json.dumps(
                {k: v for k, v in (full_pipe or pipe).items() if k in PIPELINE_KEYS}, indent=2
            )
        )
        (d / "jobs.json").write_text(json.dumps([sanitize_job(j) for j in jobs], indent=2))

        entry = {
            "project": project,
            "project_id": info["id"],
            "pipeline_id": pipe["id"],
            "jobs": len(jobs),
            "retried_names": sorted(
                {j["name"] for j in jobs if sum(x["name"] == j["name"] for x in jobs) > 1}
            )[:10],
            "report_jobs": [],
        }
        for job in report_jobs[:8]:
            types = [a["file_type"] for a in job["artifacts"] if a.get("file_type") in REPORT_TYPES]
            has_archive = any(a.get("file_type") == "archive" for a in job["artifacts"])
            for ftype in types:
                fname = REPORT_TYPES[ftype]
                routes = {
                    "api_archive_path": f"{API}/projects/{enc}/jobs/{job['id']}/artifacts/{fname}",
                    "ui_file_type": (
                        f"{GITLAB}/{project}/-/jobs/{job['id']}/artifacts/download"
                        f"?file_type={ftype}"
                    ),
                }
                results = {}
                for route, url in routes.items():
                    body, headers, code = get(url, raw=True, limit=MAX_REPORT_BYTES)
                    ctype = {k.lower(): v for k, v in headers.items()}.get("content-type", "")
                    results[route] = {
                        "status": code,
                        "content_type": ctype,
                        "bytes": len(body or b""),
                    }
                    if body and code == 200 and route == "api_archive_path":
                        (d / "reports" / f"{job['name']}-{ftype}.json").write_bytes(body)
                    if body and code == 200 and route == "ui_file_type":
                        suffix = "json" if body[:1] in (b"{", b"[") else "bin"
                        (d / "reports" / f"{job['name']}-{ftype}.ui.{suffix}").write_bytes(body)
                entry["report_jobs"].append(
                    {
                        "job": job["name"],
                        "job_id": job["id"],
                        "status": job["status"],
                        "file_type": ftype,
                        "has_archive": has_archive,
                        "routes": results,
                    }
                )
        summary.append(entry)
        return  # one pipeline per project is enough
    summary.append({"project": project, "error": "no recent pipeline with security reports"})


def main() -> None:
    out_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "gitlab-contract")
    out_dir.mkdir(parents=True, exist_ok=True)
    summary: list = []
    for project in CANDIDATES:
        try:
            collect(project, out_dir, summary)
        except Exception as exc:  # keep going; record what failed
            summary.append({"project": project, "error": f"{type(exc).__name__}: {exc}"})
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
