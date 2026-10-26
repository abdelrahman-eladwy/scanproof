"""Collect REAL GitLab parent/child pipeline data (bridges API) from public gitlab.com projects.

Anonymous, read-only, stdlib only. Writes sanitized output (allow-listed fields, no user data):
  <slug>/pipeline.json, <slug>/jobs.json, <slug>/bridges.json,
  <slug>/child-<id>/pipeline.json + jobs.json for each downstream pipeline (max 3)
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

API = "https://gitlab.com/api/v4"
UA = {
    "User-Agent": "scanproof-contract-collector (+https://github.com/abdelrahman-eladwy/scanproof)"
}
CANDIDATES = ["gitlab-org/gitlab-runner", "gitlab-org/gitaly", "gitlab-org/gitlab"]
JOB_KEYS = {
    "id",
    "name",
    "stage",
    "status",
    "allow_failure",
    "ref",
    "created_at",
    "started_at",
    "finished_at",
    "artifacts",
    "web_url",
}
PIPE_KEYS = {
    "id",
    "iid",
    "project_id",
    "sha",
    "ref",
    "status",
    "source",
    "created_at",
    "finished_at",
    "web_url",
}


def get(path: str):
    url = path if path.startswith("https://") else f"{API}{path}"
    if not url.startswith("https://gitlab.com/"):
        raise ValueError(url)
    req = urllib.request.Request(url, headers=UA)  # noqa: S310 - fixed https host
    try:
        with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return {"_error": e.code}


def job(j):
    out = {k: v for k, v in j.items() if k in JOB_KEYS}
    out["commit"] = {"id": (j.get("commit") or {}).get("id")}
    out["pipeline"] = {k: (j.get("pipeline") or {}).get(k) for k in ("id", "project_id", "sha")}
    return out


def bridge(b):
    out = {k: b.get(k) for k in ("id", "name", "stage", "status", "allow_failure")}
    ds = b.get("downstream_pipeline")
    out["downstream_pipeline"] = None if not ds else {k: ds.get(k) for k in PIPE_KEYS}
    out["commit"] = {"id": (b.get("commit") or {}).get("id")}
    return out


def main() -> None:
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    summary = []
    for project in CANDIDATES:
        enc = urllib.parse.quote(project, safe="")
        pipes = get(f"/projects/{enc}/pipelines?status=success&per_page=20")
        if not isinstance(pipes, list):
            summary.append({"project": project, "error": pipes})
            continue
        for p in pipes:
            bridges = get(f"/projects/{enc}/pipelines/{p['id']}/bridges?per_page=100")
            if not isinstance(bridges, list) or not any(
                b.get("downstream_pipeline") for b in bridges
            ):
                continue
            d = out / project.split("/")[-1]
            d.mkdir(exist_ok=True)
            pipe = get(f"/projects/{enc}/pipelines/{p['id']}")
            (d / "pipeline.json").write_text(
                json.dumps({k: v for k, v in pipe.items() if k in PIPE_KEYS}, indent=2)
            )
            jobs = get(
                f"/projects/{enc}/pipelines/{p['id']}/jobs?include_retried=true&per_page=100"
            )
            (d / "jobs.json").write_text(
                json.dumps([job(j) for j in jobs] if isinstance(jobs, list) else jobs, indent=2)
            )
            (d / "bridges.json").write_text(json.dumps([bridge(b) for b in bridges], indent=2))
            children = []
            for b in [b for b in bridges if b.get("downstream_pipeline")][:3]:
                ds = b["downstream_pipeline"]
                cenc = ds["project_id"]
                cp = get(f"/projects/{cenc}/pipelines/{ds['id']}")
                cj = get(
                    f"/projects/{cenc}/pipelines/{ds['id']}/jobs?include_retried=true&per_page=100"
                )
                cd = d / f"child-{ds['id']}"
                cd.mkdir(exist_ok=True)
                (cd / "pipeline.json").write_text(
                    json.dumps(
                        {k: v for k, v in cp.items() if k in PIPE_KEYS}
                        if isinstance(cp, dict)
                        else cp,
                        indent=2,
                    )
                )
                (cd / "jobs.json").write_text(
                    json.dumps([job(j) for j in cj] if isinstance(cj, list) else cj, indent=2)
                )
                children.append(
                    {
                        "bridge": b["name"],
                        "child": ds["id"],
                        "child_project": ds["project_id"],
                        "same_project": ds["project_id"] == p.get("project_id", info_id(enc)),
                        "same_sha": ds.get("sha") == p.get("sha"),
                        "child_jobs": len(cj) if isinstance(cj, list) else cj,
                    }
                )
            summary.append(
                {
                    "project": project,
                    "pipeline": p["id"],
                    "bridges": len(bridges),
                    "children": children,
                }
            )
            break
        else:
            summary.append({"project": project, "error": "no recent pipeline with child pipelines"})
    (out / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


def info_id(enc: str):
    info = get(f"/projects/{enc}")
    return info.get("id") if isinstance(info, dict) else None


if __name__ == "__main__":
    main()
