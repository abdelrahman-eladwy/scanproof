"""Collect real, sanitized Azure DevOps build API responses from a PUBLIC project (anonymous).

Usage: python scripts/collect_azure_devops.py OUT_DIR ORG PROJECT
Writes builds/<id>/{build,timeline,artifacts}.json for a few builds per result, plus summary.json
(which record results occur per record type, and builds where a failed task did not fail its job).
Only whitelisted fields are kept: no people (requestedBy/For, lastChangedBy), avatars or logs.
"""

# ruff: noqa: S310 - collectors only open fixed https hosts (or the local contract Jenkins)

from __future__ import annotations

import io
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import Counter
from pathlib import Path

API = "api-version=7.1"
MAX = 20 * 1024 * 1024

BUILD_KEYS = {
    "id",
    "buildNumber",
    "status",
    "result",
    "queueTime",
    "startTime",
    "finishTime",
    "sourceBranch",
    "sourceVersion",
    "reason",
    "url",
    "retainedByRelease",
}
RECORD_KEYS = {
    "id",
    "parentId",
    "type",
    "name",
    "identifier",
    "state",
    "result",
    "order",
    "startTime",
    "finishTime",
    "errorCount",
    "warningCount",
    "attempt",
    "previousAttempts",
    "refName",
    "percentComplete",
}


def get(url: str) -> object:
    req = urllib.request.Request(
        url, headers={"Accept": "application/json", "User-Agent": "scanproof-fixtures"}
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read(MAX + 1)
    if len(data) > MAX:
        raise ValueError("response too large")
    return json.loads(data)


def build_view(b: dict) -> dict:
    out = {k: b[k] for k in BUILD_KEYS if k in b}
    out["definition"] = {k: b.get("definition", {}).get(k) for k in ("id", "name")}
    out["project"] = {k: b.get("project", {}).get(k) for k in ("id", "name")}
    out["_links"] = {"web": b.get("_links", {}).get("web")}
    return out


def record_view(r: dict) -> dict:
    out = {k: r[k] for k in RECORD_KEYS if k in r}
    out["issues"] = [
        {"type": i.get("type"), "message": (i.get("message") or "")[:300]}
        for i in (r.get("issues") or [])[:5]
    ]
    return out


def artifact_view(a: dict) -> dict:
    res = a.get("resource") or {}
    return {
        "id": a.get("id"),
        "name": a.get("name"),
        "source": a.get("source"),
        "resource": {
            "type": res.get("type"),
            "data": res.get("data"),
            "url": res.get("url"),
            "downloadUrl": res.get("downloadUrl"),
            "properties": {
                k: v
                for k, v in (res.get("properties") or {}).items()
                if k in ("artifactsize", "RootId", "HashType")
            },
        },
    }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # record redirects instead of following
        return None


def probe_download(d: Path, arts: dict, summary: dict) -> None:
    """How artifact downloads behave: status, redirect target host, content type, size."""
    for a in arts.get("value", [])[:2]:
        api = (a.get("resource") or {}).get("url")
        if api:  # the API-origin route: does it redirect to a signed URL?
            opener = urllib.request.build_opener(_NoRedirect)
            try:
                with opener.open(
                    urllib.request.Request(
                        api + "&%24format=zip", headers={"User-Agent": "scanproof-fixtures"}
                    ),
                    timeout=60,
                ) as r:
                    body = r.read(3 * 1024 * 1024 + 1)
                    entry = {
                        "artifact": a.get("name"),
                        "status": r.status,
                        "content_type": r.headers.get("Content-Type"),
                        "zip": body[:2] == b"PK",
                    }
                    if body[:2] == b"PK" and len(body) <= 3 * 1024 * 1024:
                        with zipfile.ZipFile(io.BytesIO(body)) as zf:
                            entry["names"] = zf.namelist()[:15]
                    summary.setdefault("api_zip", []).append(entry)
            except urllib.error.HTTPError as e:
                loc = urllib.parse.urlsplit(e.headers.get("Location") or "")
                summary.setdefault("api_zip", []).append(
                    {
                        "artifact": a.get("name"),
                        "status": e.code,
                        "redirect_host": loc.hostname,
                        "redirect_query_keys": sorted(urllib.parse.parse_qs(loc.query)),
                    }
                )
            except Exception as exc:
                summary.setdefault("api_zip", []).append(
                    {"artifact": a.get("name"), "error": type(exc).__name__}
                )
        url = (a.get("resource") or {}).get("downloadUrl")
        if not url:
            continue
        opener = urllib.request.build_opener(_NoRedirect)
        try:
            with opener.open(
                urllib.request.Request(url, headers={"User-Agent": "scanproof-fixtures"}),
                timeout=60,
            ) as r:
                head = r.read(2048)
                summary.setdefault("downloads", []).append(
                    {
                        "artifact": a.get("name"),
                        "status": r.status,
                        "content_type": r.headers.get("Content-Type"),
                        "length": r.headers.get("Content-Length"),
                        "zip": head[:2] == b"PK",
                    }
                )
        except urllib.error.HTTPError as e:
            loc = e.headers.get("Location") or ""
            summary.setdefault("downloads", []).append(
                {
                    "artifact": a.get("name"),
                    "status": e.code,
                    "redirect_host": urllib.parse.urlsplit(loc).hostname,
                    "url_host": urllib.parse.urlsplit(url).hostname,
                }
            )
        except Exception as exc:
            summary.setdefault("downloads", []).append(
                {"artifact": a.get("name"), "error": type(exc).__name__}
            )


def main(out: Path, org: str, project: str) -> None:
    base = f"https://dev.azure.com/{org}/{project}/_apis/build"
    summary: dict = {
        "org": org,
        "project": project,
        "record_results": {},
        "masked": [],
        "notes": [],
    }
    results: Counter = Counter()
    saved = 0
    for result_filter in ("partiallySucceeded", "succeeded", "failed", "canceled"):
        try:
            builds = get(
                f"{base}/builds?resultFilter={result_filter}&$top=15&queryOrder=finishTimeDescending&{API}"
            )["value"]
        except Exception as exc:  # record and continue: this is a collector
            summary["notes"].append(f"list {result_filter}: {type(exc).__name__}: {exc}")
            continue
        kept = 0
        for b in builds:
            try:
                tl = get(f"{base}/builds/{b['id']}/timeline?{API}")
            except Exception as exc:
                summary["notes"].append(f"timeline {b['id']}: {type(exc).__name__}")
                continue
            records = (tl or {}).get("records") or []
            by_id = {r["id"]: r for r in records}
            for r in records:
                results[f"{r.get('type')}:{r.get('result')}"] += 1
            masked = []
            for r in records:
                if r.get("type") == "Task" and r.get("result") in ("failed", "succeededWithIssues"):
                    job = by_id.get(r.get("parentId"), {})
                    masked.append(
                        {
                            "task": r.get("name"),
                            "task_result": r.get("result"),
                            "job": job.get("name"),
                            "job_result": job.get("result"),
                        }
                    )
            interesting = result_filter != "partiallySucceeded" or any(
                m["job_result"] in ("succeeded", "succeededWithIssues") for m in masked
            )
            if not interesting or kept >= 2:
                continue
            d = out / "builds" / str(b["id"])
            d.mkdir(parents=True, exist_ok=True)
            (d / "build.json").write_text(json.dumps(build_view(b), indent=1))
            (d / "timeline.json").write_text(
                json.dumps(
                    {
                        "id": tl.get("id"),
                        "changeId": tl.get("changeId"),
                        "records": [record_view(r) for r in records],
                    },
                    indent=1,
                )
            )
            prev_ids = {
                str(pa.get("timelineId"))
                for r in records
                if r.get("type") == "Job"
                for pa in (r.get("previousAttempts") or [])
                if pa.get("timelineId")
            }
            for tid in sorted(prev_ids)[:5]:  # earlier attempts of re-run jobs
                try:
                    old = get(f"{base}/builds/{b['id']}/timeline/{tid}?{API}")
                    (d / f"timeline-{tid}.json").write_text(
                        json.dumps(
                            {
                                "id": old.get("id"),
                                "records": [record_view(r) for r in old.get("records") or []],
                            },
                            indent=1,
                        )
                    )
                except Exception as exc:
                    summary["notes"].append(
                        f"previous timeline {b['id']}/{tid}: {type(exc).__name__}"
                    )
            try:
                arts = get(f"{base}/builds/{b['id']}/artifacts?{API}")
                (d / "artifacts.json").write_text(
                    json.dumps(
                        {
                            "count": arts.get("count"),
                            "value": [artifact_view(a) for a in arts.get("value", [])],
                        },
                        indent=1,
                    )
                )
            except Exception as exc:
                summary["notes"].append(f"artifacts {b['id']}: {type(exc).__name__}")
            if saved == 0 and (d / "artifacts.json").exists():
                probe_download(d, json.loads((d / "artifacts.json").read_text()), summary)
            if masked:
                summary["masked"].append(
                    {"build": b["id"], "result": b.get("result"), "tasks": masked[:10]}
                )
            kept += 1
            saved += 1
    summary["record_results"] = dict(sorted(results.items()))
    summary.setdefault("downloads", [])
    summary.setdefault("api_zip", [])
    summary["saved_builds"] = saved
    (out / "summary.json").write_text(json.dumps(summary, indent=1))
    print(json.dumps({k: summary[k] for k in ("record_results", "saved_builds")})[:3000])


if __name__ == "__main__":
    main(Path(sys.argv[1]), sys.argv[2], sys.argv[3])
