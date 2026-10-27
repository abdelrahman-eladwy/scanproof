"""Run every pipeline on the throwaway contract Jenkins and save its REST API responses.

Usage: SCANPROOF_JENKINS_PASSWORD=... python scripts/collect_jenkins.py OUT_DIR [BASE_URL]
Saves <job>/{build,wfapi,graph}.json, stage node describes and archived artifacts' listing.
"""

# ruff: noqa: S310 - collectors only open fixed https hosts (or the local contract Jenkins)

from __future__ import annotations

import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request
from http.cookiejar import CookieJar
from pathlib import Path

JOBS = [
    "sast-ok",
    "sast-masked",
    "sast-unstable",
    "sast-skipped",
    "sast-failed",
    "sast-parallel",
    "sast-matrix",
    "sast-retry",
    "sast-trycatch",
]
BASE = sys.argv[2] if len(sys.argv) > 2 else "http://localhost:8080"
AUTH = (
    "Basic "
    + base64.b64encode(f"scanproof:{os.environ['SCANPROOF_JENKINS_PASSWORD']}".encode()).decode()
)
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()))


def req(path: str, method: str = "GET", headers: dict | None = None) -> tuple[int, bytes, dict]:
    r = urllib.request.Request(
        BASE + path, method=method, headers={"Authorization": AUTH, **(headers or {})}
    )
    try:
        with opener.open(r, timeout=60) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)


def wait_up() -> str:
    for _ in range(120):
        try:
            code, _, headers = req("/api/json")
            if code == 200:
                return headers.get("X-Jenkins", "?")
        except OSError:
            pass
        time.sleep(5)
    raise SystemExit("Jenkins did not come up")


def main(out: Path) -> None:
    version = wait_up()
    for _ in range(60):  # job-dsl seed runs at startup
        code, body, _ = req("/api/json?tree=jobs[name]")
        names = {j["name"] for j in json.loads(body)["jobs"]} if code == 200 else set()
        if set(JOBS) <= names:
            break
        time.sleep(3)
    code, body, _ = req("/crumbIssuer/api/json")
    crumb = json.loads(body) if code == 200 else {}
    hdr = {crumb["crumbRequestField"]: crumb["crumb"]} if crumb else {}
    for job in JOBS:
        code, _, _ = req(f"/job/{job}/build", "POST", hdr)
        print(job, "trigger", code)
    summary = {"jenkins_version": version, "jobs": {}}
    for job in JOBS:
        build = None
        for _ in range(120):
            code, body, _ = req(f"/job/{job}/1/api/json")
            if code == 200:
                build = json.loads(body)
                if not build.get("building"):
                    break
            time.sleep(3)
        d = out / job
        d.mkdir(parents=True, exist_ok=True)
        (d / "build.json").write_text(json.dumps(build, indent=1))
        code, body, _ = req(f"/job/{job}/1/wfapi/describe")
        wf = json.loads(body) if code == 200 else {"http": code}
        (d / "wfapi.json").write_text(json.dumps(wf, indent=1))
        for stage in wf.get("stages", []) if isinstance(wf, dict) else []:
            code, body, _ = req(f"/job/{job}/1/execution/node/{stage['id']}/wfapi/describe")
            (d / f"stage-{stage['id']}.json").write_text(
                body.decode() if code == 200 else json.dumps({"http": code})
            )
        for path in ("stages/tree", "stages/allSteps"):  # Pipeline Graph View plugin
            code, body, _ = req(f"/job/{job}/1/{path}")
            (d / (path.replace("/", "_") + ".json")).write_text(
                body.decode() if code == 200 else json.dumps({"http": code})
            )
        arts = [a["relativePath"] for a in (build or {}).get("artifacts", [])]
        for rel in arts[:3]:
            code, body, _ = req(f"/job/{job}/1/artifact/{rel}")
            summary.setdefault("artifact_fetch", {})[f"{job}/{rel}"] = [code, len(body)]
        summary["jobs"][job] = {
            "result": (build or {}).get("result"),
            "stages": [(s.get("name"), s.get("status")) for s in wf.get("stages", [])]
            if isinstance(wf, dict)
            else wf,
            "artifacts": arts,
        }
    (out / "summary.json").write_text(json.dumps(summary, indent=1))
    print(json.dumps(summary)[:6000])


if __name__ == "__main__":
    main(Path(sys.argv[1]))
