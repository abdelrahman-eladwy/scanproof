"""Collect real Bitbucket Cloud Pipelines API responses from PUBLIC repositories (anonymous).

Usage: python scripts/collect_bitbucket.py OUT_DIR WORKSPACE/REPO [WORKSPACE/REPO ...]
Writes <repo>/pipelines.json, <repo>/<n>/{pipeline,steps,reports}.json and summary.json.
Only whitelisted fields are kept: no people (creator, author), avatars or commit messages.
"""

# ruff: noqa: S310 - collectors only open fixed https hosts (or the local contract Jenkins)

from __future__ import annotations

import json
import sys
import urllib.request
from collections import Counter
from pathlib import Path

API = "https://api.bitbucket.org/2.0/repositories"
MAX = 10 * 1024 * 1024


def get(url: str) -> object:
    req = urllib.request.Request(
        url, headers={"Accept": "application/json", "User-Agent": "scanproof-fixtures"}
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read(MAX + 1)
    if len(data) > MAX:
        raise ValueError("response too large")
    return json.loads(data)


def state(s: dict | None) -> dict | None:
    if not isinstance(s, dict):
        return None
    out = {"name": s.get("name"), "type": s.get("type")}
    for k in ("result", "stage"):
        if isinstance(s.get(k), dict):
            out[k] = {"name": s[k].get("name"), "type": s[k].get("type")}
    return out


def pipeline_view(p: dict) -> dict:
    t = p.get("target") or {}
    return {
        "uuid": p.get("uuid"),
        "build_number": p.get("build_number"),
        "state": state(p.get("state")),
        "created_on": p.get("created_on"),
        "completed_on": p.get("completed_on"),
        "duration_in_seconds": p.get("duration_in_seconds"),
        "target": {
            "type": t.get("type"),
            "ref_type": t.get("ref_type"),
            "ref_name": t.get("ref_name"),
            "commit": {"hash": (t.get("commit") or {}).get("hash")},
            "selector": t.get("selector"),
        },
        "trigger": {"type": (p.get("trigger") or {}).get("type")},
    }


def step_view(s: dict) -> dict:
    keep = {
        k: s.get(k)
        for k in (
            "uuid",
            "name",
            "started_on",
            "completed_on",
            "duration_in_seconds",
            "run_number",
            "max_time",
            "trigger",
            "teardown",
        )
    }
    keep["state"] = state(s.get("state"))
    keep["image"] = {"name": (s.get("image") or {}).get("name")}
    # anything that looks like a failure strategy, whatever the API calls it
    keep["other_keys"] = sorted(
        k
        for k in s
        if k not in keep
        and k not in ("links", "pipeline", "script_commands", "setup_commands", "teardown_commands")
    )
    for k in keep["other_keys"]:
        v = s.get(k)
        if (
            isinstance(v, (str, int, float, bool))
            or v is None
            or k in ("on_fail", "onFail", "failure_strategy")
        ):
            keep[k] = v
    return keep


def main(out: Path, repos: list[str]) -> None:
    summary: dict = {"repos": {}, "step_states": {}, "notes": []}
    states: Counter = Counter()
    for repo in repos:
        d = out / repo.replace("/", "__")
        d.mkdir(parents=True, exist_ok=True)
        try:
            page = get(f"{API}/{repo}/pipelines/?sort=-created_on&pagelen=30")
        except Exception as exc:
            summary["notes"].append(f"{repo}: {type(exc).__name__}: {exc}")
            continue
        pipes = [pipeline_view(p) for p in page.get("values", [])]
        (d / "pipelines.json").write_text(
            json.dumps({"values": pipes, "size": page.get("size")}, indent=1)
        )
        if pipes:  # does the API accept a build number where the docs say pipeline UUID?
            try:
                by_number = get(f"{API}/{repo}/pipelines/{pipes[0]['build_number']}")
                summary.setdefault("by_number", {})[repo] = (
                    by_number.get("uuid") == pipes[0]["uuid"]
                )
            except Exception as exc:
                summary.setdefault("by_number", {})[repo] = f"{type(exc).__name__}: {exc}"
        picked: dict[str, int] = {}
        for p in pipes:
            r = ((p["state"] or {}).get("result") or {}).get("name") or (p["state"] or {}).get(
                "name"
            )
            if picked.get(r, 0) >= 2:
                continue
            picked[r] = picked.get(r, 0) + 1
            pd = d / str(p["build_number"])
            pd.mkdir(exist_ok=True)
            (pd / "pipeline.json").write_text(json.dumps(p, indent=1))
            try:
                steps = get(f"{API}/{repo}/pipelines/{p['uuid']}/steps/?pagelen=100")
                views = [step_view(s) for s in steps.get("values", [])]
                for v in views:
                    st = v["state"] or {}
                    states[f"{st.get('name')}:{(st.get('result') or {}).get('name')}"] += 1
                (pd / "steps.json").write_text(json.dumps({"values": views}, indent=1))
            except Exception as exc:
                summary["notes"].append(
                    f"{repo}#{p['build_number']} steps: {type(exc).__name__}: {exc}"
                )
            sha = p["target"]["commit"]["hash"]
            if sha:
                try:
                    rep = get(f"{API}/{repo}/commit/{sha}/reports")
                    (pd / "reports.json").write_text(
                        json.dumps(
                            {
                                "values": [
                                    {
                                        k: x.get(k)
                                        for k in (
                                            "uuid",
                                            "external_id",
                                            "title",
                                            "report_type",
                                            "reporter",
                                            "result",
                                            "created_on",
                                        )
                                    }
                                    for x in rep.get("values", [])
                                ]
                            },
                            indent=1,
                        )
                    )
                    for x in rep.get("values", [])[:3]:
                        rid = x.get("uuid")
                        detail = get(f"{API}/{repo}/commit/{sha}/reports/{rid}")
                        detail.pop("links", None)
                        notes = get(
                            f"{API}/{repo}/commit/{sha}/reports/{rid}/annotations?pagelen=100"
                        )
                        safe = (rid or "x").strip("{}")
                        (pd / f"report-{safe}.json").write_text(json.dumps(detail, indent=1))
                        (pd / f"report-{safe}-annotations.json").write_text(
                            json.dumps(
                                {
                                    "size": notes.get("size"),
                                    "next": bool(notes.get("next")),
                                    "values": [
                                        {
                                            k: v.get(k)
                                            for k in (
                                                "external_id",
                                                "annotation_type",
                                                "severity",
                                                "result",
                                                "summary",
                                                "path",
                                                "line",
                                                "created_on",
                                            )
                                        }
                                        for v in notes.get("values", [])
                                    ],
                                },
                                indent=1,
                            )
                        )
                except Exception as exc:
                    summary["notes"].append(
                        f"{repo}#{p['build_number']} reports: {type(exc).__name__}"
                    )
        summary["repos"][repo] = {"pipelines": len(pipes), "picked": picked}
    summary["step_states"] = dict(sorted(states.items()))
    (out / "summary.json").write_text(json.dumps(summary, indent=1))
    print(json.dumps(summary)[:3000])


if __name__ == "__main__":
    main(Path(sys.argv[1]), sys.argv[2:])
