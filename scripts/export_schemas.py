"""Write (or --check) the published JSON Schemas in schemas/ (Phase 4, #47).

    python scripts/export_schemas.py           # regenerate schemas/
    python scripts/export_schemas.py --check   # exit 1 if schemas/ drifted

schemas/manifest.json records each file's SHA-256 and the pydantic version that
generated it; --check compares content only when that pydantic minor matches, because
pydantic may reorder or reword generated schemas between minors.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from importlib.metadata import version
from pathlib import Path

from scanproof.schemas import documents

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "schemas"


def render(doc: dict) -> str:
    return json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def pydantic_minor() -> str:
    return ".".join(version("pydantic").split(".")[:2])


def expected() -> dict[str, str]:
    files = {name: render(doc) for name, doc in documents().items()}
    manifest = {
        "generator": "scripts/export_schemas.py",
        "pydantic": pydantic_minor(),
        "files": {
            name: hashlib.sha256(text.encode("utf-8")).hexdigest()
            for name, text in sorted(files.items())
        },
    }
    files["manifest.json"] = render(manifest)
    return files


def check(out: Path = OUT) -> list[str]:
    """Return human-readable drift problems (empty when in sync)."""
    want = expected()
    problems: list[str] = []
    present = {p.name for p in out.glob("*.json")} if out.is_dir() else set()
    for extra in sorted(present - set(want)):
        problems.append(f"unexpected file schemas/{extra}")
    try:
        recorded = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return [*problems, "schemas/manifest.json missing or unreadable"]
    if set(recorded.get("files", {})) != set(want) - {"manifest.json"}:
        problems.append("manifest file list differs from the schema catalog")
    for name, digest in recorded.get("files", {}).items():
        path = out / name
        if not path.is_file():
            problems.append(f"missing schemas/{name}")
        elif hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            problems.append(f"schemas/{name} does not match its manifest digest")
    if recorded.get("pydantic") == pydantic_minor():
        for name, text in want.items():
            path = out / name
            if path.is_file() and path.read_text(encoding="utf-8") != text:
                problems.append(f"schemas/{name} is stale; run scripts/export_schemas.py")
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args(argv)
    if args.check:
        problems = check()
        for p in problems:
            print(p, file=sys.stderr)
        return 1 if problems else 0
    OUT.mkdir(exist_ok=True)
    for name, text in expected().items():
        (OUT / name).write_text(text, encoding="utf-8")
    print(f"wrote {len(expected())} files to {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
