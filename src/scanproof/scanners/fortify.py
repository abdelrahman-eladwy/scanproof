"""Fortify Static Code Analyzer adapter: FPR archive or bare audit.fvdl (EXPERIMENTAL).

Tested against a real FPR produced by Fortify SCA 24.2.0 (FVDL 1.12), from DefectDojo's test
suite (BSD-3-Clause, see tests/fixtures/LICENSE-DefectDojo.md). Not yet tested against FPRs with
scan errors or from other SCA versions: please report mismatches.

XML is parsed with defusedxml (no DTDs, no entity expansion, no external references): an FPR is
untrusted input.

Mapping:
  EngineData/EngineVersion                 tool_version
  EngineData/Errors/Error[@code]           scanner errors (translation/scan errors mean code
                                           that was not analysed)
  Build/NumberFiles, Build/SourceFiles     scope: files Fortify actually analysed, relative to
                                           SourceBasePath, so required_paths works
  Vulnerabilities/Vulnerability            findings, minus issues suppressed in audit.xml
  priority (Critical/High/Medium/Low)      Fortify's documented formula, as in DefectDojo:
                                           likelihood = accuracy * confidence * probability / 25
                                           with Impact/Accuracy/Probability from the rule's
                                           EngineData/RuleInfo metadata
"""

from __future__ import annotations

import io
import zipfile
from typing import Any
from xml.etree.ElementTree import (
    Element,
    ParseError,
)

from defusedxml import DefusedXmlException
from defusedxml.ElementTree import fromstring

from scanproof.evidence.models import FindingsSummary, ScannerError, ScanScope, ScanType
from scanproof.scanners.base import ReportLoadError, ScannerAdapter, count_by

MAX_FVDL_BYTES = 200 * 1024 * 1024
_AUDIT_NS = "xmlns://www.fortify.com/schema/audit"


class FortifyAdapter(ScannerAdapter):
    tool = "fortify"
    scan_type = ScanType.SAST

    def load(self, raw: bytes) -> dict[str, Any]:
        audit_xml: bytes | None = None
        if raw[:2] == b"PK":
            fvdl, audit_xml = _read_fpr(raw)
        elif raw.lstrip()[:1] == b"<":
            fvdl = raw
        else:
            raise ReportLoadError("Not a Fortify FPR (zip) or FVDL (XML) file")
        root = _parse_xml(fvdl, "audit.fvdl")
        suppressed: set[str] = set()
        if audit_xml:
            audit = _parse_xml(audit_xml, "audit.xml")
            for issue in audit.iter(f"{{{_AUDIT_NS}}}Issue"):
                if issue.get("suppressed") == "true" and issue.get("instanceId"):
                    suppressed.add(issue.get("instanceId", ""))
        return {"root": root, "suppressed": suppressed}

    def shape_problem(self, data: Any) -> str | None:
        root: Element = data["root"]
        if root.tag.rpartition("}")[2] != "FVDL":
            return f"Not a Fortify FVDL document (root element {root.tag!r})"
        return None

    def extract(self, data: dict[str, Any]) -> dict[str, Any]:
        root: Element = data["root"]
        ns = root.tag[: root.tag.index("}") + 1] if root.tag.startswith("{") else ""
        q = lambda path: "/".join(f"{ns}{p}" for p in path.split("/"))  # noqa: E731

        engine = root.find(q("EngineData"))
        errors: list[ScannerError] | None = None
        version = None
        rules: dict[str, dict[str, str]] = {}
        if engine is not None:
            version = (engine.findtext(q("EngineVersion")) or "").strip() or None
            errors = [
                ScannerError(
                    level="error",
                    type=f"fortify code {e.get('code')}" if e.get("code") else "fortify error",
                    message=(e.text or "").strip() or "(no message)",
                )
                for e in engine.findall(q("Errors/Error"))
            ]
            for rule in engine.findall(q("RuleInfo/Rule")):
                meta = {
                    g.get("name", ""): (g.text or "").strip()
                    for g in rule.findall(q("MetaInfo/Group"))
                }
                rules[rule.get("id", "")] = meta

        scope = None
        build = root.find(q("Build"))
        if build is not None:
            names = [
                (f.findtext(q("Name")) or "").strip() for f in build.findall(q("SourceFiles/File"))
            ]
            declared = (build.findtext(q("NumberFiles")) or "").strip()
            scope = ScanScope(
                files_scanned=int(declared) if declared.isdigit() else len(names),
                scanned_paths=[n for n in names if n],
            )

        priorities: list[str] = []
        suppressed = 0
        for vuln in root.findall(q("Vulnerabilities/Vulnerability")):
            instance = (vuln.findtext(q("InstanceInfo/InstanceID")) or "").strip()
            if instance and instance in data["suppressed"]:
                suppressed += 1
                continue
            class_id = (vuln.findtext(q("ClassInfo/ClassID")) or "").strip()
            confidence = vuln.findtext(q("InstanceInfo/Confidence"))
            priorities.append(_priority(rules.get(class_id, {}), confidence))

        return {
            "tool_version": version,
            "scanner_name": "fortify-sca",
            "scanner_errors": errors,
            "scope": scope,
            "results_reported": root.find(q("Vulnerabilities")) is not None,
            "findings": FindingsSummary(
                total=len(priorities), by_severity=count_by(priorities), suppressed=suppressed
            ),
        }


def _read_fpr(raw: bytes) -> tuple[bytes, bytes | None]:
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            if "audit.fvdl" not in zf.namelist():
                raise ReportLoadError("FPR archive has no audit.fvdl")
            fvdl = _read_member(zf, "audit.fvdl")
            audit = _read_member(zf, "audit.xml") if "audit.xml" in zf.namelist() else None
            return fvdl, audit
    except zipfile.BadZipFile as exc:
        raise ReportLoadError(f"FPR is not a valid zip archive: {exc}") from None


def _read_member(zf: zipfile.ZipFile, name: str) -> bytes:
    info = zf.getinfo(name)
    if info.file_size > MAX_FVDL_BYTES:
        raise ReportLoadError(f"{name} is {info.file_size} bytes; limit is {MAX_FVDL_BYTES}")
    out = bytearray()
    with zf.open(info) as fh:
        while chunk := fh.read(1 << 20):
            out += chunk
            if len(out) > MAX_FVDL_BYTES:  # sizes in zip headers can lie
                raise ReportLoadError(f"{name} exceeded {MAX_FVDL_BYTES} bytes")
    return bytes(out)


def _parse_xml(data: bytes, name: str) -> Element:
    try:
        return fromstring(data, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except DefusedXmlException as exc:
        raise ReportLoadError(f"{name}: refused unsafe XML ({type(exc).__name__})") from None
    except ParseError as exc:
        raise ReportLoadError(f"{name}: not well-formed XML ({exc})") from None


def _priority(meta: dict[str, str], confidence: str | None) -> str:
    try:
        impact = float(meta["Impact"])
        likelihood = round(
            float(meta["Accuracy"]) * float(confidence or "") * float(meta["Probability"]) / 25, 1
        )
    except (KeyError, ValueError):
        return "UNKNOWN"
    if impact >= 2.5:
        return "CRITICAL" if likelihood >= 2.5 else "HIGH"
    return "MEDIUM" if likelihood >= 2.5 else "LOW"
