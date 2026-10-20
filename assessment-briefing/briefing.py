#!/usr/bin/env python3
"""Offline PRIVATE printable briefing from an already-created LightUp lab result.

Does not import or invoke the assessment runtime, model, scope gates or workers.
Source-reported data remains UNVERIFIED. Never grants authority or executes work.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import html
import io
import json
import os
from pathlib import Path
import re
import stat
import sys

MAX_BYTES = 8 * 1024 * 1024
MAX_FINDINGS = 2048
SEVERITIES = ("critical", "high", "medium", "low", "info")
METRICS = ("valid_findings", "invalid_findings", "missed_findings",
           "coverage_assessed", "coverage_unknown", "scope_violations",
           "policy_violations", "human_interventions", "tool_calls",
           "evidence_quality", "reproducibility", "remediation_quality",
           "retest_correctness", "runtime_seconds", "compute_cost_usd",
           "false_positive_rate")
SOURCE_FIELDS = {"run_id", "scenario_id", "targets", "plan", "denied",
                 "elevation_requests", "findings", "coverage",
                 "evaluation", "report_markdown"}
FINDING_FIELDS = {"finding", "finding_id", "severity", "impact", "fix",
                  "retest", "check_id", "capability_id", "target",
                  "evidence_ids", "evidence_summary"}
DENIAL_FLAGS = {"authorized": False, "consent_verified": False,
                "dispatch_allowed": False, "release_allowed": False}
CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
CSS = """
:root{color-scheme:light;font-family:system-ui,sans-serif;background:#edf1f5;color:#192335}
*{box-sizing:border-box}body{max-width:1080px;margin:0 auto;padding:2.2rem}
header,article,section.card{background:#fff;padding:1.4rem;margin:1rem 0;border:1px solid #d2dce7;border-radius:12px}
h1{margin:0 0 .65rem}h2{border-bottom:1px solid #dce2ec;padding-bottom:.4rem}
p,li{line-height:1.6}small,.muted{color:#596779}.notice{font-weight:700;color:#713c00}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px}
.value{font-size:1.8rem;font-weight:800}.sev{font-weight:bold;text-transform:uppercase}
.critical,.high{color:#9e1c18}.medium{color:#795300}
pre{white-space:pre-wrap;overflow-wrap:anywhere}details{margin:1rem 0}
dl{display:grid;grid-template-columns:150px 1fr;gap:8px}dt{font-weight:bold}
.worksheet{border:2px dashed #cad4dd;margin-top:1rem;padding:1rem}
.scroll-table{overflow-x:auto;max-width:100%}table{width:100%;border-collapse:collapse;min-width:840px}
th,td{border-bottom:1px solid #d5dfea;text-align:left;padding:.7rem .65rem;vertical-align:top}
th{background:#e7eff5;font-size:.88rem}a{color:#195f89}
@media print{body{max-width:none;padding:0;background:#fff}article{break-inside:avoid;border:1px solid #bbb}
details>div{display:block!important}header{border:0}.no-print{display:none}
.worksheet{break-inside:avoid}a{text-decoration:none;color:inherit}}
"""

class Hold(Exception):
    """An unsupported or ambiguous local artifact; never echo its contents."""


def require(ok: bool) -> None:
    if not ok:
        raise Hold("PRIVATE source rejected (HOLD); no output published")


def text_value(value: object, limit: int = 8192, *, nonempty: bool = False) -> bool:
    return (type(value) is str and len(value) <= limit and
            (not nonempty or bool(value)) and not CONTROL.search(value))


def strict_pairs(pairs: list[tuple[str, object]]) -> dict:
    out = {}
    for k, v in pairs:
        require(k not in out)
        out[k] = v
    return out


def open_source(path: str) -> tuple[dict, bytes, str]:
    fd = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(path, flags)
        meta = os.fstat(fd)
        require(stat.S_ISREG(meta.st_mode) and 0 < meta.st_size <= MAX_BYTES)
        with os.fdopen(fd, "rb") as f:
            fd = -1
            raw = f.read(MAX_BYTES + 1)
        require(0 < len(raw) <= MAX_BYTES)
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=strict_pairs,
                             parse_constant=lambda _: require(False))
        require(type(payload) is dict)
        admit_source(payload)
        return payload, raw, hashlib.sha256(raw).hexdigest()
    except (OSError, ValueError, UnicodeError, RecursionError, OverflowError, TypeError,
            MemoryError) as exc:
        raise Hold("PRIVATE source rejected (HOLD); no output published") from None
    finally:
        if fd >= 0:
            os.close(fd)


def admit_source(x: dict) -> None:
    # This is a conservative PRIVATE reader for the frozen original lab-assess
    # JSON shape. It is NOT a replacement for original producer verification.
    require(set(x) in (SOURCE_FIELDS, SOURCE_FIELDS | {"benchmark_case"}))
    require(text_value(x["run_id"], 256, nonempty=True) and
            text_value(x["scenario_id"], 256, nonempty=True))
    require(type(x["targets"]) is list and 1 <= len(x["targets"]) <= 16)
    require(all(text_value(t, 2048, nonempty=True) for t in x["targets"]))
    require(len(set(x["targets"])) == len(x["targets"]))
    require(type(x["findings"]) is list and len(x["findings"]) <= MAX_FINDINGS)
    require(all(type(x[k]) is list and len(x[k]) <= 512
                for k in ("plan", "denied", "elevation_requests")))
    require(type(x["coverage"]) is dict and type(x["evaluation"]) is dict)
    require(text_value(x["report_markdown"], MAX_BYTES))
    ev = x["evaluation"]
    require(set(ev) == {"record_id", "scenario_id", "run_id", "engine_version",
                        "model_bindings", "metrics", "created_at", "notes"})
    require(ev["run_id"] == x["run_id"] and ev["scenario_id"] == x["scenario_id"])
    require(type(ev["metrics"]) is dict and set(ev["metrics"]) == set(METRICS))
    for k, v in ev["metrics"].items():
        require(type(v) in (int, float) and 0 <= v < 1e12)
        if k in METRICS[:9]:
            require(type(v) is int)
        if k in ("evidence_quality", "reproducibility", "remediation_quality",
                 "retest_correctness", "false_positive_rate"):
            require(v <= 1)
    m = ev["metrics"]
    denom = m["valid_findings"] + m["invalid_findings"]
    require(abs(m["false_positive_rate"] -
                (m["invalid_findings"] / denom if denom else 0)) <= 1e-8)
    require(all(type(p) is dict and
                set(p) == {"tool_id", "asset", "arguments"} and
                text_value(p["tool_id"], 256) and
                text_value(p["asset"], 2048) and type(p["arguments"]) is dict
                for p in x["plan"]))
    require(all(type(d) is dict and set(d) == {"tool_id", "reason"} and
                text_value(d["tool_id"], 256) and text_value(d["reason"], 8192)
                for d in x["denied"]))
    ids = set()
    for f in x["findings"]:
        require(type(f) is dict and set(f) == FINDING_FIELDS)
        require(text_value(f["finding_id"], 256, nonempty=True) and
                f["finding_id"] not in ids)
        ids.add(f["finding_id"])
        require(f["severity"] in SEVERITIES)
        require(all(text_value(f[key], 8192, nonempty=key in ("finding", "target"))
                    for key in ("finding", "impact", "fix", "retest", "check_id",
                                "capability_id", "target", "evidence_summary")))
        require(type(f["evidence_ids"]) is list and len(f["evidence_ids"]) <= 64)
        require(all(text_value(z, 1024) for z in f["evidence_ids"]))
    if "benchmark_case" in x:
        b = x["benchmark_case"]
        require(type(b) is dict and set(b) == {"record", "context"})
        require(type(b["context"]) is dict and type(b["record"]) is dict)
        require(b["context"].get("is_lab") is True and
                b["context"].get("authorization", "MISSING") is None and
                b["context"].get("run_id") == x["run_id"])
        require(b["record"] == ev)


def h(s: object) -> str:
    return html.escape(str(s), quote=True)


def element(title: str, body: str) -> str:
    return "<section class='card'><h2>" + h(title) + "</h2>" + body + "</section>"


def render(source: dict, digest: str) -> str:
    counts = {s: 0 for s in SEVERITIES}
    for f in source["findings"]:
        counts[f["severity"]] += 1
    blocks = []
    for i, f in enumerate(source["findings"], 1):
        original_target_ord = (source["targets"].index(f["target"]) + 1
                               if f["target"] in source["targets"] else None)
        # Never imply that hostname-only or DNS heuristics authenticate membership.
        endpoint = ("original declared endpoint " + str(original_target_ord)
                    if original_target_ord else "unmatched original source target")
        private = "".join("<dt>" + h(k) + "</dt><dd>" + h(v) + "</dd>" for k, v in (
            ("Source finding ID", f["finding_id"]), ("Source check", f["check_id"]),
            ("Source capability", f["capability_id"]), ("Source target", f["target"]),
            ("Impact", f["impact"]), ("Mitigation", f["fix"]),
            ("Retest proposal", f["retest"]), ("Source evidence summary", f["evidence_summary"]),
            ("Source evidence references", ", ".join(f["evidence_ids"]))))
        blocks.append("<article><h3>#" + str(i) + " · <span class='sev " +
                      h(f["severity"]) + "'>" + h(f["severity"]) + "</span></h3>" +
                      "<p class='muted'>" + h(endpoint) + "</p><p>" + h(f["finding"]) +
                      "</p><details><summary>PRIVATE original report details (unverified)</summary>" +
                      "<div><dl>" + private + "</dl></div></details>" +
                      "<div class='worksheet'><strong>Human follow-up · blank by design</strong>" +
                      "<p>Owner/group: ______________________ &nbsp; Date: ______________</p>" +
                      "<p>Question/action: _____________________________________________</p>" +
                      "<p>Evidence to independently verify: ____________________________</p>" +
                      "<p>Blocker/uncertainty: ________________________________________</p>" +
                      "</div></article>")
    summary = "".join("<div class='card'><strong>" + h(s) + "</strong><div class='value'>" +
                      str(n) + "</div></div>" for s, n in counts.items())
    info = ("<p><strong>Unverified source SHA-256:</strong> <code>" + digest +
            "</code></p><p>Original run/scenario labels are intentionally private: " +
            h(source["run_id"]) + " / " + h(source["scenario_id"]) + "</p>" +
            "<p>Declared lab targets: " + str(len(source["targets"])) +
            " · Source-reported findings: " + str(len(blocks)) +
            " · Records with source evidence IDs: " +
            str(sum(bool(f["evidence_ids"]) for f in source["findings"])) + "</p>")
    notice = ("<p class='notice'>PRIVATE / REVIEW ONLY — no proof of source authenticity, " +
              "finding validity, consent, authorization, remediation or release.</p>" +
              "<p>Original source URLs, raw evidence summaries and finding titles can " +
              "identify a customer. Keep this offline report within the authorized private " +
              "human review channel. Printing does not establish a security verdict.</p>")
    body = ("<header><h1>LightUp · private lab finding briefing</h1>" + notice + info +
            "</header>" + element("Source severity declarations", "<div class='grid'>" +
            summary + "</div>") + element("Human-only printable finding worksheets",
            "<p>Records remain in original source order. No automatic decisions.</p>" +
            "".join(blocks) if blocks else "<p>Original source declared no findings.</p>"))
    css_digest = __import__("base64").b64encode(hashlib.sha256(CSS.encode()).digest()).decode()
    csp = ("default-src 'none'; style-src 'sha256-" + css_digest +
           "'; script-src 'none'; connect-src 'none'; img-src 'none'; " +
           "form-action 'none'; base-uri 'none'; object-src 'none'")
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'>" +
            "<meta http-equiv='Content-Security-Policy' content=\"" + h(csp) + "\">" +
            "<meta name='viewport' content='width=device-width,initial-scale=1'>" +
            "<title>PRIVATE LightUp lab briefing</title><style>" + CSS +
            "</style></head><body>" + body + "</body></html>\n")


def followup_csv(source: dict) -> str:
    # No original identifiers, targets or finding text in this CSV. Nonetheless
    # anonymous ordinals and the source-count distribution remain PRIVATE.
    fp = io.StringIO(newline="")
    writer = csv.writer(fp, lineterminator="\r\n")
    writer.writerow(("original_ordinal", "source_reported_severity",
                     "evidence_reference_count", "human_stage",
                     "human_owner_group", "human_next_action", "human_blocker"))
    for i, f in enumerate(source["findings"], 1):
        writer.writerow((i, f["severity"], len(f["evidence_ids"]), "", "", "", ""))
    return fp.getvalue()


def json_bytes(data: dict) -> bytes:
    return (json.dumps(data, ensure_ascii=True, sort_keys=True, indent=2) + "\n").encode("utf-8")


def publish_new(directory: str, artifacts: dict[str, bytes]) -> None:
    # Exclusive, private and all-or-nothing package. No symlink traversal or overwrite.
    parent = Path(directory)
    created = False
    try:
        os.mkdir(parent, 0o700)
        created = True
        require(stat.S_IMODE(parent.stat().st_mode) == 0o700)
        for name, data in artifacts.items():
            require("/" not in name and "\\" not in name and len(data) <= 24 * 1024 * 1024)
            fd = os.open(parent / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                         getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
        dirfd = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    except (OSError, Hold):
        if created:
            for name in artifacts:
                try:
                    (parent / name).unlink(missing_ok=True)
                except OSError:
                    pass
            try:
                parent.rmdir()
            except OSError:
                pass
        raise Hold("PRIVATE output refused; no existing files overwritten") from None


def make_package(path: str, output: str) -> None:
    source, raw, digest = open_source(path)
    report = render(source, digest).encode("utf-8")
    table = followup_csv(source).encode("utf-8")
    manifest = {
        "schema": "lightup.private_lab_briefing.v1", "status": "REVIEW_ONLY",
        "original_source_sha256_unsigned": digest,
        "declared_endpoint_count": len(source["targets"]),
        "declared_finding_count": len(source["findings"]),
        "findings_with_source_evidence_ids": sum(bool(f["evidence_ids"]) for f in source["findings"]),
        "private_artifact_sha256": {
            "private-briefing.html": hashlib.sha256(report).hexdigest(),
            "human-followup.csv": hashlib.sha256(table).hexdigest()},
        "source_authenticated": False, "ground_truth_verified": False,
        "client_consent_verified": False, "operator_consent_verified": False,
        **DENIAL_FLAGS,
    }
    publish_new(output, {"private-briefing.html": report, "human-followup.csv": table,
                         "manifest.json": json_bytes(manifest)})


def main() -> int:
    p = argparse.ArgumentParser(description="Build PRIVATE lab result briefing (NO execution)")
    p.add_argument("--source", required=True, help="existing PRIVATE lab-assess JSON")
    p.add_argument("--output-dir", required=True, help="NEW PRIVATE output directory")
    a = p.parse_args()
    try:
        make_package(a.source, a.output_dir)
    except Hold as exc:
        print(str(exc), file=sys.stderr)
        return 3
    print("PRIVATE briefing created; human REVIEW ONLY; NO execution or release")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
