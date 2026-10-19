#!/usr/bin/env python3
"""PRIVATE offline human review of repeated local evidence fingerprints and snapshot drift.

Consumes HUMAN-only exports from LightUp Evidence Artifact Ledger (#1642).
Never authenticates the original source, touches an asset, or verifies remediation.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import html
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys

MAX_BYTES = 4 * 1024 * 1024
MAX_FILE_BYTES = 16 * 1024 * 1024
HEX = re.compile(r"^[0-9a-f]{64}$")
STAMP = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")
STAGES = frozenset(("unreviewed", "human_review", "follow_up", "archived"))
FLAGS = ("authenticated", "tenant_verified", "source_authorized",
         "assessment_authorized", "grant", "client_consent", "operator_consent",
         "execution", "scan", "audit_verdict", "retest_verified", "release")
COMMON = {"kind", "schema_version", "disposition", "source_contract",
          "source_sha256", "source_count", "client_reference",
          "engagement_reference", "attachments", "warning", *FLAGS}
UNIFIED = COMMON | {"casework", "evidence_review", "human_requests"}
ROW = {"finding_id", "file_name", "byte_length", "sha256", "mime",
       "added_utc", "human_reviewer", "human_stage", "human_note"}


class Hold(ValueError):
    """The complete HUMAN-only input cannot safely be reviewed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Hold(message)


def exact_string(value: object, limit: int, name: str, mandatory: bool = False) -> str:
    require(type(value) is str and len(value) <= limit and
            not any(ord(c) < 32 or ord(c) == 127 for c in value) and
            (not mandatory or bool(value.strip())), "Invalid " + name)
    return value


def pairs(items: list[tuple[str, object]]) -> dict:
    out = {}
    for key, value in items:
        if key in out:
            raise Hold("Duplicate JSON member (HOLD)")
        out[key] = value
    return out


def reject_constant(value: str) -> None:
    raise Hold("Non-finite number in source (HOLD)")


def private_read(path: Path) -> bytes:
    # Check literal owner-only directory as well as descriptor-bound file metadata.
    # A symlinked ancestor or non-private download directory is not an admissible source.
    parent = path.parent.resolve(strict=True)
    require(path.is_absolute() and path.parent == parent,
            "Input requires a literal absolute path without symlinked ancestors")
    directory = parent.stat()
    require(stat.S_ISDIR(directory.st_mode) and directory.st_uid == os.getuid() and
            directory.st_mode & 0o077 == 0,
            "Input must be inside a real owner-private 0700 directory")
    flags = (os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) |
             getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                "Input must be one regular PRIVATE file")
        require(info.st_uid == os.getuid() and info.st_mode & 0o077 == 0,
                "Input must be owner-controlled 0600; move to a private directory and chmod 600")
        require(info.st_size <= MAX_BYTES, "PRIVATE packet exceeds 4 MiB")
        data = bytearray()
        while True:
            chunk = os.read(fd, min(65536, MAX_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            require(len(data) <= MAX_BYTES, "PRIVATE packet exceeds 4 MiB")
        return bytes(data)
    finally:
        os.close(fd)


def parse_packet_data(raw: bytes) -> dict:
    """Parse exactly the already-read bytes, to prevent different source reads."""
    require(type(raw) is bytes and len(raw) <= MAX_BYTES, "PRIVATE input exceeds 4 MiB")
    try:
        data = json.loads(raw.decode("utf-8"),
                          object_pairs_hook=pairs, parse_constant=reject_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise Hold("Malformed PRIVATE JSON (HOLD)") from exc
    require(type(data) is dict, "Expected a PRIVATE packet object")
    schema = data.get("schema_version")
    if (data.get("kind") == "lightup.private_artifact_ledger" and
            type(schema) is int and schema == 1):
        require(set(data) == COMMON and
                data.get("disposition") == "PRIVATE_HUMAN_EVIDENCE_INDEX_ONLY",
                "Unknown original ledger envelope")
    elif (data.get("kind") == "lightup.private_unified_human_evidence_workspace" and
          type(schema) is int and schema == 2):
        require(set(data) == UNIFIED and
                data.get("disposition") == "PRIVATE_HUMAN_REVIEW_ONLY",
                "Unknown original unified HUMAN envelope")
        for key in ("casework", "evidence_review"):
            overlay = data[key]
            require(overlay is None or
                    (type(overlay) is list and len(overlay) == data.get("source_count")),
                    "Incomplete original HUMAN overlay")
        require(type(data["human_requests"]) is list and
                len(data["human_requests"]) <= 200,
                "Invalid opaque native HUMAN request overlay")
    else:
        raise Hold("Only original Evidence Artifact Ledger v1 or unified HUMAN v2 export is supported")
    require(data.get("source_contract") == "lightup.finding_export._COLUMNS_v1",
            "Unrecognized original source contract")
    require(all(data.get(k) is False for k in FLAGS), "Untrusted authority claim (HOLD)")
    sha = data.get("source_sha256")
    require(type(sha) is str and HEX.fullmatch(sha) is not None,
            "Source SHA is not canonical")
    require(type(data.get("source_count")) is int and
            0 < data["source_count"] <= 350, "Invalid original finding count")
    for key in ("client_reference", "engagement_reference"):
        exact_string(data.get(key), 120, key, True)
    exact_string(data.get("warning"), 2000, "source warning", True)
    rows = data.get("attachments")
    require(type(rows) is list and len(rows) <= 120, "Invalid original attachment inventory")
    keys = set()
    for row in rows:
        require(type(row) is dict and set(row) == ROW, "Unknown attachment fields")
        exact_string(row["finding_id"], 160, "original finding", True)
        file_name = exact_string(row["file_name"], 240, "file name", True)
        require(not any(c in file_name for c in "/\\"),
                "Path separator in local file label")
        require(type(row["byte_length"]) is int and
                0 <= row["byte_length"] <= MAX_FILE_BYTES, "Invalid local byte count")
        require(type(row["sha256"]) is str and HEX.fullmatch(row["sha256"]) is not None,
                "Invalid local SHA-256")
        exact_string(row["mime"], 120, "local MIME")
        when = exact_string(row["added_utc"], 32, "local timestamp", True)
        require(STAMP.fullmatch(when) is not None, "Invalid timestamp format")
        try:
            datetime.fromisoformat(when.replace("Z", "+00:00"))
        except ValueError as exc:
            raise Hold("Invalid local timestamp") from exc
        exact_string(row["human_reviewer"], 120, "human reviewer")
        exact_string(row["human_note"], 1200, "private HUMAN note")
        require(type(row["human_stage"]) is str and row["human_stage"] in STAGES,
                "Unknown HUMAN stage")
        key = (row["finding_id"], row["sha256"])
        require(key not in keys, "Duplicate finding and file fingerprint")
        keys.add(key)
    return data


def parse_packet(path: Path) -> dict:
    return parse_packet_data(private_read(path))


def analyze(current: dict, previous: dict | None) -> dict:
    if previous is not None:
        for field in ("source_sha256", "source_count", "client_reference",
                      "engagement_reference", "source_contract"):
            require(current[field] == previous[field],
                    "Different original source or HUMAN context; cross-source comparison refused (HOLD)")
    rows = current["attachments"]
    groups = defaultdict(list)
    for row in rows:
        groups[row["sha256"]].append(row)
    shared = []
    for digest, members in sorted(groups.items()):
        findings = sorted({item["finding_id"] for item in members})
        sizes = {item["byte_length"] for item in members}
        if len(findings) < 2 and len(sizes) < 2:
            continue
        stages = sorted({item["human_stage"] for item in members})
        shared.append({"digest": digest, "findings": findings, "rows": members,
                       "stage_divergence": len(stages) > 1,
                       "size_disagreement": len(sizes) > 1})
    now = {(r["finding_id"], r["sha256"]): r for r in rows}
    old = {(r["finding_id"], r["sha256"]): r for r in previous["attachments"]} if previous else {}
    added = sorted(now.keys() - old.keys()) if previous else []
    removed = sorted(old.keys() - now.keys()) if previous else []
    changed = []
    if previous is not None:
        for key in sorted(now.keys() & old.keys()):
            a, b = old[key], now[key]
            fields = [k for k in ("human_stage", "human_reviewer", "human_note",
                                  "file_name", "mime", "byte_length", "added_utc") if a[k] != b[k]]
            if fields:
                changed.append({"key": key, "fields": fields,
                                "before": a["human_stage"], "after": b["human_stage"]})
    new_reused = sorted({k[1] for k in added if len({x["finding_id"] for x in groups[k[1]]}) > 1})
    attention = [g for g in shared if g["stage_divergence"] or g["size_disagreement"]]
    return {"total_findings_claimed": current["source_count"], "local_links": len(rows),
            "distinct_fingerprints": len(groups), "shared_groups": shared,
            "attention_groups": attention, "added": added, "removed": removed,
            "changed": changed, "new_reused": new_reused, "has_previous": previous is not None}


def anonymous(result: dict) -> dict:
    return {"kind": "lightup.anonymous_human_evidence_relationship_counts",
            "schema_version": 1, "disposition": "HUMAN_REVIEW_ONLY_NO_AUTHORITY",
            **{k: result[k] for k in ("total_findings_claimed", "local_links",
                                     "distinct_fingerprints")},
            "cross_finding_reuse_groups": len(result["shared_groups"]),
            "divergent_or_size_attention_groups": len(result["attention_groups"]),
            "new_links": len(result["added"]), "missing_from_current_local_snapshot": len(result["removed"]),
            "human_metadata_changes": len(result["changed"]),
            "newly_linked_shared_fingerprints": len(result["new_reused"]),
            "has_previous_private_snapshot": result["has_previous"],
            "notice": "Unverified HUMAN-local counts; none proves evidence authenticity, resolution, consent or permission."}


def proposed_actions(current: dict, result: dict) -> dict:
    """Private advisory HUMAN questions; never LightUp native Apply."""
    items = {}
    rows = {(r["finding_id"], r["sha256"]): r for r in current["attachments"]}
    for group in result["shared_groups"]:
        reasons = ["VERIFY_INTENTIONAL_CROSS_FINDING_REUSE"]
        if group["stage_divergence"]:
            reasons.append("RECONCILE_HUMAN_STAGE_DIFFERENCE")
        if group["size_disagreement"]:
            reasons.append("RECHECK_LOCAL_BYTES_WITH_ORIGINAL_LEDGER")
        for row in group["rows"]:
            items[(row["finding_id"], row["sha256"])] = set(reasons)
    for key in result["added"]:
        items.setdefault(key, set()).add("REVIEW_NEW_LOCAL_LINK")
    for key in result["removed"]:
        items.setdefault(key, set()).add("PREVIOUS_LOCAL_LINK_ABSENT_NOT_PROVEN_FIXED")
    for change in result["changed"]:
        items.setdefault(change["key"], set()).add("REVIEW_CHANGED_LOCAL_HUMAN_METADATA")
    actions = []
    for (finding_id, digest), reasons in sorted(items.items()):
        row = rows.get((finding_id, digest))
        actions.append({
            "finding_id": finding_id, "local_sha256": digest,
            "present_in_current_local_snapshot": row is not None,
            "human_stage": row["human_stage"] if row is not None else None,
            "human_reviewer": row["human_reviewer"] if row is not None else None,
            "proposed_human_questions": sorted(reasons),
        })
    return {
        "kind": "lightup.private_human_evidence_reuse_questions",
        "schema_version": 1,
        "disposition": "UNVERIFIED_HUMAN_FOLLOWUP_ONLY",
        "source_contract": current["source_contract"],
        "source_sha256": current["source_sha256"],
        "source_count": current["source_count"],
        "client_reference": current["client_reference"],
        "engagement_reference": current["engagement_reference"],
        **{flag: False for flag in FLAGS},
        "actions": actions,
        "warning": "Private advisory HUMAN questions only; never Apply, scan, grant, consent, evidence custody, fix or signed acceptance.",
    }


def render(current: dict, result: dict) -> str:
    e = lambda value: html.escape(str(value), quote=True)
    shared = result["shared_groups"]
    cols = "".join("<dt>" + e(k.replace("_", " ")) + "</dt><dd>" + e(v) + "</dd>"
                   for k, v in anonymous(result).items() if type(v) is int)
    sections = []
    for g in sorted(shared, key=lambda x: (not x["size_disagreement"],
                                          not x["stage_divergence"], -len(x["findings"]))):
        flags = []
        if g["size_disagreement"]:
            flags.append("SOURCE-LOCAL SIZE INCONSISTENCY · verify manually")
        if g["stage_divergence"]:
            flags.append("CONFLICTING HUMAN STAGES")
        if not flags:
            flags.append("REUSED LOCAL FINGERPRINT · provenance not established")
        records = "".join("<tr><td>" + e(r["finding_id"]) + "</td><td>" +
                          e(r["file_name"]) + "</td><td>" + e(r["byte_length"]) +
                          "</td><td>" + e(r["human_stage"]) + "</td><td>" +
                          e(r["human_reviewer"] or "unassigned") + "</td></tr>"
                          for r in g["rows"])
        sections.append("<section><h3>" + e(" · ".join(flags)) + "</h3><p>Local SHA-256: <code>" +
                        e(g["digest"]) + "</code></p><table><thead><tr><th>Source finding ID</th>" +
                        "<th>Private filename label</th><th>Bytes</th><th>Human stage</th><th>Reviewer alias</th>" +
                        "</tr></thead><tbody>" + records + "</tbody></table></section>")
    sections_html = "".join(sections) or "<p>No repeated local fingerprints detected in this snapshot.</p>"
    def changed_group(title: str, values: list, fmt) -> str:
        if not result["has_previous"]:
            return ""
        return ("<section><h3>" + e(title) + " · " + str(len(values)) + "</h3><ul>" +
                "".join("<li>" + fmt(v) + "</li>" for v in values) +
                "</ul></section>")
    diff = changed_group("New local references", result["added"],
                         lambda k: e(k[0]) + " · " + e(k[1][:20]) + "…") + \
           changed_group("No longer present in later LOCAL snapshot — NOT fixed", result["removed"],
                         lambda k: e(k[0]) + " · " + e(k[1][:20]) + "…") + \
           changed_group("Human/local metadata changed", result["changed"],
                         lambda x: e(x["key"][0]) + " · " + e(x["key"][1][:20]) +
                         "… · " + e(", ".join(x["fields"])) +
                         " · " + e(x["before"]) + " → " + e(x["after"]))
    return ("<!doctype html><html lang='en'><meta charset='utf-8'><meta http-equiv='Content-Security-Policy' "
            "content=\"default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; connect-src 'none'; "
            "form-action 'none'; base-uri 'none'\"><meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<title>LightUp PRIVATE evidence relationship review · HUMAN ONLY</title><style>"
            "body{font:16px system-ui;max-width:1100px;margin:2rem auto;padding:0 1rem;background:#f7f8fb;color:#172333}"
            "h1{font-size:1.9rem}section{background:white;margin:1rem 0;padding:1.1rem;border:1px solid #ccc;border-radius:.7rem}"
            "table{width:100%;border-collapse:collapse;word-break:break-word}th,td{border-bottom:1px solid #ddd;padding:.55rem;text-align:left}"
            "dt{font-weight:700}dd{margin:0 0 .6rem 0}code{overflow-wrap:anywhere}aside{border-left:4px solid #a36b00;padding:1rem;background:#fff6df}"
            "</style><main><h1>PRIVATE local evidence reuse &amp; change desk</h1>"
            "<aside><strong>HUMAN REVIEW ONLY · DRAFT/HOLD.</strong> Original source SHA, client/engagement "
            "labels and evidence fingerprints in this file are unauthenticated input claims. The tool never "
            "reads underlying evidence file bytes, authenticates a reviewer, issues scans/grants, or proves "
            "remediation, missing evidence, consent, legal custody or retest. Do not upload this PRIVATE report.</aside>"
            "<section><h2>Local relationship snapshot</h2><dl>" + cols + "</dl><p>Source claim digest: <code>" +
            e(current["source_sha256"]) + "</code></p><p>Self-declared PRIVATE client: " +
            e(current["client_reference"]) + " · engagement: " +
            e(current["engagement_reference"]) + "</p></section><h2>Shared fingerprints / attention</h2>" +
            sections_html + "<section><h2>Suggested HUMAN follow-up</h2><p>Confirm why one local fingerprint is " +
            "associated with several source finding IDs. Ask the original HUMAN reviewer to reconcile " +
            "different local stages. For inconsistent byte lengths reselect files in the original Ledger. " +
            "No missing local link proves a fix. The separate PRIVATE action packet contains exact " +
            "finding-specific advisory questions, NOT an original LightUp Apply or authorization.</p></section>" +
            ("<h2>Exact same-source private snapshot changes</h2>" + diff
                             if result["has_previous"] else "") +
            "<p>Work with original authenticated source and independent HUMAN review before any conclusion.</p></main></html>\n")


def private_publish(path: Path, payload: bytes) -> None:
    parent = path.parent.resolve(strict=True)
    require(path.parent == parent, "Output parent must have no alias or symlink")
    st = parent.stat()
    require(stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid() and
            st.st_mode & 0o077 == 0 and
            not path.exists() and not path.is_symlink(), "Output requires owner-private directory and unused name")
    temp = parent / (".pending-" + secrets.token_hex(12))
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temp, path, follow_symlinks=False)
        dirfd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        temp.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only PRIVATE local fingerprint reuse / drift desk (no scans)")
    parser.add_argument("current", type=Path, help="PRIVATE original ledger v1 / unified v2 JSON export (0600)")
    parser.add_argument("--previous", type=Path, help="Earlier SAME SOURCE and SAME CONTEXT PRIVATE snapshot")
    parser.add_argument("--format", choices=("inspect", "html", "counts", "actions"), default="inspect")
    parser.add_argument("--output", type=Path, help="New output in real owner-private 0700 directory")
    args = parser.parse_args()
    try:
        require((args.format == "inspect") == (args.output is None),
                "Choose --output for html/counts only; inspect writes nothing")
        current = parse_packet(args.current)
        previous = parse_packet(args.previous) if args.previous else None
        result = analyze(current, previous)
        totals = anonymous(result)
        if args.format == "inspect":
            print(json.dumps(totals, sort_keys=True, indent=2))
        else:
            output = (render(current, result).encode("utf-8") if args.format == "html"
                      else (json.dumps(proposed_actions(current, result) if args.format == "actions"
                                       else totals, sort_keys=True, indent=2) + "\n").encode("utf-8"))
            private_publish(args.output, output)
            print("PRIVATE " + args.format + " published; no original source modified.")
        return 2  # HOLD / HUMAN only, never authority exit 0
    except (Hold, OSError, ValueError) as exc:
        print("HOLD: " + str(exc), file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
