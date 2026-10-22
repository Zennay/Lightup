#!/usr/bin/env python3
"""PRIVATE HUMAN retention/source-set lineage across changing plan snapshots.

Only strict locally saved plan receipts are read. This reports observations;
it never restores HUMAN choices, deletes sources, authorizes assessment or
proves a source, person, chronology, legal hold, remediation, consent or release.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import html
import io
import json
import os
import stat
import sys
import zipfile

from history import (
    CLASSIFICATIONS,
    HOLD_FLAGS,
    HUMAN_FIELDS,
    MAX_FILES,
    MAX_RECEIPT_BYTES,
    STAGES,
    Hold,
    parse_receipt_bytes,
    publish_private,
)


def read_private_plan(path: str) -> dict:
    """Read one owner-private receipt with stable descriptor-bound bytes."""
    flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise Hold("plan could not be opened as a local regular file") from exc
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or not before.st_mode & stat.S_IRUSR
            or before.st_mode & 0o077
            or before.st_mode & 0o7000
            or not 0 < before.st_size <= MAX_RECEIPT_BYTES
        ):
            raise Hold("plan must be a bounded owner-private unlinked regular file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(MAX_RECEIPT_BYTES + 1)
        after = os.fstat(fd)
        before_identity = (
            before.st_dev, before.st_ino, before.st_size, before.st_mode,
            before.st_uid, before.st_nlink, before.st_mtime_ns, before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev, after.st_ino, after.st_size, after.st_mode,
            after.st_uid, after.st_nlink, after.st_mtime_ns, after.st_ctime_ns,
        )
        if len(raw) != before.st_size or before_identity != after_identity:
            raise Hold("plan changed or exceeded its bounded read")
        return parse_receipt_bytes(raw)
    except OSError as exc:
        raise Hold("plan could not be securely read") from exc
    finally:
        os.close(fd)


def compose_history(plans: list[dict]) -> dict:
    """Compare changing source membership without carrying HUMAN choices."""
    if not 2 <= len(plans) <= MAX_FILES:
        raise Hold("two to twelve intentionally ordered plans required")

    sizes: dict[str, int] = {}
    for plan in plans:
        for digest, row in plan.items():
            previous_size = sizes.get(digest)
            if previous_size is not None and previous_size != row["bytes"]:
                raise Hold("same source digest has conflicting declared byte lengths")
            sizes[digest] = row["bytes"]

    prefixes: dict[str, str] = {}
    for digest in sizes:
        prefix = digest[:20]
        if prefix in prefixes and prefixes[prefix] != digest:
            raise Hold("ambiguous private digest prefix; no report produced")
        prefixes[prefix] = digest

    summaries = []
    for index, plan in enumerate(plans):
        counts = {stage: sum(row["status"] == stage for row in plan.values())
                  for stage in STAGES}
        if index == 0:
            added = absent = unchanged = changed = None
        else:
            previous = plans[index - 1]
            before_keys, current_keys = set(previous), set(plan)
            continuing = before_keys & current_keys
            added = len(current_keys - before_keys)
            absent = len(before_keys - current_keys)
            changed = sum(
                any(previous[key][field] != plan[key][field] for field in HUMAN_FIELDS)
                for key in continuing
            )
            unchanged = len(continuing) - changed
        summaries.append({
            "plan_number": index + 1,
            "source_count": len(plan),
            "added_since_previous": added,
            "absent_since_previous": absent,
            "continuing_rows_unchanged": unchanged,
            "continuing_rows_with_human_changes": changed,
            "stage_counts": counts,
        })

    details = []
    for digest in sorted(sizes):
        for index, plan in enumerate(plans):
            row = plan.get(digest)
            previous = plans[index - 1] if index else {}
            prior = previous.get(digest)
            if index == 0:
                presence = "PRESENT_IN_BASELINE" if row else "ABSENT_FROM_BASELINE"
            elif row and prior:
                presence = "PRESENT_IN_ADJACENT_PLANS"
            elif row:
                appeared_before = any(digest in earlier for earlier in plans[:index - 1])
                presence = "REAPPEARED_AFTER_GAP" if appeared_before else "NEW_IN_SELECTED_PLAN"
            elif prior:
                presence = "ABSENT_FROM_SELECTED_PLAN"
            else:
                presence = "ABSENT"
            changed_fields = [
                field for field in HUMAN_FIELDS
                if row is not None and prior is not None and row[field] != prior[field]
            ]
            details.append({
                "digest_prefix": digest[:20],
                "bytes": sizes[digest],
                "plan_number": index + 1,
                "presence": presence,
                "status": row["status"] if row else "",
                "review_date": row["review_date"] if row else "",
                "custodian_declared": bool(row["custodian"].strip()) if row else None,
                "classification": row["classification"] if row else "",
                "hold_flag": row["hold_flag"] if row else "",
                "changed_fields": changed_fields,
            })

    return {
        "plan_count": len(plans),
        "source_union_count": len(sizes),
        "plan_summaries": summaries,
        "source_plan_rows": details,
    }


def render_html(history: dict, *, original_bytes_rehashed: bool = False) -> str:
    esc = lambda value: html.escape(str(value), quote=True)
    summary_rows = []
    for item in history["plan_summaries"]:
        summary_rows.append("<tr>" + "".join(
            "<td>" + esc(item[key] if item[key] is not None else "—") + "</td>"
            for key in (
                "plan_number", "source_count", "added_since_previous",
                "absent_since_previous", "continuing_rows_unchanged",
                "continuing_rows_with_human_changes",
            )
        ) + "".join(
            "<td>" + esc(item["stage_counts"][stage]) + "</td>"
            for stage in STAGES
        ) + "</tr>")

    detail_rows = []
    for item in history["source_plan_rows"]:
        detail_rows.append("<tr>" + "".join(
            "<td>" + esc(value) + "</td>" for value in (
                item["digest_prefix"], item["bytes"], item["plan_number"],
                item["presence"], STAGES.get(item["status"], "—"),
                item["review_date"] or "—",
                "Yes" if item["custodian_declared"] is True else
                ("No" if item["custodian_declared"] is False else "—"),
                CLASSIFICATIONS.get(item["classification"], "—"),
                HOLD_FLAGS.get(item["hold_flag"], "—"),
                ", ".join(item["changed_fields"]) or "—",
            )
        ) + "</tr>")

    page = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; connect-src 'none'; img-src 'none'; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'">
<title>PRIVATE HUMAN source-set lineage</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:1450px;margin:2rem auto;padding:1rem;color:#172130}
.banner{border:2px solid #8b5a18;background:#fff4df;padding:1rem;border-radius:8px}
.scroll{overflow-x:auto}table{border-collapse:collapse;width:100%;margin:1rem 0 2rem}
th,td{border:1px solid #b7c3cf;padding:.45rem;text-align:left;vertical-align:top;overflow-wrap:anywhere}
th{background:#eaf0f5}.presence{font-weight:600}
@media print{body{margin:0;font-size:10px}.scroll{overflow:visible}tr{break-inside:avoid}th,td{padding:3px}}</style>
</head><body>
<h1>PRIVATE HUMAN source-set lineage</h1>
<p class="banner"><strong>REVIEW_ONLY / HOLD · INCUBATE M3/M7 PLAN/LAB ONLY.</strong>
Plan order is selected manually and is not authenticated chronology. A source absent from a
selected plan is not evidence of deletion, remediation, revocation or clearance. HUMAN fields
are unverified proposals; this report does not carry decisions across plans, change files,
contact clients, scan targets, grant authority or authorize release. Keep private.</p>
<p>Plans compared: <strong>__PLANS__</strong>. Distinct SHA-prefix/size identities across the
selected snapshots: <strong>__SOURCES__</strong>. Source contents, aliases, free-text actions,
filenames and full digests are deliberately excluded; digest prefixes and stage/hold categories
remain sensitive and are not anonymous.</p>
<h2>Per-plan membership and HUMAN stage counts</h2><div class="scroll"><table><thead><tr>
<th scope="col">Manual plan</th><th scope="col">Selected sources</th><th scope="col">New vs prior</th>
<th scope="col">Absent vs prior</th><th scope="col">Continuing rows unchanged</th>
<th scope="col">Continuing rows with HUMAN changes</th>__STAGE_HEAD__</tr></thead>
<tbody>__SUMMARY_ROWS__</tbody></table></div>
<h2>Source-by-plan lineage</h2><div class="scroll"><table><thead><tr>
<th scope="col">Private SHA-256 prefix</th><th scope="col">Bytes</th><th scope="col">Manual plan</th>
<th scope="col">Membership observation</th><th scope="col">HUMAN stage</th><th scope="col">Proposed review date</th>
<th scope="col">Custodian declared</th><th scope="col">HUMAN sensitivity</th>
<th scope="col">HUMAN hold declaration</th><th scope="col">Changed HUMAN field names vs adjacent plan</th>
</tr></thead><tbody>__DETAIL_ROWS__</tbody></table></div>
<p><strong>Interpretation:</strong> “New” and “absent” compare only adjacent selected snapshots.
“Reappeared after gap” means a digest is present after being absent from at least one selected plan;
it does not establish why. HUMAN field-change names reveal no alias or free-text content. The
__SOURCE_BINDING_NOTE__ Follow the original source-owner and
security/privacy/consent gates independently.</p>
</body></html>"""
    stage_heads = "".join("<th scope='col'>" + esc(STAGES[stage]) + "</th>" for stage in STAGES)
    binding_note = (
        "<strong>Encrypted workflow:</strong> for each vault, the separately selected original "
        "source bytes were re-hashed and the complete SHA-256/size membership matched. This proves "
        "local byte equality only, not external producer identity, person, legal retention, "
        "verified consent, authorization, remediation or release."
        if original_bytes_rehashed else
        "<strong>Plaintext-plan workflow:</strong> this report compares the source digest/size "
        "declarations inside the selected plan receipts; it does not re-open the original assets. "
        "It does not authenticate producer identity, person, legal retention, verified consent, "
        "authorization, remediation or release."
    )
    return (page.replace("__SOURCE_BINDING_NOTE__", binding_note)
            .replace("__PLANS__", esc(history["plan_count"]))
            .replace("__SOURCES__", esc(history["source_union_count"]))
            .replace("__STAGE_HEAD__", stage_heads)
            .replace("__SUMMARY_ROWS__", "".join(summary_rows))
            .replace("__DETAIL_ROWS__", "".join(detail_rows)))


MAX_BUNDLE_BYTES = 32 * 1024 * 1024
BUNDLE_SCHEMA = "lightup.private_human_source_set_lineage.v1"
BUNDLE_ROWS = (
    "digest_prefix", "bytes", "plan_number", "presence", "status",
    "review_date", "custodian_declared", "classification", "hold_flag",
    "changed_fields",
)


def render_csv(history: dict) -> bytes:
    """Create a flat, source-minimal table; no paths, aliases or free-text fields."""
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\\n")
    writer.writerow((
        "plan_number", "source_sha256_prefix", "source_bytes", "membership_observation",
        "human_stage", "proposed_review_date", "custodian_declared",
        "human_sensitivity", "human_hold_declaration", "changed_human_field_names",
    ))
    for item in history["source_plan_rows"]:
        writer.writerow((
            item["plan_number"], item["digest_prefix"], item["bytes"], item["presence"],
            STAGES.get(item["status"], ""), item["review_date"] or "",
            "" if item["custodian_declared"] is None else str(item["custodian_declared"]).lower(),
            CLASSIFICATIONS.get(item["classification"], ""),
            HOLD_FLAGS.get(item["hold_flag"], ""),
            ";".join(item["changed_fields"]),
        ))
    return output.getvalue().encode("utf-8")


def render_json(history: dict, *, original_bytes_rehashed: bool = False) -> bytes:
    """Export only enum/date/prefix/count metadata, never original free text or full digests."""
    boundary = (
        "ORIGINAL_SOURCE_BYTES_REHASHED_PER_SNAPSHOT"
        if original_bytes_rehashed else "PLAN_DECLARATIONS_ONLY"
    )
    rows = [{key: row[key] for key in BUNDLE_ROWS}
            for row in history["source_plan_rows"]]
    document = {
        "schema": BUNDLE_SCHEMA,
        "status": "REVIEW_ONLY",
        "evidence_boundary": boundary,
        "manual_plan_order": True,
        "chronology_authenticated": False,
        "source_identity_authenticated": False,
        "authorization_granted": False,
        "consent_verified": False,
        "remediation_proven": False,
        "release_allowed": False,
        "plan_count": history["plan_count"],
        "source_union_count": history["source_union_count"],
        "plan_summaries": history["plan_summaries"],
        "source_plan_rows": rows,
    }
    return (json.dumps(
        document, sort_keys=True, ensure_ascii=True, separators=(",", ":")
    ) + "\\n").encode("utf-8")


def render_bundle(history: dict, *, original_bytes_rehashed: bool = False) -> bytes:
    """Create one bounded, deterministic, private ZIP with HTML, CSV, JSON and caveats."""
    artifacts = [
        ("source-set-lineage.html", render_html(
            history, original_bytes_rehashed=original_bytes_rehashed
        ).encode("utf-8")),
        ("source-set-lineage.csv", render_csv(history)),
        ("source-set-lineage.json", render_json(
            history, original_bytes_rehashed=original_bytes_rehashed
        )),
        ("README.txt", (
            "LIGHTUP PRIVATE HUMAN SOURCE-SET LINEAGE BUNDLE\\n"
            "REVIEW_ONLY / HOLD — INCUBATE M3/M7 PLAN/LAB ONLY.\\n\\n"
            "The HTML is scriptless. CSV and JSON include only private digest prefixes, byte sizes, "
            "manually ordered plan numbers, membership observations, HUMAN enum/date metadata and "
            "changed field names. No source paths, aliases, free-text actions, full source digests "
            "or original source contents are included.\\n\\n"
            "Evidence boundary: " + (
                "original bytes were re-hashed separately for every encrypted plan and their complete "
                "digest/size sets matched locally. This does not authenticate external identity."
                if original_bytes_rehashed else
                "source digest/size values are declarations from the selected plan receipts; original "
                "assets were not re-opened by this workflow."
            ) + "\\n"
            "Plan order is manually selected, not authenticated chronology. Missing from a snapshot "
            "does not mean deletion, remediation, revocation or clearance. Nothing in this bundle "
            "proves a person, consent, legal retention, source identity, authorization or release. "
            "No assessment, scan, client contact or other action is performed.\\n\\n"
            "This bundle and its reports are sensitive and unsigned. The included manifest hashes "
            "check local artifact byte integrity only; they are not signatures or provenance. Keep "
            "the bundle in owner-private storage.\\n"
        ).encode("utf-8")),
    ]
    manifest = [
        "LIGHTUP PRIVATE REPORT ARTIFACT MANIFEST",
        "UNSIGNED — local artifact integrity only; not source provenance or authorization.",
    ]
    for name, raw in artifacts:
        manifest.append(hashlib.sha256(raw).hexdigest() + "  " + name)
    artifacts.append(("MANIFEST.txt", ("\\n".join(manifest) + "\\n").encode("utf-8")))

    buffer = io.BytesIO()
    try:
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED,
                             compresslevel=9, strict_timestamps=True) as archive:
            for name, raw in artifacts:
                info = zipfile.ZipInfo(name, date_time=(2026, 10, 22, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o600) << 16
                archive.writestr(info, raw, compress_type=zipfile.ZIP_DEFLATED,
                                 compresslevel=9)
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile) as exc:
        raise Hold("private lineage bundle could not be composed") from exc
    raw_bundle = buffer.getvalue()
    if not 1 <= len(raw_bundle) <= MAX_BUNDLE_BYTES:
        raise Hold("private lineage bundle exceeds the bounded archive size")
    return raw_bundle


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare 2–12 PRIVATE HUMAN plans with changing source membership; read-only"
    )
    outputs = parser.add_mutually_exclusive_group(required=True)
    outputs.add_argument("--output",
                         help="New HTML report inside an existing owner-owned 0700 directory")
    outputs.add_argument("--bundle-output",
                         help="New private ZIP containing scriptless HTML, CSV, JSON and caveats")
    parser.add_argument("plans", nargs="+",
                        help="2–12 owner-private HUMAN plan JSON files in manually chosen order")
    args = parser.parse_args()
    if not 2 <= len(args.plans) <= MAX_FILES:
        parser.error("two to twelve original HUMAN plan files required")
    try:
        plans = [read_private_plan(path) for path in args.plans]
        history = compose_history(plans)
        if args.bundle_output:
            publish_private(args.bundle_output, render_bundle(history))
        else:
            publish_private(args.output, render_html(history))
    except (Hold, OSError, ValueError, TypeError, MemoryError, RecursionError, UnicodeError) as exc:
        parser.exit(2, "HOLD: PRIVATE source-set lineage not admitted; no report published.\n")
    print("REVIEW_ONLY: PRIVATE HUMAN source-set lineage report created; no authority or release.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
