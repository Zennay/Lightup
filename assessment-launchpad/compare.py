#!/usr/bin/env python3
"""Private offline Lab Launchpad source-revision desk; human follow-up only.

Reads two existing source-bound human lab preparation packets, never a target.
'Missing in newer proposal' does NOT mean fixed, revoked or cleared.
"""
from __future__ import annotations

import argparse
from base64 import b64encode
from hashlib import sha256
from html import escape
import json
import os
from pathlib import Path
import sys

from build import _safe_write, Hold
from reopen import reopen, _read_private

_SCHEMA = "lightup.lab_launchpad_human_delta.v1"
_FALSE = ("authorized", "consent_verified", "dispatch_allowed", "release_allowed")
_STYLE = """
:root{background:#0b1726;color:#e9f2fb;font:16px/1.55 system-ui,sans-serif}
body{max-width:1100px;margin:auto;padding:30px 22px}
header,section{background:#172a3d;border:1px solid #46647a;border-radius:20px;padding:24px;margin-bottom:18px}
h1{font-size:2rem;margin:4px 0}h2{margin:4px 0 14px}p{color:#ccdaea}
table{border-collapse:collapse;width:100%;word-break:break-word}
th,td{text-align:left;padding:12px;border-bottom:1px solid #46647a}
code{color:#c0efcd;overflow-wrap:anywhere}aside{border:1px solid #d1a46f;border-radius:13px;padding:14px}
""".strip()


def _load(directory: str) -> dict:
    # Original source, original lab-scope, original Studio, all file hashes and
    # owner-only modes have already been independently admitted by reopen().
    count, studio = reopen(directory)
    fd = os.open(directory, os.O_RDONLY |
                 getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_DIRECTORY", 0))
    try:
        manifest = _read_private(fd, "targets.txt")
        raw_plan = _read_private(fd, "private-plan.json")
    finally:
        os.close(fd)
    plan = json.loads(raw_plan.decode("utf-8"))
    if sha256(manifest).hexdigest() != plan["manifest_sha256"]:
        raise Hold("source changed since packet reopening")
    text = manifest.decode("utf-8")
    if text != "\n".join(text.splitlines()) + "\n":
        raise Hold("noncanonical source bytes")
    endpoints = tuple(text.splitlines())
    if len(endpoints) != count:
        raise Hold("changing endpoint membership")
    return {
        "endpoints": endpoints,
        "manifest_sha256": plan["manifest_sha256"],
        "studio": studio,
        "studio_scenario_id": plan["studio_scenario_id"],
        "studio_catalog_sha256": plan["studio_catalog_sha256"],
    }


def _private_html(doc: dict) -> bytes:
    def table(name: str, entries: list[str], comment: str) -> str:
        rows = "".join(
            "<tr><th scope='row'>#" + str(i) + "</th><td><code>" +
            escape(url, quote=True) + "</code></td></tr>"
            for i, url in enumerate(entries, 1)
        ) or "<tr><td colspan='2'>No recorded proposed endpoints in this category.</td></tr>"
        return ("<section><h2>" + name + " · " + str(len(entries)) + "</h2><p>" +
                escape(comment) + "</p><table><thead><tr><th>Local ordinal</th>"
                "<th>Private proposed endpoint</th></tr></thead><tbody>" +
                rows + "</tbody></table></section>")
    style_pin = b64encode(sha256(_STYLE.encode("utf-8")).digest()).decode("ascii")
    header = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'sha256-""" + style_pin + """'; script-src 'none'; connect-src 'none'; img-src 'none'; base-uri 'none'">
<title>LightUp / Private proposal revision</title><style>""" + _STYLE + """</style></head>
<body><header><p>LIGHTUP / OFFLINE LAB PREPARATION / PRIVATE HUMAN COMPARISON</p>
<h1>What changed between two selected proposals?</h1>
<p>HUMAN REVIEW ONLY · INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NOT AUTHORIZED.</p>
<p>Before and after are human-selected labels, not verified chronology, actual customer identity or audit truth.
This file contains exact private lab URLs; share only through a separately approved private channel.</p></header>"""
    sections = table(
        "Added in selected later proposal", doc["added"],
        "A newly listed endpoint is only a proposed human lab input, never a permission or verified scan."
    ) + table(
        "Absent in selected later proposal", doc["missing"],
        "Absence cannot prove remediation, revocation, decommissioning or a security clearance."
    ) + table(
        "Unchanged exact proposal", doc["unchanged"],
        "Same text does not prove the original source, scope, ownership or consent is still valid."
    )
    footer = ("<section><aside><h2>Original authority untouched</h2><p>Studio source revision status: " +
              ("CHANGED / DIFFERENT / ABSENT" if doc["studio_revision_differs"] else "same claimed source digest") +
              ". All original hosted + permanent named VPS CI, source-owner/privacy/security review, "
              "authentic client/operator permission including action-time revocation and HUMAN GO "
              "remain separate and mandatory. Unsigned hashes are not source authentication.</p>"
              "</aside></section></body></html>")
    return (header + sections + footer).encode("utf-8")


def compare(before_dir: str, after_dir: str, output_dir: str) -> dict:
    before = _load(before_dir)
    after = _load(after_dir)
    bset, aset = set(before["endpoints"]), set(after["endpoints"])
    doc = {
        "schema": _SCHEMA, "status": "DRAFT_HOLD",
        "source_identity_authenticated": False,
        "same_client_or_engagement_authenticated": False,
        "planning_not_permission": True,
        "verified_remediation": False,
        "before_manifest_sha256": before["manifest_sha256"],
        "after_manifest_sha256": after["manifest_sha256"],
        "before_studio_catalog_sha256": before["studio_catalog_sha256"],
        "after_studio_catalog_sha256": after["studio_catalog_sha256"],
        "before_scenario_id": before["studio_scenario_id"],
        "after_scenario_id": after["studio_scenario_id"],
        "studio_revision_differs": (before["studio_catalog_sha256"],
                                    before["studio_scenario_id"]) !=
                                   (after["studio_catalog_sha256"], after["studio_scenario_id"]),
        "added": [u for u in after["endpoints"] if u not in bset],
        "missing": [u for u in before["endpoints"] if u not in aset],
        "unchanged": [u for u in after["endpoints"] if u in bset],
        **{key: False for key in _FALSE},
    }
    aggregate = {
        "schema": "lightup.lab_launchpad_delta_counts.v1",
        "status": "DRAFT_HOLD",
        "before_count": len(before["endpoints"]),
        "after_count": len(after["endpoints"]),
        "added_count": len(doc["added"]),
        "missing_count": len(doc["missing"]),
        "unchanged_count": len(doc["unchanged"]),
        "studio_revision_differs": doc["studio_revision_differs"],
        "planning_not_permission": True,
        **{key: False for key in _FALSE},
    }
    output = Path(output_dir)
    if output.name in ("", ".", "..") or not output.parent.is_dir():
        raise Hold("invalid new private output directory")
    os.mkdir(output, 0o700)
    fd = -1
    created = []
    try:
        fd = os.open(output, os.O_RDONLY |
                     getattr(os, "O_DIRECTORY", 0) |
                     getattr(os, "O_NOFOLLOW", 0))
        os.fchmod(fd, 0o700)
        items = (
            ("private-change-brief.html", _private_html(doc)),
            ("private-source-delta.json", (json.dumps(doc, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")),
            ("anonymous-counts.json", (json.dumps(aggregate, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")),
            ("START-HERE.txt", (
                "LIGHTUP / PRIVATE LAB PROPOSAL REVISION / HUMAN HOLD\n"
                "Open private-change-brief.html locally. Keep whole directory owner-private.\n"
                "No source chronology, same client, authorization, scan, vulnerability or fix is verified.\n"
                "A missing proposal is NOT an approved revocation, repair or vulnerability clearance.\n"
                "Original permissions, CI, source-owner/security/privacy and HUMAN GO still required.\n"
            ).encode("utf-8")),
        )
        for name, data in items:
            _safe_write(fd, name, data)
            created.append(name)
        os.fsync(fd)
    except BaseException:
        if fd >= 0:
            for name in reversed(created):
                try:
                    os.unlink(name, dir_fd=fd)
                except OSError:
                    pass
        try:
            os.rmdir(output)
        except OSError:
            pass
        raise
    finally:
        if fd >= 0:
            os.close(fd)
    return aggregate


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Privately compare two original launch proposals, without executing or granting anything."
    )
    parser.add_argument("--before", required=True, help="earlier owner-private packet directory")
    parser.add_argument("--after", required=True, help="later owner-private packet directory")
    parser.add_argument("--output-dir", required=True, help="new exclusive owner-private human delta directory")
    args = parser.parse_args(argv)
    try:
        summary = compare(args.before, args.after, args.output_dir)
        print("PRIVATE_LAB_PROPOSAL_DIFF_CREATED — HUMAN HOLD ONLY; " +
              "added=" + str(summary["added_count"]) +
              " absent=" + str(summary["missing_count"]) +
              " unchanged=" + str(summary["unchanged_count"]) +
              "; NO AUTHORITY")
        return 2
    except (Hold, OSError, ValueError, KeyError, TypeError, UnicodeError,
            OverflowError, RecursionError):
        print("PRIVATE_LAB_PROPOSAL_DIFF_HOLD — source changed, incompatible or inaccessible",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
