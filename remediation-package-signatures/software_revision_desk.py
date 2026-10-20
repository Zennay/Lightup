#!/usr/bin/env python3
"""Offline private diff of 2–12 independently selected ORIGINAL LightUp suites.

No verified chronology, fix, security claim, release, tenant identity,
provenance, authorization or deployment. No QA or test activity.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
from pathlib import Path
import secrets
import shutil
import sys

from inbox_reopen import inspect as inspect_original
from inbox import _import_original_install
from offline_signatures import Hold, _canonical, _pairs_no_duplicates, _regular_file_bytes, _write_new_private
from trust_registry import _json_file, _owner_private, minimum_signers

KIND = "lightup.offline.software_revision_desk.v1"
MAX_INPUTS = 12
MAX_PATHS = 256


def _entry(keyring: Path, inbox: Path, need_two: bool, ordinal: int) -> dict:
    # This calls ORIGINAL native software-source inspection and independently
    # checks all current signed ZIP/trust properties before reading anything.
    inspect_original(keyring, inbox, need_two)
    manifest = _json_file(inbox / "inbox.json")
    rows = manifest["entries"]
    if type(rows) is not list or len(rows) != 1:
        raise Hold("revision desk requires exactly one original software package per inbox")
    row = rows[0]
    # The original native software inventory is already independently
    # source-verified, but can exceed the 16-KiB local keyring-record ceiling.
    # Read it with its own bounded original source-only ceiling, still rejecting
    # duplicate JSON keys and never admitting private client evidence.
    try:
        installed = json.loads(
            _regular_file_bytes(
                inbox / row["slot"] / "manifest.json", 128 * 1024
            ).decode("utf-8"),
            object_pairs_hook=_pairs_no_duplicates,
        )
    except (ValueError, UnicodeError, TypeError) as exc:
        raise Hold("original source-locked manifest is not unambiguous JSON") from exc
    if type(installed) is not dict:
        raise Hold("original installed software manifest must be an object")
    source = installed["files"]
    if type(source) is not dict or not 1 <= len(source) <= MAX_PATHS:
        raise Hold("unrecognized native source-lock file inventory")
    normalized: dict[str, str] = {}
    for name, detail in source.items():
        if (
            type(name) is not str or len(name) > 200
            or type(detail) is not dict
            or type(detail.get("sha256")) is not str
            or len(detail["sha256"]) != 64
            or any(c not in "0123456789abcdef" for c in detail["sha256"])
        ):
            raise Hold("unrecognized original source file identity")
        normalized[name] = detail["sha256"]
    # Everything in the output is a code file path + digest, not a copy of
    # proprietary/client materials, private notes or identity records.
    return {
        "human_selected_position": ordinal,
        "software_sha256": row["original_zip_sha256"],
        "software_bytes": row["original_zip_bytes"],
        "signed_by": [s["fingerprint"] for s in row["signers"]],
        "original_source_files": normalized,
        "original_source_inventory_sha256": hashlib.sha256(
            _canonical(normalized)
        ).hexdigest(),
    }


def _diff(left: dict, right: dict) -> dict:
    a = left["original_source_files"]
    b = right["original_source_files"]
    added = sorted(set(b) - set(a))
    removed = sorted(set(a) - set(b))
    changed = sorted(name for name in set(a) & set(b) if a[name] != b[name])
    unchanged = len(set(a) & set(b)) - len(changed)
    return {
        "previous_human_selected_position": left["human_selected_position"],
        "next_human_selected_position": right["human_selected_position"],
        "software_zip_byte_identical": left["software_sha256"] == right["software_sha256"],
        "original_files_added": added,
        "original_files_removed": removed,
        "original_files_changed": changed,
        "original_files_unchanged_count": unchanged,
        "custody_keys_added": sorted(set(right["signed_by"]) - set(left["signed_by"])),
        "custody_keys_removed": sorted(set(left["signed_by"]) - set(right["signed_by"])),
    }


def _html(rows: list[dict], diffs: list[dict], require_two: bool) -> bytes:
    start = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none';",
        "style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">",
        "<title>LightUp — offline software source-difference review</title>",
        "<style>body{font:16px system-ui,sans-serif;background:#101825;color:#eff5fc;",
        "margin:2rem auto;max-width:1024px;padding:0 1rem}h1,h2{color:#fff}",
        ".hold{border:1px solid #efbe73;border-radius:8px;padding:1rem}",
        "table{width:100%;border-collapse:collapse;margin:1rem 0}",
        "td,th{padding:.7rem;border:1px solid #546172;text-align:left;",
        "vertical-align:top;word-break:break-word}th{background:#26374b}",
        "code{font-size:.83rem;color:#b9deff}ul{line-height:1.6}</style></head><body>",
        "<h1>PRIVATE LightUp software byte-difference desk</h1>",
        "<p class='hold'><strong>INCUBATE · DRAFT/HOLD · REVIEW_ONLY.</strong> ",
        "This comparison records selected package and native source-file bytes. ",
        "It does <strong>not</strong> prove update chronology, security remediation, ",
        "safe deployment, software provenance, actual signer identity, client consent, ",
        "authorization, release approval, source-owner acceptance or HUMAN GO.</p>",
        f"<p>{len(rows)} independently human-selected ORIGINAL software inboxes; ",
        "adjacent comparisons follow the <strong>operator's chosen input order only</strong>. ",
        f"Current local minimum: {'two trusted keys' if require_two else 'one trusted key'}.</p>",
        "<h2>Selected original source-only software</h2>",
        "<table><thead><tr><th>Selected position</th><th>Exact ZIP</th>",
        "<th>Original inventory</th><th>Local custody keys</th></tr></thead><tbody>",
    ]
    for row in rows:
        signers = "<br>".join("<code>" + html.escape(x[:20]) + "…</code>" for x in row["signed_by"])
        start.extend([
            "<tr>",
            f"<td>#{row['human_selected_position']:02d}</td>",
            f"<td><code>{row['software_sha256']}</code><br>{row['software_bytes']} bytes</td>",
            f"<td><code>{row['original_source_inventory_sha256']}</code><br>",
            f"{len(row['original_source_files'])} original installed files</td>",
            f"<td>{signers}</td>",
            "</tr>",
        ])
    start.extend(["</tbody></table><h2>Human-selected adjacent byte changes</h2>"])
    for diff in diffs:
        same = "same exact software ZIP bytes" if diff["software_zip_byte_identical"] else "DIFFERENT ZIP bytes, not proof of fixes"
        start.extend([
            f"<h3>Selected #{diff['previous_human_selected_position']:02d} → ",
            f"#{diff['next_human_selected_position']:02d}</h3>",
            f"<p><strong>{html.escape(same)}</strong>. ",
            f"Unchanged original file entries: {diff['original_files_unchanged_count']}.</p>",
        ])
        for field, title in (
            ("original_files_added", "Added original paths"),
            ("original_files_removed", "Removed original paths"),
            ("original_files_changed", "Changed original path contents"),
            ("custody_keys_added", "Added trusted signing-key fingerprints"),
            ("custody_keys_removed", "Absent prior signing-key fingerprints"),
        ):
            entries = diff[field]
            start.append(f"<h4>{html.escape(title)}: {len(entries)}</h4>")
            if entries:
                start.append("<ul>")
                for name in entries:
                    start.append(f"<li><code>{html.escape(name)}</code></li>")
                start.append("</ul>")
            else:
                start.append("<p>None in these two selected snapshots.</p>")
    start.extend([
        "<h2>Human review boundary</h2><p>Every input was separately admitted ",
        "by current local signer registry and the original native source-lock ",
        "inspector at report creation. Neither ZIP fingerprints nor local keys ",
        "prove original client/provider identity. A changed file is not a fixed ",
        "vulnerability; an unchanged file is not a safety finding. Refresh from ",
        "original PRIVATE inboxes after any key revocation. This saved HTML ",
        "cannot continuously check key status. No scripts, network, browser ",
        "storage or embedded confidential finding/target data.</p></body></html>",
    ])
    return "".join(start).encode("utf-8")


def build(keyring: Path, inboxes: list[Path], output: Path, require_two: bool) -> None:
    if not 2 <= len(inboxes) <= MAX_INPUTS:
        raise Hold("revision desk requires 2–12 separately admitted private inboxes")
    if len({str(p) for p in inboxes}) != len(inboxes):
        raise Hold("duplicate selected source inbox path")
    original = _import_original_install()
    _owner_private(output.parent)
    if not output.is_absolute() or output.exists() or output.is_symlink():
        raise Hold("choose fresh absolute private output directory")
    require_two = require_two or minimum_signers(keyring) == 2
    rows = [
        _entry(keyring, directory, require_two, n)
        for n, directory in enumerate(inboxes, 1)
    ]
    diffs = [_diff(a, b) for a, b in zip(rows, rows[1:])]
    receipt = {
        "format": KIND,
        "status": "PRIVATE_HUMAN_REVIEW_ONLY",
        "original_source_approval": False,
        "original_security_findings_verification": False,
        "real_customer_consent": False,
        "active_scan_authorized": False,
        "release_authorized": False,
        "verified_remediation": False,
        "human_go": False,
        "operator_order_is_verified_chronology": False,
        "current_local_two_key_minimum": require_two,
        "software_entries": rows,
        "selected_adjacent_diffs": diffs,
    }
    html_content = _html(rows, diffs, require_two)
    stage = output.parent / (".lightup-revision-desk-" + secrets.token_hex(12))
    os.mkdir(stage, 0o700)
    try:
        _write_new_private(stage / "index.html", html_content)
        _write_new_private(stage / "software-diff.json", _canonical(receipt) + b"\n")
        # Recheck current local key revocation state just before final publish.
        from trust_registry import trusted
        for row in rows:
            for fp in row["signed_by"]:
                trusted(keyring, fp)
        original.exclusive_publish(stage, output)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    print("PRIVATE REVIEW_ONLY: selected source-only software byte-difference desk:", output)
    print("Open local scriptless comparison:", output / "index.html")
    print("No real source/identity, client consent, verified fix, action or release approval.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keyring", type=Path, required=True)
    parser.add_argument("--inbox", action="append", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--require-two-signers", action="store_true")
    args = parser.parse_args()
    try:
        build(args.keyring, args.inbox, args.output_dir, args.require_two_signers)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print("HOLD:", exc, file=sys.stderr)
        return 3
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
