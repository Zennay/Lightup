#!/usr/bin/env python3
"""Offline PRIVATE original-scope distribution change briefing for HUMAN review.

Compare two existing LightUp SOURCE-MANIFEST.json inventories, never accept
them as signatures or authorization. No execution/network/scan/test framework.
"""
from __future__ import annotations
import csv
import io
import hashlib
import html
import json
import os
from pathlib import Path
import re
import sys

MAX_INPUT = 1_000_000
MAX_ENTRIES = 256
HEX = re.compile(r"^[0-9a-f]{64}$")
VALID_PATH = re.compile(r"^[A-Za-z0-9_./-]{1,240}$")
AUTHORITY = {"client_consent", "operator_consent", "grant", "scan", "deploy", "release"}

def no_duplicates(pairs):
    obj = {}
    for k, v in pairs:
        if k in obj:
            raise ValueError("Ambiguous duplicate JSON member: " + k)
        obj[k] = v
    return obj

def source(path):
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= MAX_INPUT:
        raise ValueError("Missing, linked or oversized original source inventory")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        with os.fdopen(fd, "rb") as f:
            raw = f.read(MAX_INPUT + 1)
    finally:
        pass
    if len(raw) > MAX_INPUT:
        raise ValueError("Input byte limit")
    doc = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=no_duplicates)
    if type(doc) is not dict or doc.get("format") != "lightup.scope_offline_bundle.v1" or doc.get("posture") != "INCUBATE_M3_M7_DRAFT_HOLD":
        raise ValueError("Unexpected source inventory or posture")
    flags = doc.get("authority")
    if type(flags) is not dict or set(flags) != AUTHORITY or any(value is not False for value in flags.values()):
        raise ValueError("Authority field must stay literal false")
    heads = doc.get("pinned_original_branch_heads")
    if type(heads) is not dict or len(heads) != 8 or any(type(k) is not str or type(v) is not str or not re.fullmatch(r"[0-9a-f]{40}", v) for k, v in heads.items()):
        raise ValueError("Malformed original HEAD declarations")
    rows = doc.get("file_entries")
    if type(rows) is not list or not 1 <= len(rows) <= MAX_ENTRIES:
        raise ValueError("Malformed or oversized file inventory")
    files = {}
    for row in rows:
        if type(row) is not dict or set(row) != {"path", "size", "sha256"}:
            raise ValueError("Malformed original file row")
        name, size, dig = row["path"], row["size"], row["sha256"]
        if type(name) is not str or not VALID_PATH.fullmatch(name) or name.startswith("/") or any(part in ("", ".", "..") for part in name.split("/")):
            raise ValueError("Unsafe original file path")
        if type(size) is not int or not 0 <= size <= 8_000_000 or type(dig) is not str or not HEX.fullmatch(dig) or name in files:
            raise ValueError("Invalid size/hash or duplicate file path")
        files[name] = (size, dig)
    return files, heads, hashlib.sha256(raw).hexdigest()

def require_fresh_private_directory(path):
    if path.is_symlink() or path.exists():
        raise ValueError("Private output must not exist already; choose a fresh folder")
    path.mkdir(mode=0o700, parents=False)
    os.chmod(path, 0o700)

def write_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as file:
        file.write(data)
        file.flush()
        os.fsync(file.fileno())

def render_page(rows, first_hash, second_hash, heads_changed):
    counts = {kind: sum(1 for row in rows if row[1] == kind) for kind in ("unchanged", "changed", "added", "absent")}
    tr = "".join(
        "<tr><td>" + html.escape(name) + "</td><td>" + status.upper() +
        "</td><td>" + (html.escape(old[:12]) if old else "—") + "</td><td>" +
        (html.escape(new[:12]) if new else "—") + "</td></tr>"
        for name, status, old, new in rows
    )
    return ("""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>LightUp PRIVATE source change brief · HOLD</title><style>body{font:16px system-ui;max-width:1100px;margin:2rem auto;padding:0 1rem;background:#101927;color:#eff5ff}h1{font-size:1.8rem}p{line-height:1.55}.flag{font-weight:bold;color:#ffd381}table{width:100%;border-collapse:collapse}th,td{text-align:left;border-bottom:1px solid #34465e;padding:.75rem;overflow-wrap:anywhere}tr:nth-child(2n){background:#19263b}small{display:block;color:#b5cee8}</style><main><h1>LightUp · PRIVATE original-source change brief</h1><p class="flag">INCUBATE M3/M7 · HUMAN REVIEW ONLY · HOLD · no authorized grants, live scans, release or client consent.</p><p>Unsigned source byte fingerprints are NOT source authentication, revocation proof or risk verdict. An absent locally selected file does not mean a fix, withdrawal or deletion. All changed and added files require HUMAN re-review.</p><p>Unchanged: """ + str(counts["unchanged"]) + " · Changed: " + str(counts["changed"]) + " · Added: " + str(counts["added"]) + " · Absent: " + str(counts["absent"]) + "</p><p>Original companion declared HEADs differ: " + ("YES — HUMAN source review" if heads_changed else "NO (not proof of actual ownership)") + "</p><small>Previous unsigned input SHA-256: " + first_hash + "<br>Current unsigned input SHA-256: " + second_hash + "</small><table><thead><tr><th>Original package path (PRIVATE)</th><th>HUMAN review</th><th>Old hash prefix</th><th>New hash prefix</th></tr></thead><tbody>" + tr + "</tbody></table><p class='flag'>No change automatically authorizes, revokes, scans, deploys or verifies anything.</p></main></html>").encode("utf-8")

def main(argv):
    if len(argv) != 4:
        raise ValueError("usage: python3 change_brief.py PREVIOUS-SOURCE-MANIFEST.json CURRENT-SOURCE-MANIFEST.json NEW-PRIVATE-OUTPUT-DIR")
    old, old_heads, old_hash = source(Path(argv[1]))
    new, new_heads, new_hash = source(Path(argv[2]))
    rows = []
    for name in sorted(old.keys() | new.keys()):
        before, after = old.get(name), new.get(name)
        state = "absent" if after is None else "added" if before is None else "unchanged" if before == after else "changed"
        rows.append((name, state, before[1] if before else "", after[1] if after else ""))
    output = Path(argv[3])
    if not output.parent.is_dir() or output.parent.is_symlink():
        raise ValueError("Fresh output must have an existing ordinary parent directory")
    require_fresh_private_directory(output)
    write_private(output / "index.html", render_page(rows, old_hash, new_hash, old_heads != new_heads))
    # Fully source-byte-bound PRIVATE human assignment template, not permission.
    template = io.StringIO(newline="")
    writer = csv.writer(template, lineterminator="\\n")
    writer.writerow(("previous_manifest_sha256", "current_manifest_sha256",
                     "source_file_path", "change_status", "previous_sha256",
                     "current_sha256", "human_stage", "human_team", "human_notes"))
    for name, state, previous, current in rows:
        writer.writerow((old_hash, new_hash, name, state, previous, current,
                         "unreviewed", "", ""))
    write_private(output / "human-review-template.csv", template.getvalue().encode("utf-8"))
    # Intentionally path-free anonymous count export (no source names or hashes).
    counts = {kind: sum(1 for row in rows if row[1] == kind) for kind in ("unchanged", "changed", "added", "absent")}
    counts["original_heads_changed"] = old_heads != new_heads
    counts["authority"] = {key: False for key in sorted(AUTHORITY)}
    counts["posture"] = "INCUBATE_M3_M7_DRAFT_HOLD"
    write_private(output / "anonymous-counts.json", (json.dumps(counts, indent=2, sort_keys=True) + "\n").encode())
    print("PRIVATE review:", output / "index.html")
    print("HUMAN attention (not authority):", counts)

if __name__ == "__main__":
    try:
        main(sys.argv)
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        print("HOLD:", type(exc).__name__, str(exc), file=sys.stderr)
        sys.exit(3)
