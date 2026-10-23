#!/usr/bin/env python3
"""PRIVATE offline review ledger for already-generated LightUp assessment kits.

No scans, remote I/O, target discovery, grants, authorization, or destructive cleanup.
Exit 2 = PRIVATE REVIEW_ONLY artifact produced/unchanged; exit 3 = HOLD.
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
from browser_studio import render_studio
import shutil
import stat
import sys
import tempfile

MAX_KITS = 12
MAX_FILES = 256
MAX_KIT_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 5
MAX_MANIFEST = 1024 * 1024
MAX_CSV = 64 * 1024
STAGES = ("needs_review", "owner_followup", "hold", "reference_only")
CSV_HEADERS = ("ordinal", "ledger_sha256", "kit_digest", "stage", "owner", "question")
FLAGS = {
    "authorization": False,
    "consent": False,
    "verified_finding": False,
    "verified_remediation": False,
    "release_approval": False,
    "source_authentication": False,
}


class Hold(Exception):
    pass


def reject(message="PRIVATE HOLD: invalid or changed source"):
    raise Hold(message)


def digest(blob):
    return hashlib.sha256(blob).hexdigest()


def object_unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            reject("PRIVATE HOLD: duplicate JSON key")
        result[key] = value
    return result


def read_owner_file(path, limit):
    p = Path(path)
    if not p.is_absolute():
        reject("PRIVATE HOLD: absolute path required")
    with open_dir(str(p.parent)) as parent:
        fd = os.open(p.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent.fd)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                    info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > limit):
                reject("PRIVATE HOLD: source file must be owner-only regular and bounded")
            chunks = []
            total = 0
            while True:
                block = os.read(fd, 65536)
                if not block:
                    break
                total += len(block)
                if total > limit:
                    reject("PRIVATE HOLD: source file exceeds limit")
                chunks.append(block)
            after = os.fstat(fd)
            if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
            ):
                reject("PRIVATE HOLD: source changed during read")
            return b"".join(chunks)
        finally:
            os.close(fd)


class Dir:
    def __init__(self, fd):
        self.fd = fd

    def __enter__(self):
        return self

    def __exit__(self, *_):
        os.close(self.fd)


def open_dir(path):
    """Open every path component with O_NOFOLLOW; do not trust resolve() of a symlink."""
    if not os.path.isabs(path) or "\x00" in path:
        reject("PRIVATE HOLD: absolute private directory required")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in Path(os.path.normpath(path)).parts[1:]:
            new = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = new
        return Dir(fd)
    except BaseException:
        os.close(fd)
        raise


def private_directory(fd):
    s = os.fstat(fd)
    if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.geteuid() or s.st_mode & 0o077:
        reject("PRIVATE HOLD: kit/output folder must be owned by current user and deny group/other")


def file_inventory(kit_path):
    files = []
    seen_dirs = set()
    seen_files = set()
    total = 0

    def walk(fd, prefix, depth):
        nonlocal total
        if depth > MAX_DEPTH:
            reject("PRIVATE HOLD: kit nesting limit")
        private_directory(fd)
        ds = os.fstat(fd)
        ident = (ds.st_dev, ds.st_ino)
        if ident in seen_dirs:
            reject("PRIVATE HOLD: repeated directory")
        seen_dirs.add(ident)
        with os.scandir(fd) as iterator:
            entries = sorted(iterator, key=lambda entry: entry.name)
        for entry in entries:
            name = entry.name
            if name in (".", "..") or "/" in name or "\x00" in name:
                reject("PRIVATE HOLD: unsafe file name")
            s = os.stat(name, dir_fd=fd, follow_symlinks=False)
            rel = prefix + name
            if stat.S_ISDIR(s.st_mode):
                next_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                try:
                    walk(next_fd, rel + "/", depth + 1)
                finally:
                    os.close(next_fd)
                continue
            if not stat.S_ISREG(s.st_mode) or s.st_uid != os.geteuid() or s.st_mode & 0o077:
                reject("PRIVATE HOLD: symlink/non-private/special file in kit")
            if s.st_size > MAX_FILE_BYTES or s.st_nlink != 1 or len(files) >= MAX_FILES:
                reject("PRIVATE HOLD: kit file limit or hardlink")
            fid = (s.st_dev, s.st_ino)
            if fid in seen_files:
                reject("PRIVATE HOLD: repeated file identity")
            seen_files.add(fid)
            if total + s.st_size > MAX_KIT_BYTES:
                reject("PRIVATE HOLD: kit byte limit")
            file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=fd)
            try:
                before = os.fstat(file_fd)
                if (not stat.S_ISREG(before.st_mode)
                        or before.st_uid != os.geteuid()
                        or before.st_mode & 0o077
                        or before.st_nlink != 1
                        or (before.st_dev, before.st_ino, before.st_size,
                            before.st_mtime_ns, before.st_ctime_ns) !=
                           (s.st_dev, s.st_ino, s.st_size,
                            s.st_mtime_ns, s.st_ctime_ns)):
                    reject("PRIVATE HOLD: opened original kit file identity or privacy changed")
                h = hashlib.sha256()
                amount = 0
                while True:
                    chunk = os.read(file_fd, 65536)
                    if not chunk:
                        break
                    amount += len(chunk)
                    if amount > MAX_FILE_BYTES:
                        reject("PRIVATE HOLD: source size changed")
                    h.update(chunk)
                after = os.fstat(file_fd)
                original = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                now = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                if original != now or amount != before.st_size or (s.st_dev, s.st_ino, s.st_size) != (
                    before.st_dev, before.st_ino, before.st_size
                ):
                    reject("PRIVATE HOLD: kit mutated during snapshot")
                files.append({"path": rel, "size": amount, "sha256": h.hexdigest()})
                total += amount
            finally:
                os.close(file_fd)

    with open_dir(kit_path) as root:
        walk(root.fd, "", 0)
    if not files:
        reject("PRIVATE HOLD: empty kit")
    return sorted(files, key=lambda row: row["path"]), total


def manifest_from_source(raw):
    if not raw or len(raw) > MAX_MANIFEST:
        reject("PRIVATE HOLD: ledger length")
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=object_unique,
                         parse_constant=lambda _: reject("PRIVATE HOLD: nonfinite JSON"))
    except (UnicodeError, ValueError, TypeError) as exc:
        raise Hold("PRIVATE HOLD: malformed ledger") from exc
    if not isinstance(doc, dict) or set(doc) != {"schema", "authority", "kits", "previous_sha256"}:
        reject("PRIVATE HOLD: ledger schema")
    if doc["schema"] != "lightup.private.workspace-ledger.v1" or doc["authority"] != FLAGS:
        reject("PRIVATE HOLD: ledger is not a permission")
    kits = doc["kits"]
    if not isinstance(kits, list) or not 1 <= len(kits) <= MAX_KITS:
        reject("PRIVATE HOLD: kit count")
    used = set()
    total = 0
    for ordinal, kit in enumerate(kits, 1):
        if not isinstance(kit, dict) or set(kit) != {"ordinal", "path", "label", "files", "bytes", "digest", "delta"}:
            reject("PRIVATE HOLD: kit record schema")
        path = kit["path"]
        if not isinstance(path, str) or not os.path.isabs(path) or len(path) > 4096 or path in used:
            reject("PRIVATE HOLD: private kit path")
        if os.path.normpath(path) != path:
            reject("PRIVATE HOLD: noncanonical kit path")
        used.add(path)
        label = kit["label"]
        if not isinstance(label, str) or not 1 <= len(label) <= 96 or any(ord(c) < 32 for c in label):
            reject("PRIVATE HOLD: bounded label")
        if type(kit["ordinal"]) is not int or kit["ordinal"] != ordinal:
            reject("PRIVATE HOLD: kit ordinal")
        f = kit["files"]
        if not isinstance(f, list) or not 1 <= len(f) <= MAX_FILES:
            reject("PRIVATE HOLD: kit file list")
        seen = set()
        size = 0
        for row in f:
            if not isinstance(row, dict) or set(row) != {"path", "size", "sha256"}:
                reject("PRIVATE HOLD: file record schema")
            name = row["path"]
            if not isinstance(name, str) or not name or len(name) > 4096 or name in seen:
                reject("PRIVATE HOLD: file path")
            parts = name.split("/")
            if len(parts) > MAX_DEPTH + 1 or any(part in ("", ".", "..") for part in parts):
                reject("PRIVATE HOLD: file path traversal")
            seen.add(name)
            if type(row["size"]) is not int or not 0 <= row["size"] <= MAX_FILE_BYTES:
                reject("PRIVATE HOLD: file size")
            if not hexhash(row["sha256"]):
                reject("PRIVATE HOLD: file hash")
            size += row["size"]
        if sorted(seen) != [row["path"] for row in f]:
            reject("PRIVATE HOLD: unsorted entries")
        if type(kit["bytes"]) is not int or kit["bytes"] != size or size > MAX_KIT_BYTES:
            reject("PRIVATE HOLD: kit bytes")
        total += size
        if not hexhash(kit["digest"]) or kit["digest"] != digest(canonical(f)):
            reject("PRIVATE HOLD: file inventory digest")
        d = kit["delta"]
        if d is not None and (not isinstance(d, dict) or set(d) != {"added", "removed", "changed"} or
                              any(type(d[k]) is not int or d[k] < 0 or d[k] > MAX_FILES for k in d)):
            reject("PRIVATE HOLD: kit delta")
    if total > MAX_TOTAL_BYTES or (doc["previous_sha256"] is not None and not hexhash(doc["previous_sha256"])):
        reject("PRIVATE HOLD: ledger bounds")
    return doc


def hexhash(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def outside_checkout(path):
    repo = Path(__file__).resolve().parent.parent
    location = Path(path)
    if location == repo or repo in location.parents:
        reject("PRIVATE HOLD: customer/private data must stay outside source checkout")


def private_parent(path):
    outside_checkout(path)
    with open_dir(path) as folder:
        private_directory(folder.fd)
    return str(Path(path))


def write_private(directory, filename, content):
    fd = os.open(str(Path(directory) / filename),
                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        data = content.encode("utf-8") if isinstance(content, str) else content
        cursor = 0
        while cursor < len(data):
            cursor += os.write(fd, data[cursor:])
        os.fsync(fd)
    finally:
        os.close(fd)


def new_private(parent):
    private_parent(parent)
    path = tempfile.mkdtemp(prefix="PRIVATE-lightup-ledger-", dir=parent)
    os.chmod(path, 0o700)
    return path


def html_page(title, body):
    style = ("body{font:16px system-ui,sans-serif;line-height:1.55;max-width:920px;margin:2em auto;"
             "padding:0 1em;color:#172b40;background:#f7f9fd}main,section{background:white;"
             "border:1px solid #cad4df;padding:1.2em;margin:1em 0;border-radius:12px}"
             "th,td{padding:.45em;border-bottom:1px solid #ddd;text-align:left}"
             "table{width:100%;border-collapse:collapse}code{overflow-wrap:anywhere}")
    return ("<!doctype html><html lang='en'><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'; "
            "img-src 'none'; connect-src 'none'; form-action 'none'; base-uri 'none'\">"
            "<title>" + html.escape(title) + "</title><style>" + style +
            "</style><main><h1>" + html.escape(title) + "</h1>"
            "<p><strong>PRIVATE · REVIEW ONLY · DRAFT/HOLD.</strong> Local unsigned byte inventory. "
            "No source authentication, client/operator consent, verified remediation, permission, "
            "PASS, release, remote sharing, scan or deployment. A removed file is not a fix.</p>" + body +
            "</main></html>")


def capture(args):
    if not 1 <= len(args.kit) <= MAX_KITS:
        reject("PRIVATE HOLD: 1–12 kits required")
    if args.label and len(args.label) != len(args.kit):
        reject("PRIVATE HOLD: labels must match kit count")
    previous_raw = None
    previous = None
    if args.previous:
        previous_raw = read_owner_file(args.previous, MAX_MANIFEST)
        previous = manifest_from_source(previous_raw)
        if len(previous["kits"]) != len(args.kit):
            reject("PRIVATE HOLD: same kit positions required for comparison")
    kits = []
    combined = 0
    paths = set()
    changed = False
    for number, value in enumerate(args.kit, 1):
        path = os.path.normpath(value)
        if path != value or path in paths or not os.path.isabs(path):
            reject("PRIVATE HOLD: duplicate or noncanonical kit path")
        outside_checkout(path)
        for earlier in paths:
            if os.path.commonpath((path, earlier)) in (path, earlier):
                reject("PRIVATE HOLD: overlapping kit roots")
        parent = os.path.normpath(args.private_parent)
        if os.path.commonpath((parent, path)) == path:
            reject("PRIVATE HOLD: output parent cannot be nested inside source kit")
        paths.add(path)
        label = args.label[number - 1] if args.label else "PRIVATE kit " + str(number)
        if not 1 <= len(label) <= 96 or any(ord(c) < 32 for c in label):
            reject("PRIVATE HOLD: invalid label")
        files, amount = file_inventory(path)
        combined += amount
        if combined > MAX_TOTAL_BYTES:
            reject("PRIVATE HOLD: combined byte limit")
        delta = None
        if previous:
            old = previous["kits"][number - 1]
            if old["path"] != path:
                reject("PRIVATE HOLD: previous snapshot refers to different kit")
            before = {r["path"]: r["sha256"] for r in old["files"]}
            after = {r["path"]: r["sha256"] for r in files}
            delta = {
                "added": len(after.keys() - before.keys()),
                "removed": len(before.keys() - after.keys()),
                "changed": sum(before[key] != after[key] for key in before.keys() & after.keys()),
            }
            # A human dossier-label change is source-context drift, even when kit bytes match.
            changed |= any(delta.values()) or old["label"] != label
        kits.append({"ordinal": number, "path": path, "label": label, "files": files, "bytes": amount,
                     "digest": digest(canonical(files)), "delta": delta})
    doc = {"schema": "lightup.private.workspace-ledger.v1", "authority": FLAGS,
           "kits": kits, "previous_sha256": digest(previous_raw) if previous_raw else None}
    encoded = canonical(doc)
    manifest_from_source(encoded)
    rows = ["<p>Snapshot SHA-256 (unsigned, private): <code>" + digest(encoded) + "</code></p>",
            "<table><thead><tr><th>Kit</th><th>Human label</th><th>Files</th><th>Bytes</th><th>Source comparison</th></tr></thead><tbody>"]
    for k in kits:
        change = k["delta"]
        delta_text = ("First snapshot" if change is None else
                      "Added {added}; removed {removed}; changed {changed} (HUMAN review)" .format(**change))
        if previous and previous["kits"][k["ordinal"] - 1]["label"] != k["label"]:
            delta_text += "; HUMAN DOSSIER LABEL CHANGED — HOLD / fresh human review"
        rows.append("<tr><td>" + str(k["ordinal"]) + "</td><td>" + html.escape(k["label"]) +
                    "</td><td>" + str(len(k["files"])) + "</td><td>" + str(k["bytes"]) +
                    "</td><td>" + html.escape(delta_text) + "</td></tr>")
    rows.append("</tbody></table><p>No source files copied. Paths and SHA fingerprints remain only in "
                "the PRIVATE ledger.json. Removed or changed paths never demonstrate remediation.</p>"
                "<p><a href='REVIEW-IN-BROWSER.html'>Open PRIVATE HUMAN browser editor</a> "
                "(local-only; choose adjacent ledger.json). Exported HUMAN CSV rows include the "
                "EXACT ledger SHA-256, not just the kit digest. Browser Downloads may be publicly "
                "readable: use browser_intake.py to create a NEW private copy; do not assume "
                "that moving/chmod of the original reverses prior exposure.</p>"
                "<p>Use the companion HUMAN-review.csv in a trusted editor, then run finalize. "
                "Stages and notes are proposals, never source evidence.</p>")
    template = io.StringIO(newline="")
    writer = csv.writer(template, lineterminator="\n")
    writer.writerow(CSV_HEADERS)
    for k in kits:
        writer.writerow((k["ordinal"], digest(encoded), k["digest"], "needs_review", "", ""))
    output = new_private(args.private_parent)
    try:
        write_private(output, "ledger.json", encoded)
        write_private(output, "HUMAN-review.csv", template.getvalue())
        write_private(output, "REVIEW-IN-BROWSER.html", render_studio())
        write_private(output, "OPEN-PRIVATE.html", html_page("LightUp PRIVATE workspace inventory", "".join(rows)))
    except BaseException:
        shutil.rmtree(output)
        raise
    print("PRIVATE REVIEW_ONLY" if not changed else "PRIVATE HOLD: source-file differences require HUMAN review")
    print(str(Path(output) / "OPEN-PRIVATE.html"))
    return 3 if changed else 2


def verify_snapshot(doc):
    total = 0
    for kit in doc["kits"]:
        fresh, size = file_inventory(kit["path"])
        if fresh != kit["files"] or size != kit["bytes"] or digest(canonical(fresh)) != kit["digest"]:
            reject("PRIVATE HOLD: source kit differs from recorded bytes")
        total += size
    if total > MAX_TOTAL_BYTES:
        reject("PRIVATE HOLD: combined byte limit")


def reopen(args):
    raw = read_owner_file(args.ledger, MAX_MANIFEST)
    document = manifest_from_source(raw)
    verify_snapshot(document)
    print("PRIVATE REVIEW_ONLY: recorded kit bytes currently match; identity/consent NOT verified")
    return 2


def safe_human(value, limit):
    if not isinstance(value, str) or len(value) > limit or any(ord(c) < 32 and c not in "\t" for c in value):
        reject("PRIVATE HOLD: invalid HUMAN text")
    if value.lstrip().startswith(("=", "+", "-", "@")):
        reject("PRIVATE HOLD: spreadsheet formula content")
    return value


def finalize(args):
    raw = read_owner_file(args.ledger, MAX_MANIFEST)
    doc = manifest_from_source(raw)
    verify_snapshot(doc)
    review_data = read_owner_file(args.plan, MAX_CSV)
    try:
        reader = csv.DictReader(io.StringIO(review_data.decode("utf-8"), newline=""), strict=True)
        if reader.fieldnames != list(CSV_HEADERS):
            reject("PRIVATE HOLD: HUMAN CSV columns/order")
        decisions = list(reader)
    except (UnicodeError, ValueError, csv.Error) as exc:
        raise Hold("PRIVATE HOLD: invalid HUMAN CSV") from exc
    if len(decisions) != len(doc["kits"]):
        reject("PRIVATE HOLD: missing or extra HUMAN rows")
    result = []
    for kit, row in zip(doc["kits"], decisions):
        if None in row or set(row) != set(CSV_HEADERS):
            reject("PRIVATE HOLD: HUMAN field count")
        if (row["ordinal"] != str(kit["ordinal"]) or
                row["ledger_sha256"] != digest(raw) or
                row["kit_digest"] != kit["digest"]):
            reject("PRIVATE HOLD: HUMAN plan does not match exact original ledger SHA and kit identity")
        stage = row["stage"]
        if stage not in STAGES:
            reject("PRIVATE HOLD: invalid HUMAN stage")
        owner = safe_human(row["owner"], 80)
        question = safe_human(row["question"], 500)
        result.append({"ordinal": kit["ordinal"], "stage": stage, "owner": owner, "question": question,
                       "kit_digest": kit["digest"]})
    body = ["<p>Exact PRIVATE ledger SHA-256: <code>" + digest(raw) + "</code> · HUMAN CSV SHA-256: "
            "<code>" + digest(review_data) + "</code>. Both unsigned; never an identity assertion.</p>",
            "<table><thead><tr><th>Kit</th><th>HUMAN stage</th><th>Proposed owner</th><th>Next question</th></tr></thead><tbody>"]
    for row in result:
        body.append("<tr><td>" + str(row["ordinal"]) + "</td><td>" + html.escape(row["stage"]) +
                    "</td><td>" + html.escape(row["owner"]) + "</td><td>" +
                    html.escape(row["question"]) + "</td></tr>")
    body.append("</tbody></table><p>Every status is HUMAN-only and remains HOLD for real actions. "
                "This report neither refreshes customer authorization nor verifies any remediation.</p>")
    packet = {"schema": "lightup.private.workspace-ledger-human.v1", "authority": FLAGS,
              "ledger_sha256": digest(raw), "plan_sha256": digest(review_data), "rows": result}
    output = new_private(args.private_parent)
    try:
        write_private(output, "HUMAN-only.json", canonical(packet))
        write_private(output, "HUMAN-private.html", html_page("PRIVATE HUMAN kit follow-up", "".join(body)))
    except BaseException:
        shutil.rmtree(output)
        raise
    print("PRIVATE HOLD: HUMAN decisions recorded; never permission")
    print(str(Path(output) / "HUMAN-private.html"))
    return 3


def main():
    parser = argparse.ArgumentParser(description="Offline PRIVATE kit inventory and human-only handoff (never scan/authorize)")
    sub = parser.add_subparsers(dest="action", required=True)
    cap = sub.add_parser("capture", help="Snapshot exact already-produced owner-private kit bytes")
    cap.add_argument("--kit", action="append", required=True, help="Absolute 0700 existing PRIVATE kit folder (max 12)")
    cap.add_argument("--label", action="append", help="PRIVATE HUMAN label (one per kit)")
    cap.add_argument("--previous", help="Previous owner-private ledger.json for file-only delta")
    cap.add_argument("--private-parent", required=True, help="Existing 0700 owner-only parent outside code checkout")
    ver = sub.add_parser("reopen", help="Recheck exact recorded kit contents; no changes")
    ver.add_argument("--ledger", required=True)
    fin = sub.add_parser("finalize", help="Re-admit original ledger and manually completed HUMAN CSV")
    fin.add_argument("--ledger", required=True)
    fin.add_argument("--plan", required=True)
    fin.add_argument("--private-parent", required=True)
    args = parser.parse_args()
    try:
        if args.action == "capture":
            return capture(args)
        if args.action == "reopen":
            return reopen(args)
        return finalize(args)
    except (Hold, OSError, UnicodeError) as exc:
        print("PRIVATE HOLD: input rejected without external action", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
