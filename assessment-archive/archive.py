#!/usr/bin/env python3
"""LightUp private offline assessment archive. No target/model/authorization calls."""
from __future__ import annotations

import argparse
from collections import Counter
from hashlib import sha256
from html import escape
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from zipfile import ZipFile, BadZipFile, ZIP_DEFLATED, ZIP_STORED

SCHEMA = "lightup.assessment_archive.v1"
PUBLIC_SCHEMA = "lightup.assessment_archive_aggregate.v1"
MAX_SOURCE = 8 * 1024 * 1024
MAX_MANIFEST = 128 * 1024
FLAGS = ("authorized", "consent_verified", "dispatch_allowed", "release_allowed")
KINDS = ("completed_lab_case_claim", "completed_lab_cohort_claim",
         "offline_comparison_claim", "studio_catalog_draft",
         "other_lightup_draft", "private_review_zip_claim")


class Hold(Exception):
    pass


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Hold("ambiguous JSON keys")
        result[key] = value
    return result


def no_constant(_):
    raise Hold("invalid numeric constant")


def read_regular(path, bound):
    """Single fd read, no symlinks/devices/pipes, no size changes."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= bound:
            raise Hold("invalid input size/type")
        data = stream.read(bound + 1)
        after = os.fstat(stream.fileno())
        if (len(data) != before.st_size or before.st_size != after.st_size
                or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
                or before.st_mtime_ns != after.st_mtime_ns
                or before.st_ctime_ns != after.st_ctime_ns):
            raise Hold("input changed during read")
        return data


def decode_json(data):
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=unique_pairs,
                          parse_constant=no_constant)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise Hold("invalid JSON") from error


def reject_authority(document):
    # Imported material never becomes permissions, including nested objects.
    stack = [document]
    nodes = 0
    while stack:
        obj = stack.pop()
        nodes += 1
        if nodes > 120000:
            raise Hold("too many JSON nodes")
        if type(obj) is dict:
            if any(key in obj and obj[key] is not False for key in FLAGS):
                raise Hold("unsupported authority assertion")
            stack.extend(obj.values())
        elif type(obj) is list:
            stack.extend(obj)


def is_lab_case(doc):
    if type(doc) is not dict or type(doc.get("record")) is not dict or type(doc.get("context")) is not dict:
        return False
    context, record = doc["context"], doc["record"]
    return (context.get("is_lab") is True and context.get("authorization") is None
            and context.get("mode") in ("LAB_AUTONOMOUS", "lab_autonomous")
            and type(record.get("metrics")) is dict
            and type(record.get("run_id")) is str)


def inspect_json(doc):
    reject_authority(doc)
    if type(doc) is list:
        if 1 <= len(doc) <= 64 and all(is_lab_case(item) for item in doc):
            return "completed_lab_cohort_claim", len(doc), "REVIEW_ONLY"
        raise Hold("unsupported JSON list")
    if type(doc) is not dict:
        raise Hold("unsupported JSON primitive")
    if is_lab_case(doc):
        return "completed_lab_case_claim", 1, "REVIEW_ONLY"
    if (doc.get("status") in ("REVIEW_ONLY", "HOLD") and
            (type(doc.get("comparisons")) is list or type(doc.get("changes")) is list)):
        items = doc.get("comparisons", [doc])
        if len(items) > 64:
            raise Hold("overlarge comparison set")
        return "offline_comparison_claim", len(items), doc["status"]
    schema = doc.get("schema")
    if schema == "lightup.lab_design_catalog.v1":
        count = len(doc.get("scenarios", [])) if type(doc.get("scenarios")) is list else 0
        if count > 64:
            raise Hold("overlarge scenario set")
        return "studio_catalog_draft", count, "REVIEW_ONLY"
    if type(schema) is str and schema.startswith("lightup.") and len(schema) <= 128:
        return "other_lightup_draft", 1, "REVIEW_ONLY"
    raise Hold("unsupported source shape")


def inspect_zip(data):
    with ZipFile(io.BytesIO(data)) as zf:
        infos = zf.infolist()
        if not 1 <= len(infos) <= 128:
            raise Hold("archive count")
        seen = set()
        total = 0
        for info in infos:
            name = info.filename
            bits = name.rstrip("/").split("/")
            if (not name or name.startswith("/") or "\\" in name or
                    any(bit in ("", ".", "..") for bit in bits) or
                    len(name) > 256 or name in seen or
                    info.flag_bits & 1 or
                    info.compress_type not in (ZIP_STORED, ZIP_DEFLATED)):
                raise Hold("unsafe ZIP member")
            seen.add(name)
            total += info.file_size
            if total > 12 * 1024 * 1024 or info.file_size > MAX_SOURCE:
                raise Hold("excessive expanded ZIP size")
        # Never extract, decompress, execute or trust ZIP contents as permission.
        return "private_review_zip_claim", len(infos), "REVIEW_ONLY"


def observe(path, slot):
    data = read_regular(path, MAX_SOURCE)
    kind, count, status = (inspect_zip(data) if data.startswith(b"PK\x03\x04")
                           else inspect_json(decode_json(data)))
    return {"slot": slot, "kind": kind, "size_bytes": len(data),
            "sha256": sha256(data).hexdigest(), "item_count_claim": count,
            "review_state": status}


def encode(doc):
    return (json.dumps(doc, ensure_ascii=True, allow_nan=False,
                       sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def publish(path, data):
    """No-overwrite 0600 fully fsynced publication in same filesystem."""
    target = Path(path)
    if not target.parent.is_dir() or target.name in ("", ".", ".."):
        raise Hold("output directory invalid")
    fd, temp = tempfile.mkstemp(dir=target.parent, prefix=".lightup-archive-")
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temp, target, follow_symlinks=False)
        dir_fd = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        os.unlink(temp)


def _manifest(doc):
    """Strict original snapshot validator, reusable without a second file open."""
    expected = {"schema", "entries", "source_count", "status",
                "authorized", "consent_verified", "dispatch_allowed", "release_allowed"}
    if type(doc) is not dict or set(doc) != expected or doc["schema"] != SCHEMA:
        raise Hold("invalid manifest")
    entries = doc["entries"]
    if (type(entries) is not list or not 2 <= len(entries) <= 64 or
            type(doc["source_count"]) is not int or doc["source_count"] != len(entries) or
            any(doc[key] is not False for key in FLAGS)):
        raise Hold("invalid manifest authority/count")
    seen = set()
    for number, row in enumerate(entries, 1):
        if (type(row) is not dict or set(row) != {
                "slot", "kind", "size_bytes", "sha256", "item_count_claim", "review_state"}):
            raise Hold("invalid entry shape")
        digest = row["sha256"]
        if (type(row["slot"]) is not int or row["slot"] != number or
                row["kind"] not in KINDS or
                type(row["size_bytes"]) is not int or not 0 < row["size_bytes"] <= MAX_SOURCE or
                type(row["item_count_claim"]) is not int or not 0 <= row["item_count_claim"] <= 128 or
                type(digest) is not str or len(digest) != 64 or
                any(c not in "0123456789abcdef" for c in digest) or
                digest in seen or row["review_state"] not in ("HOLD", "REVIEW_ONLY")):
            raise Hold("invalid entry")
        seen.add(digest)
    state = "HOLD" if any(row["review_state"] == "HOLD" for row in entries) else "REVIEW_ONLY"
    if doc["status"] != state:
        raise Hold("contradictory claimed status")
    return doc


def load_manifest(path):
    return _manifest(decode_json(read_regular(path, MAX_MANIFEST)))


def capture(args):
    if not 2 <= len(args.sources) <= 64:
        raise Hold("expect 2–64 source files")
    records = [observe(path, i) for i, path in enumerate(args.sources, 1)]
    if len({r["sha256"] for r in records}) != len(records):
        raise Hold("duplicate source")
    status = "HOLD" if any(r["review_state"] == "HOLD" for r in records) else "REVIEW_ONLY"
    manifest = {"schema": SCHEMA, "entries": records, "source_count": len(records),
                "status": status, **{key: False for key in FLAGS}}
    publish(args.output, encode(manifest))
    print(f"PRIVATE_ARCHIVE_CREATED sources={len(records)} state={status} — NOT AUTHORIZED")
    return 2 if status == "REVIEW_ONLY" else 3


def verify(args):
    expected = load_manifest(args.manifest)
    if len(args.sources) != expected["source_count"]:
        raise Hold("source count differs")
    if any(observe(path, i) != recorded
           for i, (path, recorded) in enumerate(zip(args.sources, expected["entries"]), 1)):
        raise Hold("source hash or claimed shape changed")
    print(f"PRIVATE_ARCHIVE_BYTES_MATCHED sources={expected['source_count']} — NO AUTHORITY")
    return 2


def aggregate(doc):
    types = Counter(row["kind"] for row in doc["entries"])
    return {"schema": PUBLIC_SCHEMA, "source_count": doc["source_count"],
            "kind_counts": dict(sorted(types.items())), "status": doc["status"],
            "hold_source_count": sum(row["review_state"] == "HOLD" for row in doc["entries"]),
            **{key: False for key in FLAGS}}


def share(args):
    publish(args.output, encode(aggregate(load_manifest(args.manifest))))
    print("AGGREGATE_ONLY_CREATED — NOT AUTHORIZED")
    return 2


STYLE = """
:root{font-family:system-ui,-apple-system,sans-serif;background:#0c1825;color:#e8f2fb}
*{box-sizing:border-box}body{margin:0 auto;max-width:1140px;padding:35px 20px;line-height:1.5}
h1{font-size:clamp(1.9rem,4vw,3.1rem);letter-spacing:-.045em;margin:8px 0}
p{color:#bed0dc}.hero{padding:36px;border-radius:24px;border:1px solid #395569;background:linear-gradient(130deg,#173d50,#121f31)}
.kicker{color:#8bd8ed;font-size:.8rem;font-weight:700;letter-spacing:.15em}
.state{color:#f4d183;font-weight:800}main{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin:20px 0}
.card{padding:20px;border-radius:15px;background:#193043}.big{font-size:2.25rem;font-weight:800}
section{border-radius:18px;padding:22px;margin:22px 0;background:#132637;overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:.87rem}th,td{padding:13px 9px;text-align:left;border-bottom:1px solid #344b5d}
th{color:#99c2d4}code{font-size:.8rem;color:#8edeee;overflow-wrap:anywhere}
aside{border-left:4px solid #e8bb73;padding:4px 20px}
@media(max-width:730px){main{grid-template-columns:1fr}.hero{padding:22px}}
@media print{body{background:white;color:black}.hero,.card,section{color:black;background:white;border:1px solid #aaa}p,th{color:#222}}
""".strip()


def html_doc(doc, anonymous):
    from base64 import b64encode
    policy = b64encode(sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    if anonymous:
        rows = "".join(f"<tr><th>{escape(kind)}</th><td>{count}</td></tr>"
                       for kind, count in sorted(doc["kind_counts"].items()))
        headers = "<th>Claimed source class</th><th>Count</th>"
        privacy = "Anonymous category counts. No original file names, IDs, fingerprints or target metadata."
    else:
        rows = "".join(
            f"<tr><th>#{r['slot']}</th><td>{escape(r['kind'])}</td>"
            f"<td>{r['size_bytes']:,}</td><td>{r['item_count_claim']}</td>"
            f"<td>{escape(r['review_state'])}</td><td><code>{r['sha256']}</code></td></tr>"
            for r in doc["entries"])
        headers = "<th>Slot</th><th>Claimed source</th><th>Bytes</th><th>Claimed items</th><th>State</th><th>SHA-256 (private)</th>"
        privacy = "OWNER PRIVATE: SHA-256 only detects byte changes. Unsigned fingerprints do not prove authenticity."
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; base-uri 'none'; form-action 'none'; connect-src 'none'; img-src 'none'; style-src 'sha256-{policy}'">
<title>LightUp — Offline Assessment Archive</title><style>{STYLE}</style></head><body>
<header class="hero"><div class="kicker">LIGHTUP / ASSESSMENT-RUNTIME / OFFLINE</div>
<h1>Lab artifact archive</h1><p>Multiple completed local artifact claims in one human-review inventory. This does not inspect assets, rescore lab measurements, access a model or issue approval.</p>
<div class="state">INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · {escape(doc['status'])}</div></header>
<main><div class="card"><div class="kicker">Source files</div><div class="big">{doc['source_count']}</div></div>
<div class="card"><div class="kicker">Review state</div><div class="big">{escape(doc['status'])}</div></div>
<div class="card"><div class="kicker">Permission</div><div class="big">NONE</div></div></main>
<section><h2>Local source inventory</h2><p>{escape(privacy)}</p>
<table><thead><tr>{headers}</tr></thead><tbody>{rows}</tbody></table></section>
<section><aside><h2>Human follow-up required</h2><p>No source confirms customer permission, operator decision, model clearance, original target ownership, a fixed vulnerability or a release GO. Source reviewer, security/privacy approval, existing CI and real consent gates remain necessary. A reported empty regression list is not proof of safety.</p></aside></section>
<footer><p>Standalone print-ready HTML. No JavaScript, network requests, browser storage or file reads.</p></footer></body></html>""".encode("utf-8")


def view(args):
    source = load_manifest(args.manifest)
    public = bool(args.aggregate_only)
    publish(args.output, html_doc(aggregate(source) if public else source, public))
    print("OFFLINE_HTML_CREATED — NOT AUTHORIZED")
    return 2 if source["status"] == "REVIEW_ONLY" else 3


def diff(args):
    """Compare two owner-private indices without reading original source assets."""
    before = load_manifest(args.previous)
    after = load_manifest(args.current)
    old_hashes = {item["sha256"] for item in before["entries"]}
    new_hashes = {item["sha256"] for item in after["entries"]}
    previous_counts = Counter(r["kind"] for r in before["entries"])
    current_counts = Counter(r["kind"] for r in after["entries"])
    kinds = sorted(set(previous_counts) | set(current_counts))
    result = {
        "schema": "lightup.assessment_archive_diff.v1",
        "status": "HOLD" if "HOLD" in (before["status"], after["status"]) else "REVIEW_ONLY",
        "previous_source_count": before["source_count"],
        "current_source_count": after["source_count"],
        "unchanged_count": len(old_hashes & new_hashes),
        "added_count": len(new_hashes - old_hashes),
        "absent_count": len(old_hashes - new_hashes),
        "source_class_shifts": [
            {"source_class": kind, "previous": previous_counts[kind],
             "current": current_counts[kind], "delta": current_counts[kind] - previous_counts[kind]}
            for kind in kinds
        ],
        **{key: False for key in FLAGS},
    }
    if not args.aggregate_only:
        result["new_private_sha256"] = sorted(new_hashes - old_hashes)
        result["absent_private_sha256"] = sorted(old_hashes - new_hashes)
    if args.format == "html":
        from diff_render import render
        payload = render(result, args.aggregate_only)
    else:
        payload = encode(result)
    publish(args.output, payload)
    print("OFFLINE_ARCHIVE_DIFF_CREATED — ABSENT DOES NOT MEAN FIXED; NO AUTHORITY")
    return 2 if result["status"] == "REVIEW_ONLY" else 3


def main(argv=None):
    parser = argparse.ArgumentParser(description="LightUp offline archive; holds all authorization and release.")
    subs = parser.add_subparsers(dest="command", required=True)
    p = subs.add_parser("capture", help="Snapshot 2–64 existing explicit private artifacts")
    p.add_argument("sources", nargs="+")
    p.add_argument("--output", required=True)
    p = subs.add_parser("verify", help="Match exact selected source bytes against a private manifest")
    p.add_argument("--manifest", required=True)
    p.add_argument("sources", nargs="+")
    p = subs.add_parser("share", help="Publish de-identified count-only JSON")
    p.add_argument("--manifest", required=True)
    p.add_argument("--output", required=True)
    p = subs.add_parser("view", help="Publish static printable HTML without networking")
    p.add_argument("--manifest", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--aggregate-only", action="store_true")
    p = subs.add_parser("diff", help="Compare two original private archive snapshots, no source reads")
    p.add_argument("--format", choices=("json", "html"), default="json")
    p.add_argument("--previous", required=True)
    p.add_argument("--current", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--aggregate-only", action="store_true")
    p = subs.add_parser("studio", help="Create source-bound interactive private browser workbench")
    p.add_argument("--manifest", required=True)
    p.add_argument("--previous", help="Original prior private archive for local byte-history comparison")
    p.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "studio":
            from archive_studio import build
            return build(args.manifest, args.output, args.previous)
        return {"capture": capture, "verify": verify, "share": share, "view": view, "diff": diff}[args.command](args)
    except (Hold, OSError, ValueError, TypeError, UnicodeError, OverflowError,
            RecursionError, BadZipFile):
        print("ASSESSMENT_ARCHIVE_HOLD — invalid, inaccessible or changed local source", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
