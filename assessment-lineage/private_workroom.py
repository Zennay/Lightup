#!/usr/bin/env python3
"""Prepare an owner-private, standalone LightUp lab review workroom, never a runner.

Only original completed offline JSON exports may be embedded. No network, tools,
credential access, CI, scanner, grant, execution or target I/O is performed.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

FLAGS = ("authorized", "consent_verified", "dispatch_allowed", "release_allowed")
CATALOG_LIMIT = 1_048_576
REPORT_LIMIT = 262_144
SOURCE_LIMIT = 8
BUNDLE_MARKER = '<template id="originalPrivateBundle">'
APP_MARKERS = ('function parseCatalog(', 'function parseReport(', 'function read(',
               'id="catalogFile"', 'id="reportFiles"')
TEMPLATE_PATTERN = re.compile(r"<(script|style)>(.*?)</\1>", re.DOTALL)


def fail() -> None:
    raise ValueError("HOLD: invalid private input or incompatible standalone source")


def read_private(path: Path, maximum: int) -> bytes:
    # Refuse symlinks, directories, devices, shared source and mutable races.
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            fail()
        if info.st_mode & 0o077 or info.st_size <= 0 or info.st_size > maximum:
            fail()
        with os.fdopen(os.dup(fd), "rb", closefd=True) as stream:
            raw = stream.read(maximum + 1)
        if len(raw) != info.st_size or len(raw) > maximum:
            fail()
        return raw
    finally:
        os.close(fd)


def no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    obj: dict = {}
    for key, value in pairs:
        if key in obj:
            fail()
        obj[key] = value
    return obj


def reject_constant(value: str) -> None:
    fail()


def admit_json(raw: bytes, catalog: bool) -> None:
    try:
        text = raw.decode("utf-8", errors="strict")
        obj = json.loads(text, object_pairs_hook=no_duplicate_keys,
                         parse_constant=reject_constant)
    except (UnicodeError, ValueError, TypeError, RecursionError):
        fail()
    if type(obj) is not dict or any(obj.get(flag) is not False for flag in FLAGS):
        fail()
    if catalog:
        if set(obj) != {"schema", "status", *FLAGS, "scenarios"}:
            fail()
        if obj["schema"] != "lightup.lab_design_catalog.v1" or obj["status"] != "DRAFT_ONLY":
            fail()
        if type(obj["scenarios"]) is not list or not 1 <= len(obj["scenarios"]) <= 32:
            fail()
    else:
        if set(obj) != {"status", "regressed_scenarios", "comparisons", *FLAGS}:
            fail()
        if obj["status"] not in {"HOLD", "REVIEW_ONLY"}:
            fail()
        if type(obj["comparisons"]) is not list or not 1 <= len(obj["comparisons"]) <= 64:
            fail()
    # Browser's original, unchanged strict domain admission must also pass.
    # This lightweight packager does not claim authenticity of the file.


def check_standalone(raw: bytes) -> str:
    try:
        html = raw.decode("utf-8", errors="strict")
    except UnicodeError:
        fail()
    if len(html) > 250_000 or len(html) < 10_000 or any(k not in html for k in APP_MARKERS):
        fail()
    if html.count("</body>") != 1 or BUNDLE_MARKER in html:
        fail()
    # Find actual top-level inline CSS/JS; JS intentionally contains an HTML
    # handoff string with its own literal '<style>' fragments. A global regex
    # would misidentify that inert source string as another HTML style element.
    style_start, style_end = html.find("<style>"), html.find("</style>")
    script_start, script_end = html.find("<script>"), html.find("</script>")
    if not (0 <= style_start < style_end < script_start < script_end):
        fail()
    if html.count("<script>") != 1 or html.count("</script>") != 1:
        fail()
    css = html[style_start + len("<style>"):style_end]
    js = html[script_start + len("<script>"):script_end]
    for payload in (css, js):
        code = base64.b64encode(hashlib.sha256(payload.encode("utf-8")).digest()).decode()
        if html.count("sha256-" + code) != 1:
            fail()
    if "connect-src 'none'" not in html or "default-src 'none'" not in html:
        fail()
    return html


def create_bundle(catalog: bytes, reports: list[bytes], html: str) -> str:
    payload = {
        "schema": "lightup.private_lineage_bundle.v1",
        "status": "PRIVATE_UNTRUSTED_SOURCE_ONLY",
        **{flag: False for flag in FLAGS},
        "catalog_b64": base64.b64encode(catalog).decode("ascii"),
        "reports_b64": [base64.b64encode(r).decode("ascii") for r in reports],
    }
    text = json.dumps(payload, separators=(",", ":"), ensure_ascii=True)
    return html.replace("</body>", BUNDLE_MARKER + text + "</template>\n</body>")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="LightUp PRIVATE standalone original-source workroom")
    parser.add_argument("--catalog", required=True, type=Path, help="Original owner-private Lab Studio JSON")
    parser.add_argument("--report", required=True, action="append", type=Path,
                        help="Original owner-private completed comparator JSON (1–8)")
    parser.add_argument("--output", required=True, type=Path,
                        help="NEW never-overwritten local PRIVATE HTML workroom")
    args = parser.parse_args(argv)
    if not 1 <= len(args.report) <= SOURCE_LIMIT:
        fail()
    if len({os.path.realpath(p) for p in [args.catalog, *args.report]}) != len(args.report) + 1:
        fail()
    origin = Path(__file__).resolve().with_name("standalone.html")
    # Source HTML is a checked-in product artifact, never a client-provided template.
    source = origin.read_bytes()
    html = check_standalone(source)
    catalog = read_private(args.catalog, CATALOG_LIMIT)
    admit_json(catalog, True)
    reports = []
    for p in args.report:
        doc = read_private(p, REPORT_LIMIT)
        admit_json(doc, False)
        reports.append(doc)
    private_html = create_bundle(catalog, reports, html).encode("utf-8")
    output = args.output
    if output.suffix.lower() != ".html" or output.is_symlink():
        fail()
    # O_EXCL / 0600; never overwrite another operator document.
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(private_html)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        output.unlink(missing_ok=True)
        raise
    print("PRIVATE offline HTML workroom created (original inputs unchanged).")
    print("Not a scan, consent, authorization or production release.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, ValueError) as error:
        print("HOLD: no private workroom produced. Check owner-private 0600 source files, "
              "original canonical exports, output path and existing standalone.", file=sys.stderr)
        raise SystemExit(2) from None
