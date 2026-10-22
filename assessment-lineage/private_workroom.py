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
import math
import os
import stat
import sys
import unicodedata
from pathlib import Path

FLAGS = ("authorized", "consent_verified", "dispatch_allowed", "release_allowed")
CATALOG_LIMIT = 1_048_576
REPORT_LIMIT = 262_144
SOURCE_LIMIT = 8
DRAFT_LIMIT = 65_536
BUNDLE_MARKER = '<template id="originalPrivateBundle">'
APP_MARKERS = ('function parseCatalog(', 'function parseReport(', 'function read(',
               'id="catalogFile"', 'id="reportFiles"')


def fail() -> None:
    raise ValueError("HOLD: invalid private input or incompatible standalone source")


def open_parent_nofollow(path: Path) -> tuple[int, str]:
    """Pin every parent component as a directory; never follow path aliases."""
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        fail()
    absolute = os.path.abspath(os.fspath(path))
    parent, name = os.path.split(absolute)
    if not name or name in (".", ".."):
        fail()
    fd = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in (part for part in parent.split(os.sep) if part):
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=fd)
            os.close(fd)
            fd = child
        return fd, name
    except BaseException:
        os.close(fd)
        raise


def read_private(path: Path, maximum: int) -> bytes:
    """Admit unchanged owner-private regular file without symlink/hard-link aliases."""
    parent_fd, name = open_parent_nofollow(path)
    try:
        fd = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
            dir_fd=parent_fd,
        )
    finally:
        os.close(parent_fd)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                or not 0 < before.st_size <= maximum):
            fail()
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        signature = lambda info: (
            info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_uid, info.st_mode, info.st_nlink,
        )
        if len(raw) != before.st_size or signature(before) != signature(after):
            fail()
    return raw


def no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    obj: dict = {}
    for key, value in pairs:
        if key in obj:
            fail()
        obj[key] = value
    return obj


def reject_constant(value: str) -> None:
    fail()


def finite_json_number(text: str) -> float:
    """No Infinity/underflow-to-zero ambiguity in original numerical claims."""
    number = float(text)
    coefficient = text.lower().split("e", 1)[0]
    if not math.isfinite(number) or (number == 0.0 and any("1" <= ch <= "9" for ch in coefficient)):
        fail()
    return number


def admit_json(raw: bytes, catalog: bool) -> None:
    try:
        text = raw.decode("utf-8", errors="strict")
        obj = json.loads(text, object_pairs_hook=no_duplicate_keys,
                         parse_constant=reject_constant, parse_float=finite_json_number)
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
        if type(obj["status"]) is not str or obj["status"] not in {"HOLD", "REVIEW_ONLY"}:
            fail()
        if type(obj["comparisons"]) is not list or not 1 <= len(obj["comparisons"]) <= 64:
            fail()
    # Browser's original, unchanged strict domain admission must also pass.
    # This lightweight packager does not claim authenticity of the file.


def admit_private_draft(raw: bytes, catalog: bytes, reports: list[bytes]) -> None:
    """Check the original human draft is bound to the *exact* original file bytes."""
    try:
        obj = json.loads(raw.decode("utf-8", errors="strict"),
                         object_pairs_hook=no_duplicate_keys,
                         parse_constant=reject_constant, parse_float=finite_json_number)
    except (UnicodeError, ValueError, TypeError, RecursionError):
        fail()
    if type(obj) is not dict or obj.get("status") != "PRIVATE_HUMAN_DRAFT_ONLY":
        fail()
    version = obj.get("schema")
    if type(version) is not str or version not in {"lightup.assessment_lineage_private_draft.v1",
                       "lightup.assessment_lineage_private_draft.v2",
                       "lightup.assessment_lineage_private_draft.v3"}:
        fail()
    with_notes = version != "lightup.assessment_lineage_private_draft.v1"
    with_plan = version == "lightup.assessment_lineage_private_draft.v3"
    expected = {"schema", "status", *FLAGS, "source_catalog_sha256",
                "source_report_sha256", "discussion_stages"}
    if with_notes:
        expected.add("private_case_notes")
    if with_plan:
        expected.update(("proposed_review_routes", "next_human_actions"))
    if set(obj) != expected or any(obj.get(k) is not False for k in FLAGS):
        fail()
    hashes = [hashlib.sha256(value).hexdigest() for value in reports]
    if obj["source_catalog_sha256"] != hashlib.sha256(catalog).hexdigest():
        fail()
    if obj["source_report_sha256"] != hashes:
        fail()
    original = json.loads(catalog.decode("utf-8"), object_pairs_hook=no_duplicate_keys)
    count = len(original["scenarios"])
    stages = obj["discussion_stages"]
    if type(stages) is not list or len(stages) != count or any(
        type(v) is not str or v not in {"needs_review", "in_discussion", "documented"}
        for v in stages
    ):
        fail()
    if with_notes:
        notes = obj["private_case_notes"]
        if type(notes) is not list or len(notes) != count or any(
            type(note) is not str or len(note) > 400 or
            any(ord(ch) in (*range(0, 9), 11, 12, *range(14, 32), 127) for ch in note)
            for note in notes
        ):
            fail()
    if with_plan:
        routes = {"unrouted", "source_owner", "scope_policy", "finding_quality",
                  "evidence_scoring", "operations"}
        actions = {"none_recorded", "verify_original_source",
                   "request_original_evidence", "discuss_lab_method",
                   "document_human_followup"}
        for key, permitted in (("proposed_review_routes", routes),
                               ("next_human_actions", actions)):
            values = obj[key]
            if type(values) is not list or len(values) != count or any(
                type(value) is not str or value not in permitted for value in values
            ):
                fail()


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


def create_bundle(catalog: bytes, reports: list[bytes], html: str,
                  human_draft: bytes | None) -> str:
    payload = {
        "schema": ("lightup.private_lineage_bundle.v2" if human_draft is not None
                   else "lightup.private_lineage_bundle.v1"),
        "status": "PRIVATE_UNTRUSTED_SOURCE_ONLY",
        **{flag: False for flag in FLAGS},
        "catalog_b64": base64.b64encode(catalog).decode("ascii"),
        "reports_b64": [base64.b64encode(r).decode("ascii") for r in reports],
        **({"human_draft_b64": base64.b64encode(human_draft).decode("ascii")}
           if human_draft is not None else {}),
    }
    text = json.dumps(payload, separators=(",", ":"), ensure_ascii=True)
    return html.replace("</body>", BUNDLE_MARKER + text + "</template>\n</body>")


def private_receipt(catalog: bytes, reports: list[bytes], draft: bytes | None,
                    workroom: bytes) -> bytes:
    """Canonical PRIVATE unsigned byte-binding for human source reconciliation.

    Digests can correlate confidential original reports. Never publish this
    owner-private receipt as an anonymous result or interpret it as authority.
    """
    receipt = {
        "schema": "lightup.private_lineage_receipt.v1",
        "status": "PRIVATE_REVIEW_ONLY",
        **{flag: False for flag in FLAGS},
        "catalog_sha256": hashlib.sha256(catalog).hexdigest(),
        "reports_sha256": [hashlib.sha256(raw).hexdigest() for raw in reports],
        "human_draft_sha256": hashlib.sha256(draft).hexdigest() if draft is not None else None,
        "workroom_sha256": hashlib.sha256(workroom).hexdigest(),
        "report_count": len(reports),
        "human_draft_present": draft is not None,
        "origin_verified": False,
        "operator_identity_verified": False,
        "client_consent_verified": False,
        "human_go": False,
    }
    return (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def private_source_board(receipt_bytes: bytes) -> bytes:
    """Human-readable PRIVATE source-slot inventory, with no original raw input.

    All displayed variable content is locally computed lower-case ASCII hex or
    bounded integer slot ordinals. This is an unsigned continuity aid only.
    """
    receipt = json.loads(receipt_bytes.decode("utf-8"))
    rows = [
        ("Original private Lab Studio catalog", receipt["catalog_sha256"]),
        *[(f"Original finished comparator source slot {idx:02d}", digest)
          for idx, digest in enumerate(receipt["reports_sha256"], 1)],
        ("Original private HUMAN draft", receipt["human_draft_sha256"] or "NOT INCLUDED"),
        ("Generated PRIVATE workroom HTML", receipt["workroom_sha256"]),
    ]
    cells = "\n".join(
        f"<tr><th scope=\"row\">{label}</th><td><code>{digest}</code></td></tr>"
        for label, digest in rows
    )
    page = (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta http-equiv=\"Content-Security-Policy\" content=\""
        "default-src 'none'; base-uri 'none'; form-action 'none'; "
        "connect-src 'none'; img-src 'none'; style-src 'none'; script-src 'none'\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        "<title>LightUp PRIVATE original-source inventory — REVIEW ONLY</title>"
        "</head><body><main><h1>PRIVATE original-source inventory</h1>"
        "<p><strong>HOLD · unsigned original data · HUMAN review only.</strong> "
        "Not source identity, scope approval, consent, remediation, release or HUMAN GO.</p>"
        "<p>Exactly " + str(receipt["report_count"]) + " human-ordered completed source slots. "
        "Slot order is selected by the human operator, not authenticated chronology.</p>"
        "<table border=\"1\"><caption>Confidential source-byte SHA-256 fingerprints</caption>"
        "<thead><tr><th scope=\"col\">Original source slot</th><th scope=\"col\">"
        "PRIVATE local byte digest (not a signature)</th></tr></thead><tbody>"
        + cells + "</tbody></table>"
        "<p>These SHA-256 values are sensitive source correlation data. "
        "Keep this file owner-private 0600 in its 0700 directory; do not publish "
        "or forward as an anonymous handoff. A matching hash does not prove "
        "authorship, client/operator identity, permission, or an authentic finding.</p>"
        "</main></body></html>\n"
    )
    return page.encode("utf-8")


def read_private_report_selection(path: Path) -> list[Path]:
    """Admit an explicit operator-owned report ordering without target access."""
    raw = read_private(path, 16_384)
    if not raw.endswith(b"\n") or b"\r" in raw or b"\0" in raw:
        fail()
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError:
        fail()
    # A path separator cannot be a disguised Unicode line break or bidi mark.
    paths = text.split("\n")[:-1]
    if not 1 <= len(paths) <= SOURCE_LIMIT or len(set(paths)) != len(paths):
        fail()
    result = []
    for name in paths:
        if (not name.startswith(os.sep) or os.path.normpath(name) != name
                or not 1 <= len(name) <= 2048 or any(
                    unicodedata.category(char) in ("Cc", "Cf", "Zl", "Zp")
                    for char in name
                )):
            fail()
        result.append(Path(name))
    return result


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="LightUp PRIVATE standalone original-source workroom")
    parser.add_argument("--catalog", required=True, type=Path, help="Original owner-private Lab Studio JSON")
    parser.add_argument("--report", action="append", type=Path,
                        help="Original owner-private completed comparator JSON (1–8)")
    parser.add_argument("--reports-file", type=Path,
                        help="One owner-private mode-0600 LF-delimited list of absolute completed report paths")
    parser.add_argument("--human-draft", type=Path,
                        help="Optional owner-private exact-source-bound human work draft v1/v2/v3")
    parser.add_argument("--output", required=True, type=Path,
                        help="New or --verify-existing owner-private HTML workroom")
    parser.add_argument("--verify-existing", action="store_true",
                        help="Re-admit original inputs and exactly reopen the existing PRIVATE HTML without writes")
    parser.add_argument("--private-receipt", action="store_true",
                        help="Also create or read-only reopen an owner-private byte-bound JSON source receipt")
    parser.add_argument("--private-source-board", action="store_true",
                        help="With --private-receipt, create/reopen a scriptless PRIVATE source-fingerprint table")
    args = parser.parse_args(argv)
    if args.private_source_board and not args.private_receipt:
        fail()
    if bool(args.report) == bool(args.reports_file):
        fail()
    report_paths = read_private_report_selection(args.reports_file) if args.reports_file else args.report
    if not 1 <= len(report_paths) <= SOURCE_LIMIT:
        fail()
    input_files = [
        args.catalog, *report_paths, *([args.human_draft] if args.human_draft else []),
        *([args.reports_file] if args.reports_file else []),
    ]
    if len({os.path.realpath(p) for p in input_files}) != len(input_files):
        fail()
    origin = Path(__file__).resolve().with_name("standalone.html")
    # Source HTML is a checked-in product artifact, never a client-provided template.
    source = origin.read_bytes()
    html = check_standalone(source)
    catalog = read_private(args.catalog, CATALOG_LIMIT)
    admit_json(catalog, True)
    reports = []
    for p in report_paths:
        doc = read_private(p, REPORT_LIMIT)
        admit_json(doc, False)
        reports.append(doc)
    draft = read_private(args.human_draft, DRAFT_LIMIT) if args.human_draft else None
    if draft is not None:
        admit_private_draft(draft, catalog, reports)
    private_html = create_bundle(catalog, reports, html, draft).encode("utf-8")
    # Re-admit all original source bytes immediately before publication.
    for original_path, expected, limit in [
        (args.catalog, catalog, CATALOG_LIMIT),
        *[(path, raw, REPORT_LIMIT) for path, raw in zip(report_paths, reports)],
        *([(args.human_draft, draft, DRAFT_LIMIT)] if draft is not None else []),
    ]:
        if read_private(original_path, limit) != expected:
            fail()
    if args.reports_file and read_private_report_selection(args.reports_file) != report_paths:
        fail()
    output = args.output
    if output.suffix.lower() != ".html" or os.path.realpath(output) in {
        os.path.realpath(source_path) for source_path in input_files
    }:
        fail()
    receipt_path = output.with_suffix(".private-lineage-receipt.json")
    outputs = [(output.name, private_html)]
    if args.private_receipt:
        if (receipt_path == output or os.path.realpath(receipt_path) in {
            os.path.realpath(source_path) for source_path in input_files
        }):
            fail()
        receipt_bytes = private_receipt(catalog, reports, draft, private_html)
        outputs.append((receipt_path.name, receipt_bytes))
        if args.private_source_board:
            board_path = output.with_suffix(".private-lineage-source-board.html")
            if os.path.realpath(board_path) in {
                os.path.realpath(source_path) for source_path in input_files
            }:
                fail()
            outputs.append((board_path.name, private_source_board(receipt_bytes)))
    parent_fd, _ = open_parent_nofollow(output)
    created_names: list[str] = []
    try:
        info = os.fstat(parent_fd)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            fail()
        if args.verify_existing:
            for filename, expected in outputs:
                if read_private(output.with_name(filename), len(expected)) != expected:
                    fail()
            print("PRIVATE ORIGINAL-SOURCE-BOUND WORKROOM"
                  + (" AND RECEIPT" if args.private_receipt else "")
                  + " MATCH — REVIEW_ONLY; NOT AUTHORIZED")
            return 0
        # Both artifacts are exclusive, owner-only and must remain together.
        # If publication of the second fails, discard only files created here.
        # Pre-existing sources or output files are never overwritten or removed.
        try:
            for filename, content in outputs:
                fd = os.open(
                    filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600, dir_fd=parent_fd,
                )
                created_names.append(filename)
                with os.fdopen(fd, "wb", closefd=True) as stream:
                    os.fchmod(stream.fileno(), 0o600)
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
            os.fsync(parent_fd)
        except BaseException:
            for filename in reversed(created_names):
                os.unlink(filename, dir_fd=parent_fd)
            os.fsync(parent_fd)
            raise
    finally:
        os.close(parent_fd)
    print("PRIVATE offline HTML workroom created (original inputs unchanged).")
    if args.private_receipt:
        print("PRIVATE unsigned source-byte receipt created; NOT source authenticity or authority.")
        if args.private_source_board:
            print("PRIVATE scriptless source-slot board created; HOLD and local review only.")
    print("Not a scan, consent, authorization or production release.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, ValueError, TypeError, OverflowError, RecursionError, UnicodeError) as error:
        print("HOLD: PRIVATE workroom cannot be created or reopened. Check owner-private 0600 source files, "
              "original canonical exports, output path and existing standalone.", file=sys.stderr)
        raise SystemExit(2) from None
