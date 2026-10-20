"""PRIVATE offline HUMAN history for previously emitted tenant review packets.

Source identity, human-declared packet order and same-tenant identity cannot be
proved by unsigned local files. No domain/authorization/runtime writes or scans.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
from html import escape
import io
import json
import os
from pathlib import Path
import secrets
import stat
import sys
import unicodedata

from .finding_export_review import _RETESTS, _admit_export, _render, _summary
from .finding_export_review_publish import (
    _HOLD_NOTICE, _SAFE_NAME, _file, _private_parent, _publish_noreplace,
)
from .finding_export_unicode_integrity import _checked_text

_NAMES = ("findings.csv", "review.html", "summary.json", "REVIEW_ONLY.txt")
_LIMITS = (300_000, 900_000, 40_000, 2_000)
_STAGES = ("not_in_selection", *_RETESTS)
_HISTORY_HOLD = (
    "PRIVATE HUMAN COMPARISON · DRAFT/HOLD · PLAN/LAB ONLY. These are "
    "operator-selected, unsigned and unauthenticated files. A finding absent "
    "from a later selected packet is NOT a verified fix, closure, revocation "
    "or change in authorization. Declared order and same-scope grouping are "
    "HUMAN assertions, not independently authenticated chronology or identity."
)


def _load_file(folder_fd: int, name: str, limit: int) -> bytes:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                 dir_fd=folder_fd)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1 or info.st_size > limit):
            raise ValueError("untrusted PRIVATE packet file: " + name)
        with os.fdopen(fd, "rb", closefd=False) as stream:
            result = stream.read(limit + 1)
        if len(result) > limit:
            raise ValueError("oversized PRIVATE packet file")
        return result
    finally:
        os.close(fd)


def _read_packet(path: Path) -> tuple[dict[str, tuple[str, ...]], str]:
    """Reopen only a complete native packet, not a random user-made CSV."""
    if not path.is_absolute() or _SAFE_NAME.fullmatch(path.name) is None:
        raise ValueError("use a literal absolute original packet path")
    parent_fd = _private_parent(path.parent)
    fd = -1
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY |
                     os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
        info = os.fstat(fd)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError("PRIVATE review directory ownership or mode invalid")
        if set(os.listdir(fd)) != set(_NAMES):
            raise ValueError("PRIVATE review inventory differs from original")
        files = [_load_file(fd, name, max_bytes)
                 for name, max_bytes in zip(_NAMES, _LIMITS)]
    finally:
        if fd >= 0:
            os.close(fd)
        os.close(parent_fd)

    try:
        csv_text, html_text, json_text, hold_text = [
            content.decode("utf-8", "strict") for content in files
        ]
    except UnicodeError as exc:
        raise ValueError("PRIVATE packet requires canonical UTF-8") from exc
    rows, digest = _admit_export(csv_text)
    if hold_text != _HOLD_NOTICE or html_text != _render(rows, digest):
        raise ValueError("original PRIVATE review/HOLD source bytes do not match")
    if json_text != _summary(rows, digest):
        raise ValueError("original PRIVATE count/source receipt does not match")
    # Canonical native CSV syntax only. Reject injected extra syntax even when
    # csv.reader could otherwise interpret it as the same logical rows.
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    writer.writerow(("finding_id", "title", "severity", "retest_status", "remediation"))
    writer.writerows(rows)
    if stream.getvalue() != csv_text:
        raise ValueError("PRIVATE CSV is not canonical native presentation")
    findings: dict[str, tuple[str, ...]] = {}
    normalized_ids: set[str] = set()
    for row in rows:
        for field, value, ceiling in (
            ("finding_id", row[0], 1024),
            ("title", row[1], 16384),
            ("remediation", row[4], 16384),
        ):
            _checked_text(value, field, ceiling)
            # A native source renderer apostrophe-prefixes literal ASCII
            # spreadsheet formula leaders. A forged standalone CSV may not
            # skip that presentation boundary during offline re-admission.
            if value.lstrip().startswith(("=", "+", "-", "@")):
                raise ValueError("unescaped spreadsheet formula in PRIVATE packet")
        identity = unicodedata.normalize("NFKC", row[0])
        if identity in normalized_ids:
            raise ValueError("ambiguous private finding presentation identity")
        normalized_ids.add(identity)
        findings[row[0]] = row
    return findings, digest


def _difference(
    earlier: dict[str, tuple[str, ...]],
    later: dict[str, tuple[str, ...]],
) -> tuple[list[dict], dict[str, int]]:
    result: list[dict] = []
    counts = dict(added=0, absent=0, changed=0, unchanged=0)
    by_id = sorted(set(earlier) | set(later))
    for finding_id in by_id:
        old = earlier.get(finding_id)
        new = later.get(finding_id)
        if old is None:
            kind = "added"
        elif new is None:
            kind = "absent"
        elif old == new:
            kind = "unchanged"
        else:
            kind = "changed"
        counts[kind] += 1
        fields = [field for index, field in enumerate(
            ("finding_id", "title", "severity", "retest_status", "remediation")
        ) if old is not None and new is not None and old[index] != new[index]]
        result.append({
            "finding_id": finding_id,
            "change_kind": kind,
            "changed_display_fields": fields,
            "earlier_reported_severity": old[2] if old else None,
            "later_reported_severity": new[2] if new else None,
            "earlier_reported_retest_stage": old[3] if old else None,
            "later_reported_retest_stage": new[3] if new else None,
        })
    return result, counts


def _html(payload: dict) -> str:
    """No-script focus lists: changed/added/absent first, unchanged collapsed."""
    blocks = [
        '<!doctype html><html lang="en"><head><meta charset="utf-8">',
        '<meta name="referrer" content="no-referrer">',
        '<meta http-equiv="Content-Security-Policy" content="',
        "default-src 'none'; base-uri 'none'; form-action 'none'; ",
        'connect-src \'none\'; img-src \'none\'; object-src \'none\'">',
        '<title>PRIVATE HUMAN packet comparison</title></head><body><main>',
        '<h1>PRIVATE HUMAN selected-packet comparison</h1>',
        '<p role="status">', escape(_HISTORY_HOLD), '</p>',
        '<p>', str(payload["packet_count"]), ' source-selected local packets. ',
        'Each transition reflects HUMAN-supplied order, NOT independently ',
        'verified chronology or matching tenant identity.</p>',
    ]
    severity_priority = {"critical": 0, "high": 1, "medium": 2,
                         "low": 3, "info": 4}
    for transition in payload["transitions"]:
        totals = transition["counts"]
        blocks.extend(('<section><h2>HUMAN-selected packets ',
                       str(transition["from_ordinal"]), ' → ',
                       str(transition["to_ordinal"]), '</h2><p>',
                       str(totals["changed"]), ' changed; ',
                       str(totals["added"]), ' added to selection; ',
                       str(totals["absent"]), ' absent from later selection; ',
                       str(totals["unchanged"]), ' unchanged.',
                       '</p><p>Absence does not mean fixed or closed. ',
                       'Changed only means source-selected presentation fields ',
                       'differ. Priority uses reported severity, not a risk verdict.</p>'))
        blocks.append("<h3>Reported stage movement (NOT independently verified)</h3><ul>")
        for prior in _STAGES:
            for later in _STAGES:
                number = transition["reported_stage_movements"][prior][later]
                if number:
                    blocks.extend(("<li>", escape(prior), " → ",
                                   escape(later), ": ", str(number),
                                   " selected presentations</li>"))
        blocks.append("</ul>")
        for kind, heading in (
            ("changed", "Changed reported fields"),
            ("added", "Only in later selected packet"),
            ("absent", "Absent from later selected packet (NOT fixed)"),
            ("unchanged", "Unchanged reported presentation"),
        ):
            matching = [row for row in transition["items"]
                        if row["change_kind"] == kind]
            matching.sort(key=lambda item: (
                severity_priority.get(item["later_reported_severity"]
                                      or item["earlier_reported_severity"], 5),
                item["finding_id"]))
            blocks.extend(("<details" + ("" if kind == "unchanged" else " open") +
                           "><summary>", escape(heading), " (",
                           str(len(matching)), ")</summary>"))
            if matching:
                blocks.extend(('<table><thead><tr><th>Finding ID</th>',
                               '<th>Changed columns</th><th>Earlier severity</th>',
                               '<th>Later severity</th><th>Earlier retest label</th>',
                               '<th>Later retest label</th></tr></thead><tbody>'))
                for item in matching:
                    cells = (
                        item["finding_id"],
                        ", ".join(item["changed_display_fields"]) or "—",
                        item["earlier_reported_severity"] or "not selected",
                        item["later_reported_severity"] or "not selected",
                        item["earlier_reported_retest_stage"] or "not selected",
                        item["later_reported_retest_stage"] or "not selected",
                    )
                    blocks.append("<tr>")
                    blocks.extend('<td dir="auto">' + escape(value, quote=True) +
                                  "</td>" for value in cells)
                    blocks.append("</tr>")
                blocks.append("</tbody></table>")
            else:
                blocks.append("<p>No records in this classification.</p>")
            blocks.append("</details>")
        blocks.append("</section>")
    blocks.extend(('<p>Local SHA-256 only detects comparison-input drift. ',
                   'Unsigned digests and claimed HUMAN grouping never prove ',
                   'sender identity, customer consent, findings or remediation.',
                   '</p></main></body></html>'))
    return "".join(blocks)


def publish_private_review_history(
    review_dirs: list[str | Path], *,
    output_parent: str | Path,
    output_name: str,
    human_declares_same_scope: bool,
) -> Path:
    """Reopen 2–12 original PRIVATE packets and publish ONE local review desk.

    No inferred chronology, account identity or consent. Input packets and
    earlier human work remain untouched; output is wholly new PRIVATE data.
    """
    if human_declares_same_scope is not True:
        raise ValueError("explicit HUMAN same-scope declaration is required")
    if type(review_dirs) is not list or not 2 <= len(review_dirs) <= 12:
        raise ValueError("select two through twelve original PRIVATE packets")
    if type(output_name) is not str or _SAFE_NAME.fullmatch(output_name) is None:
        raise ValueError("invalid PRIVATE output name")
    originals: list[dict[str, tuple[str, ...]]] = []
    hashes: list[str] = []
    paths: set[Path] = set()
    for value in review_dirs:
        if type(value) not in (str, Path):
            raise ValueError("PRIVATE source path must be a literal path")
        path = Path(value)
        if path in paths:
            raise ValueError("repeated original PRIVATE packet path")
        paths.add(path)
        original, digest = _read_packet(path)
        if digest in hashes:
            raise ValueError("repeated original source bytes cannot be a new moment")
        originals.append(original)
        hashes.append(digest)
    transitions = []
    for index in range(1, len(originals)):
        previous_ids = {unicodedata.normalize("NFKC", key): key
                        for key in originals[index - 1]}
        current_ids = {unicodedata.normalize("NFKC", key): key
                       for key in originals[index]}
        # Visually equivalent but byte-distinct identifiers in separate
        # moments cannot silently masquerade as a stable original finding.
        if any(previous_ids[key] != current_ids[key]
               for key in previous_ids.keys() & current_ids.keys()):
            raise ValueError("cross-packet compatibility identity drift: HUMAN HOLD")
        items, counts = _difference(originals[index - 1], originals[index])
        # Count source-reported labels only; no verified remediation inference.
        movements = {before: {after: 0 for after in _STAGES}
                     for before in _STAGES}
        for item in items:
            before = item["earlier_reported_retest_stage"] or "not_in_selection"
            after = item["later_reported_retest_stage"] or "not_in_selection"
            movements[before][after] += 1
        transitions.append({
            "from_ordinal": index,
            "to_ordinal": index + 1,
            "counts": counts,
            "reported_stage_movements": movements,
            "items": items,
        })
    payload = {
        "schema": "lightup.private.finding-review-history.v1",
        "classification": "PRIVATE_HUMAN_REVIEW_ONLY",
        "packet_count": len(originals),
        "operator_selected_csv_sha256": hashes,
        "human_declared_same_scope": True,
        "chronology_authenticated": False,
        "source_authenticated": False,
        "client_consent_verified": False,
        "remediation_verified": False,
        "release_approved": False,
        "transitions": transitions,
    }
    json_body = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                           indent=2) + "\n"
    html_body = _html(payload)
    parent = Path(output_parent)
    parent_fd = _private_parent(parent)
    stage = ".history-" + secrets.token_hex(12)
    stage_fd = -1
    created = published = False
    names = ("history.html", "history.json", "REVIEW_ONLY.txt")
    try:
        os.mkdir(stage, 0o700, dir_fd=parent_fd)
        created = True
        stage_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY |
                           os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
        os.fchmod(stage_fd, 0o700)
        _file(stage_fd, names[0], html_body.encode("utf-8"))
        _file(stage_fd, names[1], json_body.encode("utf-8"))
        _file(stage_fd, names[2], (_HISTORY_HOLD + "\n").encode("utf-8"))
        os.fsync(stage_fd)
        _publish_noreplace(parent_fd, stage, output_name)
        published = True
        os.fsync(parent_fd)
        return parent / output_name
    finally:
        if not published and created:
            if stage_fd >= 0:
                for name in names:
                    try:
                        os.unlink(name, dir_fd=stage_fd)
                    except FileNotFoundError:
                        pass
            try:
                os.rmdir(stage, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        if stage_fd >= 0:
            os.close(stage_fd)
        os.close(parent_fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=_HISTORY_HOLD)
    parser.add_argument("--review-dir", action="append", required=True,
                        help="Original native PRIVATE review folder, selected order (2–12)")
    parser.add_argument("--output-parent", required=True,
                        help="Existing PRIVATE owner-only 0700 directory")
    parser.add_argument("--output-name", required=True,
                        help="New private child folder name, must not exist")
    parser.add_argument("--human-confirm-same-scope", action="store_true",
                        help="I independently checked this selection; no identity is verified by software")
    args = parser.parse_args()
    try:
        location = publish_private_review_history(
            args.review_dir, output_parent=args.output_parent,
            output_name=args.output_name,
            human_declares_same_scope=args.human_confirm_same_scope)
    except (ValueError, OSError, UnicodeError, csv.Error) as exc:
        print("HOLD: " + str(exc), file=sys.stderr)
        return 3
    print("PRIVATE HUMAN REVIEW ONLY: " + str(location))
    return 2


if __name__ == "__main__":
    sys.exit(main())
