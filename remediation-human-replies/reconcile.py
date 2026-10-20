#!/usr/bin/env python3
"""Offline PRIVATE source-redacted comparison of 2..8 real HUMAN reply packets.

No agreement, signature, independent reviewer or original finding is inferred
from repeated local files. Purely self-declared HUMAN return comparison.
"""
from __future__ import annotations

import argparse
import hashlib
import html
from pathlib import Path
import sys

import reply

WARNING = (
    "PRIVATE HUMAN self-declared response comparison only. Different encrypted "
    "files are NOT necessarily different reviewers. Matching statements are "
    "NOT consensus, verified evidence, remediation, retest, valid consent, "
    "original authenticated source, grant, approval or HUMAN GO. DRAFT/HOLD."
)
KIND = "lightup.private_selected_human_reply_comparison.v1"
STYLE = """
body{background:#edf3f7;color:#182c43;font:15px/1.55 system-ui,sans-serif;margin:0}
main{max-width:1280px;padding:1.5rem;margin:auto}
section,aside{background:white;border:1px solid #cad7e4;border-radius:10px;padding:1rem 1.2rem;margin:1rem 0}
aside{border-left:6px solid #ad7b21}table{width:100%;border-collapse:collapse}
td,th{border-bottom:1px solid #b8cbdc;text-align:left;vertical-align:top;padding:.65rem}
td{white-space:pre-wrap;overflow-wrap:anywhere}
th{background:#f1f5fa}
.alert{border-left:5px solid #a94826;padding:.5rem 1rem}
.same{border-left:5px solid #527d56;padding:.5rem 1rem}
small{color:#455d78}
@media print{section{break-inside:avoid}body{background:#fff}}
"""

def require(ok: bool, msg: str) -> None:
    reply.require(ok, msg)

def q(value: object) -> str:
    return html.escape(str(value), quote=True)

def render(packet: dict, replies: list[list[dict]]) -> tuple[bytes, dict]:
    require(2 <= len(replies) <= 8 and
            all(len(group) == len(packet["items"]) for group in replies),
            "Incomplete selected HUMAN group/reviewer packet membership")
    count = len(packet["items"])
    differing_stage = 0
    differing_answer = 0
    differing_question = 0
    answered_by_any = 0
    fully_identical_rows = 0
    html_parts = [
        '<!doctype html><html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
        'script-src \'none\'; connect-src \'none\'; style-src ',
        reply.hash_csp(STYLE.encode()), '; img-src \'none\'; '
        'object-src \'none\'; base-uri \'none\'">',
        '<title>LightUp PRIVATE source-redacted HUMAN reply differences</title>',
        '<style>', STYLE, '</style></head><body><main>',
        '<h1>PRIVATE selected HUMAN response comparison</h1><aside>',
        '<strong>INCUBATE · REVIEW ONLY · DRAFT/HOLD</strong><p>', q(WARNING),
        '</p><p>Original selected human handoff and responses may still be ',
        'identifying and confidential. Local order reflects the supplied file ',
        'order, not authenticated time, identity, independence or truth. ',
        'Only an actual independent authorized reviewer can interpret claims. ',
        'NO automatic resolution, grant, scan, writeback or target action.</p></aside>',
        '<section><p><strong>Selected original source-redacted HUMAN tasks: ',
        str(count), '</strong> · <strong>Supplied encrypted reply files: ',
        str(len(replies)), '</strong>. These are file slots, NOT unique people.</p>',
        '<p>No original target, finding ID, private source packet SHA or client ',
        'engagement ID is asserted by this report.</p></section>',
    ]
    for ordinal, original in enumerate(packet["items"], 1):
        values = [rows[ordinal - 1] for rows in replies]
        statuses = {r["status"] for r in values}
        answers = {r["answer"] for r in values}
        questions = {r["question"] for r in values}
        stage_drift = len(statuses) > 1
        answer_drift = len(answers) > 1
        question_drift = len(questions) > 1
        differing_stage += int(stage_drift)
        differing_answer += int(answer_drift)
        differing_question += int(question_drift)
        answered_by_any += int(any(r["status"] == "answered_human_only" for r in values))
        fully_identical_rows += int(not(stage_drift or answer_drift or question_drift))
        label = ("Differences in self-declared HUMAN replies" if
                 stage_drift or answer_drift or question_drift else
                 "Literal matching HUMAN replies (NOT independent verification)")
        html_parts.extend([
            '<section><h2>Selected source-redacted HUMAN request ', str(ordinal),
            '</h2><p class="', ("alert" if (stage_drift or answer_drift or question_drift)
                              else "same"), '">', q(label), '</p>',
            '<p><strong>Original anonymous HUMAN reason:</strong> ',
            q(original["reason"]), '</p>',
            '<p><strong>Original HUMAN requested action:</strong> ',
            q(original["next_action"] or "Not recorded"), '</p>',
            '<p><small>The input packet may include self-declared owner labels, ',
            'tentative dates or sensitive text; none is independently trusted. ',
            'Missing or matching replies do NOT establish a fix.</small></p>',
            '<table><thead><tr><th>Unverified file slot</th>',
            '<th>HUMAN stage</th><th>PRIVATE HUMAN answer</th>',
            '<th>Further HUMAN question</th></tr></thead><tbody>',
        ])
        for slot, response in enumerate(values, 1):
            html_parts.extend([
                '<tr><td>Local reply file ', str(slot), '</td>',
                '<td>', q(response["status"]), '</td>',
                '<td>', q(response["answer"] or "No answer recorded"), '</td>',
                '<td>', q(response["question"] or "None recorded"), '</td></tr>'
            ])
        html_parts.append('</tbody></table></section>')
    html_parts.extend([
        '<section><h2>HUMAN comparison reading guide</h2><p>',
        'Differences in self-declared text show only literal differences between ',
        'local files. Matching rows can come from a single person; there is no ',
        'verified reviewer count, signed consent, authenticated source identity ',
        'or authority to change original findings. Explicit HUMAN follow-up is ',
        'required for any real interpretation.</p></section></main></body></html>'
    ])
    page = "".join(html_parts).encode("utf-8")
    require(len(page) <= 2_000_000, "PRIVATE HUMAN comparison page exceeds bound")
    counts = {
        "kind": KIND,
        "version": 1,
        "disposition": "PRIVATE_HUMAN_ONLY_DRAFT_HOLD",
        "authority_granted": False,
        "consent_verified": False,
        "source_authenticated": False,
        "remediation_verified": False,
        "unique_reviewers_verified": False,
        "original_selected_tasks": count,
        "submitted_encrypted_reply_files": len(replies),
        "literal_human_stage_difference_groups": differing_stage,
        "literal_human_answer_difference_groups": differing_answer,
        "literal_human_question_difference_groups": differing_question,
        "locally_answered_by_at_least_one_file": answered_by_any,
        "literal_identical_reply_row_groups": fully_identical_rows,
        "warning": WARNING,
    }
    return page, counts

def compare(source: Path, files: list[Path], output: Path) -> None:
    require(source.is_absolute() and
            2 <= len(files) <= 8 and
            len(set(files)) == len(files) and
            source not in files and all(p.is_absolute() for p in files),
            "Require 2–8 distinct absolute PRIVATE encrypted HUMAN reply files")
    require(output.is_absolute() and
            output.parent == output.parent.resolve(strict=True) and
            not output.exists() and not output.is_symlink() and
            source != output and source.parent != output
            and all(f != output and f.parent != output for f in files),
            "Choose a new separate PRIVATE 0700 output folder")
    original, source_digest, held_source = reply.source(source)
    copies = []
    seen_cipher = set()
    selected = []
    for file in files:
        require(output not in file.parents and file not in output.parents
                and output not in source.parents and source not in output.parents,
                "Original input/output PRIVATE paths may not overlap")
        rows, exact_bytes = reply.admitted_reply(file, original, source_digest)
        cipher_hash = hashlib.sha256(exact_bytes).digest()
        require(cipher_hash not in seen_cipher,
                "Repeated identical encrypted reply cannot masquerade as a separate file")
        seen_cipher.add(cipher_hash)
        copies.append((file, exact_bytes))
        selected.append(rows)
    page, counts = render(original, selected)
    require(reply.encrypted_cockpit.private_envelope(source) == held_source
            and all(reply.schedule_vault.private_vault(path) == old
                    for path, old in copies),
            "PRIVATE original selected handoff or HUMAN replies changed before publication")
    reply.exclusive_output(output, [source, *files], {
        "index.html": page,
        "anonymous-counts.json": reply.schedule.canonical(counts),
        "README.txt": (WARNING + "\nThe report is local plaintext PRIVATE. "
                       "No reviewer identity, chronology, actual signed consent, "
                       "original case, agreement, independent approval or "
                       "remediation verification is provided.\n").encode("utf-8"),
    })
    print("REVIEW_ONLY: PRIVATE selected HUMAN reply differences:", output / "index.html")
    print("Local reply files:", len(files), "selected HUMAN tasks:", len(original["items"]))
    print("No independent reviewer authenticity, consent or original finding proof.")

def main() -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--handoff", required=True, type=Path,
                     help="Exact original encrypted selected PRIVATE HUMAN-only .luhq")
    cli.add_argument("--reply", required=True, type=Path, action="append",
                     help="Original encrypted PRIVATE .luhr response (2–8; repeat)")
    cli.add_argument("--output-dir", required=True, type=Path,
                     help="NEW separate absolute owner-only private recipient workroom")
    a = cli.parse_args()
    try:
        compare(a.handoff, a.reply, a.output_dir)
        return 2
    except (reply.single_review.review.Hold, OSError, ValueError, KeyError,
            TypeError, RuntimeError, UnicodeError, ImportError, OverflowError) as e:
        print("HOLD: PRIVATE HUMAN comparison:", str(e), file=sys.stderr)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
