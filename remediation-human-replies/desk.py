#!/usr/bin/env python3
"""One-command PRIVATE offline HUMAN follow-up desk, agenda and local calendar.

Admits the unchanged original encrypted selected source-redacted .luhq
and an existing matching HUMAN-only encrypted .luhr ONCE. Optional prior
comparison must match exact original selected source. No network, sending,
scan, grant, finding verification, consent or release.
"""
from __future__ import annotations

import argparse
import html
from pathlib import Path
import sys

import reply
import worklist
import agenda

KIND = "lightup.private_original_bound_human_followup_desk.v1"
WARNING = (
    "PRIVATE local HUMAN follow-up draft only, not original authenticated "
    "producer/client or unique reviewer identity, current consent, "
    "verified security finding, genuine remediation, retest, grant, "
    "HUMAN GO or approval. INCUBATE M3/M7 DRAFT/HOLD."
)
STYLE = """
body{background:#ecf2f8;color:#18304b;font:16px/1.55 system-ui,sans-serif;margin:0}
main{max-width:940px;margin:1rem auto;padding:1rem}
section,aside{background:white;border:1px solid #cad6e3;border-radius:10px;padding:1rem 1.3rem;margin:1rem 0}
aside{border-left:6px solid #b07a2d}
a{color:#205f99}a:focus-visible{outline:3px solid #b07a2d}
dl{display:grid;grid-template-columns:1fr 1fr;gap:.5rem}
dt{font-weight:700}dd{margin:0}
@media print{body{background:white}}
"""

def require(condition: bool, reason: str) -> None:
    reply.require(condition, reason)

def esc(value: object) -> str:
    return html.escape(str(value), quote=True)

def home(stats: dict, comparison: bool) -> bytes:
    lines = [
        '<!doctype html><html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; ',
        'script-src \'none\'; style-src ',
        reply.hash_csp(STYLE.encode()), '; img-src \'none\'; ',
        'connect-src \'none\'; object-src \'none\'; base-uri \'none\'">',
        '<title>LightUp PRIVATE HUMAN follow-up desk</title>',
        '<style>', STYLE, '</style></head><body><main>',
        '<h1>LightUp · PRIVATE HUMAN follow-up desk</h1>',
        '<aside><strong>INCUBATE · HUMAN ONLY · DRAFT/HOLD</strong><p>',
        esc(WARNING), '</p>',
        '<p>Encrypted original selected HUMAN handoff and encrypted returned ',
        'HUMAN-only statements were admitted. A password, digest or HUMAN ',
        'answer does not authenticate clients, original evidence, reviewer ',
        'independence, authorization or fixes.</p></aside>',
        '<section><h2>Original source-redacted HUMAN groups</h2><dl>',
        '<dt>Original selected groups</dt><dd>',
        str(stats["selected"]), '</dd>',
        '<dt>Original self-declared due dates</dt><dd>',
        str(stats["dated"]), '</dd>',
        '<dt>Undated (never inferred)</dt><dd>',
        str(stats["undated"]), '</dd>',
        '<dt>Local tentative calendar entries</dt><dd>',
        str(stats["calendar"]), '</dd>',
        '<dt>Earlier literal HUMAN differences</dt><dd>',
        str(stats["differences"]) if comparison else
        'UNKNOWN (no previous original-bound comparison supplied)',
        '</dd></dl>',
        '<p>These are HUMAN selected groups, not verified distinct cases.',
        ' Every answer remains technically unverified.</p></section>',
        '<section><h2>Continue reviewing offline</h2>',
        '<p><a href="human-worklist.html">1 · HUMAN next-action worklist</a>',
        ' — questions, waiting, discussion, declined and answered-but-not-verified.',
        ' If an earlier comparison was admitted, local differences surface ',
        'first within each HUMAN category.</p>',
        '<p><a href="human-agenda.html">2 · Original due-date agenda</a>',
        ' — exact source-declared due dates and separate undated groups.',
        ' No invented date or automatic outreach.</p>',
        '<p><a href="private-human-calendar.ics">3 · Optional PRIVATE',
        ' tentative HUMAN .ics calendar</a> — deliberately excludes owners, ',
        'original reason text, answers, questions and requested-action text.',
        ' No external calendar is contacted by this software. A manual import',
        ' into another service still requires real disclosure permission.</p>',
        '<p>The owner-private JSON companions ',
        '<code>private-human-worklist.json</code> and ',
        '<code>private-human-agenda.json</code> contain PRIVATELY ',
        'declared HUMAN data and are NOT anonymous public exports.</p></section>',
        '<section><h2>Original release fence</h2>',
        '<p>No verified original finding, source authentication, ',
        'client/operator consent, security fix, retest, native Apply, ',
        'active target action, grant, scan, approval, HUMAN GO, ',
        'deployment or main merge. The original held source-owner, ',
        'exact-head permanent named VPS and hosted CI, independent ',
        'security/privacy/browser review and actual scope/consent remain ',
        'external and mandatory.</p></section></main></body></html>'
    ]
    return "".join(lines).encode("utf-8")

def publish(handoff: Path, sealed: Path, output: Path,
            comparison: Path | None = None) -> None:
    require(handoff.is_absolute() and sealed.is_absolute()
            and handoff != sealed and output.is_absolute()
            and output.parent == output.parent.resolve(strict=True)
            and not output.exists() and not output.is_symlink(),
            "Choose exact two distinct PRIVATE encrypted HUMAN inputs and fresh output")
    sources = [handoff, sealed]
    if comparison is not None:
        require(comparison.is_absolute() and comparison not in sources,
                "Prior comparison needs separate absolute native private source")
        sources.append(comparison)
    for path in sources:
        require(path != output and path.parent != output
                and output not in path.parents and path not in output.parents,
                "PRIVATE source and output workroom paths may not overlap")
    original, digest, before_handoff = reply.source(handoff)
    humans, before_response = reply.admitted_reply(sealed, original, digest)
    old_flags, old_bytes = (worklist.source_bound_differences(
        comparison, original, digest) if comparison is not None else (None, None))

    followups, group_counts = worklist.grouped(original, humans, digest, old_flags)
    timed, timeless = agenda.agenda_items(original, humans)
    calendar_bytes, event_count = agenda.calendar(timed)
    worklist_page = worklist.html_page(followups, group_counts)
    agenda_page = agenda.document(timed, timeless)
    stats = {
        "selected": len(followups),
        "dated": len(timed),
        "undated": len(timeless),
        "calendar": event_count,
        "differences": sum(old_flags) if old_flags is not None else None,
    }
    portal = home(stats, comparison is not None)
    private_worklist = reply.schedule.canonical({
        "kind": worklist.KIND, "version": 1,
        "disposition": "PRIVATE_HUMAN_ONLY_DRAFT_HOLD",
        "authority_granted": False, "consent_verified": False,
        "source_authenticated": False, "remediation_verified": False,
        "source_redacted_original_sha256": digest,
        "original_selected_human_groups": len(followups),
        "earlier_private_comparison_supplied": old_flags is not None,
        "human_followup_items": followups,
        "warning": worklist.WARNING,
    })
    private_agenda = reply.schedule.canonical({
        "kind": agenda.KIND, "version": 1,
        "disposition": "PRIVATE_HUMAN_ONLY_DRAFT_HOLD",
        "authority_granted": False, "consent_verified": False,
        "source_authenticated": False, "remediation_verified": False,
        "source_redacted_original_sha256": digest,
        "original_selected_human_groups": stats["selected"],
        "original_dated_human_groups": stats["dated"],
        "original_undated_human_groups": stats["undated"],
        "local_tentative_calendar_events": stats["calendar"],
        "original_dated_tasks": timed,
        "original_undated_tasks": timeless,
        "warning": agenda.WARNING,
    })
    for value in (private_worklist, private_agenda):
        require(len(value) <= 2_000_000, "PRIVATE HUMAN desk output is oversized")
    require(reply.encrypted_cockpit.private_envelope(handoff) == before_handoff
            and reply.schedule_vault.private_vault(sealed) == before_response
            and (comparison is None or
                 reply.schedule_vault.private_vault(comparison) == old_bytes),
            "Original native HUMAN encrypted source/response changed before desk publication")

    reply.exclusive_output(output, sources, {
        "index.html": portal,
        "human-worklist.html": worklist_page,
        "human-agenda.html": agenda_page,
        "private-human-worklist.json": private_worklist,
        "private-human-agenda.json": private_agenda,
        "private-human-calendar.ics": calendar_bytes,
        "README.txt": (
            WARNING + "\nAll files are PRIVATE, owner-only 0600 in 0700 "
            "directory; even static HTML and redacted follow-up counts can "
            "contain sensitive self-declared HUMAN data. The .ics is not "
            "automatically imported, synced, sent or used as a reminder. "
            "Obtain actual separate permission before any transfer or "
            "external calendar import. No original findings have been "
            "verified, resolved or modified.\n"
        ).encode("utf-8"),
    })
    print("REVIEW_ONLY: PRIVATE original selected HUMAN desk:", output / "index.html")
    print("Original HUMAN date groups:", stats["dated"], "undated:", stats["undated"])
    print("Local tentative .ics HUMAN entries:", event_count)
    print("No target, network, calendar provider, remediation or grant used.")

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--handoff", type=Path, required=True)
    parser.add_argument("--reply", type=Path, required=True)
    parser.add_argument("--comparison", type=Path, required=False,
                        help="Optional exact-source PRIVATE prior multi-reply comparison")
    parser.add_argument("--output-dir", type=Path, required=True,
                        help="New absolute private 0700 HUMAN follow-up workroom")
    args = parser.parse_args()
    try:
        publish(args.handoff, args.reply, args.output_dir, args.comparison)
        return 2
    except (reply.single_review.review.Hold, OSError, ValueError,
            KeyError, TypeError, ImportError, RuntimeError, OverflowError) as exc:
        print("HOLD: PRIVATE original HUMAN desk:", str(exc), file=sys.stderr)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
