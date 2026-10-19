#!/usr/bin/env python3
"""Complete PRIVATE LightUp original-source HUMAN workroom, with custody view.

Add-only composition of existing source-owner builders; no owner source changes.
Original authentication/read access is checked before encrypted source/HUMAN
admission. A real client grant, assessment, remediation or scan never occurs.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "remediation-evidence-bridge"))

import complete as original_complete
import open_current as custody

MAX_PRIVATE_OUTPUT = 18 * 1024 * 1024

def _portal_extra(page: bytes) -> bytes:
    needle = b'<section class="foot">'
    if page.count(needle) != 1 or b'href="07-evidence-custody.html"' in page:
        raise ValueError("Original source-owned offline portal changed; HUMAN HOLD.")
    # Navigation only: static literal local link, no script, sensitive data,
    # browser persistence, iframe, remote asset or hidden auth route.
    extra = (
        b'<section aria-labelledby="custody-title"><h2 id="custody-title">'
        b'PRIVATE original-source evidence custody</h2><div class="cards">'
        b'<a class="card wide" href="07-evidence-custody.html">'
        b'<span class="number">WORKSPACE 07</span>'
        b'<h3>Bulk local evidence custody and preserve-first HUMAN follow-up</h3>'
        b'<p>Recompare local SHA-256 evidence bytes and ORIGINAL source claims, '
        b'preserve native HUMAN requests, and preview PRIVATE follow-up drafts. '
        b'No target action, authorization, confirmed fix or verified retest.</p>'
        b'<span class="action">Open offline PRIVATE custody desk \xe2\x86\x92</span>'
        b'</a></div></section>'
    )
    amended = page.replace(needle, extra + needle)
    if len(amended) > original_complete.build_portal.__globals__["MAX_BYTES"]:
        raise ValueError("Original static portal exceeds safe source bound.")
    return amended

def _build(csv_text: str, client: str, engagement: str,
           original_source: Path, private_human: Path) -> dict[str, bytes]:
    vault = original_complete._vault()
    original = original_complete._admit_encrypted_source(
        csv_text, client, engagement, original_source)
    if original["mode"] not in original_complete.WORKSPACE_MODES:
        raise ValueError("Original current multiview source admission HOLD.")
    now = original_complete._rows(csv_text)
    previous = [original_complete._rows(csv) for csv in original["historical_original_csv"]]
    originals = original_complete._original_workspace_apps(
        original, csv_text, client, engagement)
    ledger_html, packet = original_complete._evidence_view(
        csv_text, client, engagement, private_human, vault)
    if packet is None:
        raise ValueError("Original encrypted HUMAN source is required for custody.")
    # The exact original owner validators admit every source-linked HUMAN record;
    # only then can custody expose the file index and original human requests.
    custody.original_admission._records(
        packet, custody._current_rows(csv_text.encode("utf-8", "strict")))
    archive_html = custody._render(csv_text.encode("utf-8", "strict"), packet)
    contents = {
        "01-review.html": original_complete.build_desk(
            now, previous[-1] if previous else None),
        "02-ticketdesk.html": originals["ticketdesk"],
        "03-casework.html": originals["casework"],
        "05-evidence-ledger.html": ledger_html,
        "06-human-actions.html": original_complete.build_board(
            now, packet, previous[-1] if previous else None),
        "07-evidence-custody.html": archive_html,
    }
    if previous:
        snapshots = [(dict(unverified_historical=True), records) for records in previous]
        snapshots.append((dict(current_authenticated=True), now))
        contents["04-history.html"] = original_complete.build_history_desk(
            original_complete.history_review(snapshots))
    portal = original_complete.build_portal(
        now, len(previous), True, previous[-1] if previous else None)
    contents["index.html"] = _portal_extra(portal)
    if not 7 <= len(contents) <= 8 or sum(map(len, contents.values())) > MAX_PRIVATE_OUTPUT:
        raise ValueError("Complete PRIVATE workroom output limit violated.")
    for name, body in contents.items():
        if not name.endswith(".html") or type(body) is not bytes or not body.startswith(b"<!doctype html>"):
            raise ValueError("Original private view contract changed.")
        if b"connect-src 'none'" not in body:
            raise ValueError("Original offline network refusal missing.")
    return contents

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("db", "email", "client-id", "engagement-id"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--source", type=Path, required=True,
                        help="Original existing PRIVATE encrypted engagement multiview .ltv")
    parser.add_argument("--human", type=Path, required=True,
                        help="Original existing PRIVATE encrypted HUMAN collaboration .ltv")
    parser.add_argument("--output-dir", type=Path, required=True,
                        help="NEW owner-only 0700 directory under existing protected parent")
    parser.add_argument("--ack-private-workspace", action="store_true", required=True)
    args = parser.parse_args(argv)
    try:
        if (not args.ack_private_workspace or not sys.stdin.isatty()
            or args.source.suffix.lower() != ".ltv" or args.human.suffix.lower() != ".ltv"):
            raise ValueError("Real private TTY, existing original .ltv sources and explicit acknowledgement required.")
        # One current real account/client/engagement read, before any private output.
        current = original_complete._authorized_summary(
            db=args.db, email=args.email,
            client_id=args.client_id, engagement_id=args.engagement_id)
        contents = _build(current, args.client_id, args.engagement_id,
                          args.source, args.human)
        # Unchanged original atomic owner-only 0700 folder + 0600 files
        # publisher. Any failure removes partially created new files/folder.
        original_complete._publish(args.output_dir, contents)
        print("One new owner-only offline PRIVATE LightUp workroom created: index.html.")
        print("Includes original source review, Ticket Desk, Casework, HUMAN Evidence Ledger, HUMAN action board, custody & optional history.")
        print("All original source/HUMAN content was admitted before private publication.")
        print("HUMAN-only: no consent, grant, scanner, live target, verified fix or retest.")
        return 0
    except Exception:
        print("HUMAN HOLD: no complete PRIVATE workroom published; review original current authorization, encrypted source identity and owner-only destination.", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
