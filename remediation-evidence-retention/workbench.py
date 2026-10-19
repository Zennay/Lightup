#!/usr/bin/env python3
"""Private operator terminal for the complete original LightUp retention workflow.

No separate login bypass, no synthetic source and no live scanner. Every menu
action re-reads ORIGINAL current LightUp account/client/engagement authorization,
the original encrypted HUMAN index and the actual owner-private evidence bytes.
Original Source/HUMAN Apply, actual legal-hold release and file deletion absent.
"""
from __future__ import annotations

import argparse
from datetime import date, datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import secrets
import sys

import human_calendar as private_calendar
import bulk_review as bulk
import desk
import history
import reconcile
import request_handoff as followup
import retention as retention

original = retention.transfer
MENU = (
    ("1", "Inspect current original source and PRIVATE evidence/review"),
    ("2", "Stage first encrypted HUMAN retention plan"),
    ("3", "Renew existing encrypted HUMAN retention plan"),
    ("4", "Publish current PRIVATE Evidence + Casework desk"),
    ("5", "Preview/stage due questions into ORIGINAL HUMAN Request Desk"),
    ("6", "Publish encrypted HUMAN retention revision history"),
    ("7", "Inspect/publish later original HUMAN Request Desk continuity"),
    ("8", "Switch to an existing PRIVATE encrypted retention plan"),
    ("9", "Export source-bound anonymous PRIVATE HUMAN review calendar"),
    ("10", "Create PRIVATE offline bulk retention editor (.tsv)"),
    ("11", "Seal edited PRIVATE bulk retention review to NEW encrypted plan"),
    ("0", "Exit — no material changed"),
)
MAX_INPUT_PATH = 1024


def _candidate_dir(value: Path) -> Path:
    return retention._hold_if_not_private_directory(value)


def _new(args, kind: str, suffix: str) -> Path:
    folder = _candidate_dir(args.output_dir)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return folder / ("lightup-private-" + kind + "-" + stamp
                     + "-" + secrets.token_hex(6) + suffix)


def _private_existing_path(label: str, suffix: str) -> Path:
    raw = input(label + " (exact private absolute " + suffix + " path; blank HOLD): ").strip()
    if not raw or len(raw) > MAX_INPUT_PATH or "\x00" in raw or not raw.startswith("/"):
        raise ValueError("Literal absolute PRIVATE input path required.")
    p = Path(raw)
    if p.suffix.lower() != suffix:
        raise ValueError("Unexpected PRIVATE input type.")
    return p


def _context(args, vault, *, require_plan: bool = True):
    # Deliberately repeats current original authentication at the START of
    # every menu action. An earlier menu read is never treated as a grant.
    envelope, packet, indexed, password_sha = original.current_human(
        args, vault, keep_passphrase_fingerprint=True)
    if require_plan:
        if args.plan is None:
            raise ValueError("Stage or select an existing PRIVATE encrypted HUMAN retention plan first.")
        items, plan_sha = retention._load_current_plan(args, vault, packet, indexed)
    else:
        files, _ = retention._read_material(args.directory, packet, indexed, vault)
        items = files
        plan_sha = None
    return envelope, packet, indexed, password_sha, plan_sha, items


def _inspect(args, vault):
    envelope, packet, indexed, old_sha, plan_sha, rows = _context(
        args, vault, require_plan=args.plan is not None)
    print("ORIGINAL CURRENT source and all actual PRIVATE evidence bytes admitted.")
    print("Indexed PRIVATE files:", len(rows))
    if args.plan is not None:
        due = sum(row["review_on"] <= date.today().isoformat() for row in rows)
        flags = sum(row["decision"] == "legal_hold" for row in rows)
        print("HUMAN reviews due:", due, "· unverified HUMAN hold labels:", flags)
    print("No local files deleted, no active authority inferred.")


def _stage_first(args, vault):
    if args.plan is not None:
        raise ValueError("An existing plan is selected; use Renew, never overwrite it.")
    envelope, packet, indexed, old_sha, _, files = _context(
        args, vault, require_plan=False)
    target = _new(args, "review-v1", ".ltv")
    clone = SimpleNamespace(**vars(args), output=target, action="stage")
    retention._seal_review(clone, vault, packet, indexed, old_sha)
    args.plan = target
    print("New PRIVATE encrypted original-linked plan is now selected in this session.")
    print("Existing HUMAN evidence and original source remain unchanged.")


def _renew(args, vault):
    _, packet, indexed, original_sha, plan_sha, old_items = _context(args, vault)
    target = _new(args, "review-renewal", ".ltv")
    clone = SimpleNamespace(**vars(args), output=target, action="renew")
    retention._seal_review(clone, vault, packet, indexed, original_sha,
                           previous=old_items, previous_key_hash=plan_sha)
    args.plan = target
    print("New private encrypted plan selected. All previous plans are preserved.")


def _desk(args, vault):
    _, packet, indexed, original_sha, plan_sha, items = _context(args, vault)
    rows, stats = desk._items(packet, items)
    confirm = input(
        'Type "INCLUDE PRIVATE NOTES" to include private HUMAN Casework notes; '
        'otherwise Enter omits them: '
    )
    if confirm not in ("", "INCLUDE PRIVATE NOTES"):
        raise ValueError("Unknown private disclosure acknowledgement.")
    include = confirm == "INCLUDE PRIVATE NOTES"
    html = desk._html(rows, stats, packet["source_sha256"], private_casework=include)
    if len(html) > desk.MAX_HTML:
        raise ValueError("Current PRIVATE desk exceeds bounded HTML capacity.")
    out = _new(args, "operations-desk", ".html")
    vault._exclusive_output(out, html)
    print("New original-source/current-file-bound scriptless PRIVATE 0600 desk:", out.name)
    print("HUMAN due:", stats["due"], "· open original HUMAN requests:",
          stats["open_native_requests"], "· possible follow-ups:",
          stats["new_request_candidates"])


def _due_requests(args, vault):
    if getattr(args, "_staged_due_this_session", False):
        print("HUMAN HOLD: A new original-native encrypted due draft has already been "
              "staged this session. Import and independently review the previous "
              "draft in the original HUMAN app before preparing another.")
        return
    if args.plan is None:
        raise ValueError("Stage or select an existing private review plan first.")
    action = input("PREVIEW only [Enter], or explicitly type STAGE to prepare new "
                   "native HUMAN follow-up drafts: ").strip()
    if action not in ("", "STAGE"):
        raise ValueError("Unknown HUMAN request choice.")
    clone = SimpleNamespace(**vars(args), action="stage" if action else "preview")
    if action:
        clone.output = _new(args, "human-request-drafts", ".ltv")
    # Original collaborator reauthenticates and validates full current source,
    # local actual bytes and encrypted HUMAN data at the action boundary.
    followup.operate(clone, vault)
    if action:
        args._staged_due_this_session = True


def _switch(args, vault):
    path = _private_existing_path("Select existing encrypted HUMAN retention plan", ".ltv")
    current = args.plan
    # A selected plan is not admitted just because its name or bytes exist.
    # Authenticate original again and check the actual original source + all
    # extracted material fingerprints against this candidate plan.
    clone = SimpleNamespace(**{**vars(args), "plan": path})
    _, packet, indexed, _ = original.current_human(
        clone, vault, keep_passphrase_fingerprint=True)
    items, _ = retention._load_current_plan(clone, vault, packet, indexed)
    if not items:
        raise ValueError("Empty original-source-bound HUMAN retention plan.")
    args.plan = path
    args._staged_due_this_session = False
    print("Selected distinct encrypted PRIVATE HUMAN plan with original current"
          " source and actual evidence bytes confirmed.")
    print("Current indexed HUMAN review entries:", len(items))


def _history(args, vault):
    if args.plan is None:
        raise ValueError("Select at least one private plan first.")
    raw = input("Number of DISTINCT encrypted plans to compare (2–12): ").strip()
    if not raw.isascii() or not raw.isdecimal() or not 2 <= int(raw) <= history.MAX_PLANS:
        raise ValueError("Original HUMAN revision count is outside bounded capacity.")
    paths = [_private_existing_path("Original encrypted review #" + str(n), ".ltv")
             for n in range(1, int(raw) + 1)]
    if len({str(path.expanduser().absolute()) for path in paths}) != len(paths):
        raise ValueError("Repeated private encrypted review file.")
    _, packet, indexed, original_sha, plan_sha, _ = _context(args, vault)
    clone = SimpleNamespace(**{**vars(args), "plan": paths})
    files, snapshots = history._open_plans(clone, vault, packet, indexed)
    rows, stats = history._row_deltas(files, snapshots)
    html = history._render(rows, snapshots, stats, packet["source_sha256"])
    if len(html) > history.MAX_OUTPUT:
        raise ValueError("Current original HUMAN history exceeds private size limit.")
    out = _new(args, "retention-history", ".html")
    vault._exclusive_output(out, html)
    print("New owner-private 0600 original-source-bound review history:", out.name)
    print("Distinct plans:", len(snapshots), "· files with HUMAN changes:",
          stats.get("files_changed", 0))


def _calendar(args, vault):
    if args.plan is None:
        raise ValueError("An original-source-bound encrypted HUMAN plan is required.")
    # This native read must happen afresh, not from prior menu actions.
    ics, days, files = private_calendar.current_calendar(args, vault)
    target = _new(args, "human-review-calendar", ".ics")
    vault._exclusive_output(target, ics)
    print("Created new anonymized PRIVATE 0600 local iCalendar:", target.name)
    print("HUMAN review days:", days, "· original private material:", files)
    print("No calendar connected, no identifier, automatic deletion or consent.")


def _bulk_export(args, vault):
    if args.plan is None:
        raise ValueError("Select a source-bound original encrypted HUMAN plan first.")
    clone = SimpleNamespace(**vars(args), output=_new(args, "bulk-review-editor", ".tsv"),
                            action="export")
    bulk._export(clone, vault)
    print("PRIVATE neutral editor: edit only decision, review_on, note_edit.")
    print("NEVER use a synced spreadsheet or upload private review material.")


def _bulk_import(args, vault):
    if args.plan is None:
        raise ValueError("Select matching previous encrypted HUMAN plan first.")
    editor = _private_existing_path("Exact existing owner-private edited TSV", ".tsv")
    clone = SimpleNamespace(**vars(args), edited=editor,
                            output=_new(args, "bulk-review-renewal", ".ltv"),
                            action="import")
    # New passphrase and any HUMAN legal-hold changes are explicitly admitted
    # inside the original-source-bound bulk sealing function.
    bulk._import(clone, vault)
    args.plan = clone.output
    args._staged_due_this_session = False
    print("NEW encrypted owner-private HUMAN plan selected in current session."
          " Original plan and evidence remain unchanged.")


def _request_reconciliation(args, vault):
    if args.plan is None:
        raise ValueError("Stage or select an existing private review plan first.")
    drafts = _private_existing_path("Our ORIGINAL-native encrypted HUMAN draft", ".ltv")
    later = _private_existing_path("Separate later ORIGINAL-native HUMAN workroom", ".ltv")
    if drafts.expanduser().absolute() == later.expanduser().absolute():
        raise ValueError("Native HUMAN input files must be distinct.")
    response = input('Type "PUBLISH PRIVATE STATUS" for a new private HTML report, '
                     'otherwise Enter only prints counts: ').strip()
    if response not in ("", "PUBLISH PRIVATE STATUS"):
        raise ValueError("Invalid HUMAN continuity choice.")
    clone = SimpleNamespace(**vars(args), drafts=drafts, later=later,
                            action="publish" if response else "inspect")
    if response:
        clone.output = _new(args, "human-request-continuity", ".html")
    # Native original code always rechecks current original source and every
    # real private material byte, even when earlier menu actions succeeded.
    reconcile.operate(clone, vault)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for item in ("db", "email", "client-id", "engagement-id"):
        parser.add_argument("--" + item, required=True)
    parser.add_argument("--human", type=Path, required=True,
                        help="Existing original encrypted source-current HUMAN .ltv")
    parser.add_argument("--directory", type=Path, required=True,
                        help="Original existing 0700 PRIVATE material/receipt folder")
    parser.add_argument("--plan", type=Path,
                        help="Optional existing private retention review .ltv, or stage first")
    parser.add_argument("--output-dir", type=Path, required=True,
                        help="Existing real owner-private 0700 parent for NEW files only")
    parser.add_argument("--ack-private-material", action="store_true")
    args = parser.parse_args(argv)
    try:
        if not args.ack_private_material or not sys.stdin.isatty():
            raise ValueError("Original PRIVATE material HUMAN awareness and interactive terminal required.")
        _candidate_dir(args.output_dir)
        vault = original.ORIGINAL._vault()
        print("LightUp PRIVATE evidence-retention operator workbench · ORIGINAL CURRENT READ")
        print("Human coordination only; no original Apply, grant, scan, release or deletion.")
        choices = {
            "1": _inspect, "2": _stage_first, "3": _renew,
            "4": _desk, "5": _due_requests, "6": _history,
            "7": _request_reconciliation, "8": _switch, "9": _calendar,
            "10": _bulk_export, "11": _bulk_import,
        }
        while True:
            print("\n" + " | ".join(num + ": " + label for num,label in MENU))
            selected = input("HUMAN action number (0 to exit): ").strip()
            if selected == "0":
                print("Exited; no additional original LightUp state changes.")
                return 0
            action = choices.get(selected)
            if action is None:
                print("Unknown action. No PRIVATE output created.")
                continue
            try:
                action(args, vault)
            except (KeyboardInterrupt, EOFError):
                print("\nHUMAN HOLD: Action abandoned; previous original state untouched.",
                      file=sys.stderr)
                return 2
            except Exception:
                print("HUMAN HOLD: Current original source, evidence bytes, encrypted "
                      "private material or explicit HUMAN choice refused. "
                      "No complete artifact published for this action.", file=sys.stderr)
    except (KeyboardInterrupt, EOFError):
        print("HUMAN HOLD: Private operator session cancelled.", file=sys.stderr)
        return 2
    except Exception:
        print("HUMAN HOLD: Original private input, output parent or terminal not admitted.",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
