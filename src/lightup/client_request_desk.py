"""Interactive authenticated client request workspace (request intake only).

A real client account may review request history, prepare a fresh proposal,
import an offline Studio proposal and submit a new request for independent
operator review. The workspace never reviews, approves, grants, scans or
dispatches. No network connection, synthetic roles or operator impersonation.
"""
from __future__ import annotations

import sys
from pathlib import Path

from .client_request_cli import (
    ClientRequestError, _client_account, _existing_database, _record,
    canonical_assets, prepare_request,
)
from .client_request_snapshot import render_request_snapshot, save_private_snapshot
from .domain import DomainStore
from .engagements import AssessmentMode, RiskLevel

_MAX_INPUT = 4096


def _ask(label: str, *, max_chars: int = _MAX_INPUT) -> str:
    value = input(label).strip()
    if len(value) > max_chars or "\x00" in value:
        raise ClientRequestError("input is too long or contains a forbidden character")
    return value


def _notes() -> str:
    print("Notes/constraints: enter one line (up to 4000 chars); never paste credentials.")
    return _ask("Description: ", max_chars=4000)


def _manual_proposal() -> dict:
    print("Provide exact canonical hostnames, IPs or CIDRs, one per line.")
    print("Press Enter on an empty line after the final asset; maximum 80.")
    assets: list[str] = []
    for number in range(1, 82):
        line = _ask(f"Asset {number}: ", max_chars=253)
        if not line:
            break
        assets.append(line)
    if len(assets) > 80:
        raise ClientRequestError("more than 80 assets")
    canonical_assets(assets)
    risk = _ask("Requested risk (1 to 4): ", max_chars=1)
    if risk not in ("1", "2", "3", "4"):
        raise ClientRequestError("risk must be a single digit 1–4")
    return prepare_request(assets, int(risk), _notes())


def _studio_proposal() -> dict:
    from .client_proposal_intake import load_studio_proposal

    location = _ask("Existing local Studio v1 JSON file: ", max_chars=2048)
    if not location:
        raise ClientRequestError("a Studio export path is required")
    return load_studio_proposal(location)


def _decision(db: DomainStore, ctx, *, payload: dict, previous_id: str | None = None,
              expanded: bool = False) -> None:
    assets = payload["requested_assets"]
    print("\n=== DRAFT ONLY · NO AUTHORIZATION ===")
    print("Assessment: " + payload["requested_mode"])
    print("Risk: " + str(payload["requested_risk"]) + "/4")
    print("Assets (NOT an allowlist):")
    for asset in assets:
        print("  - " + asset)
    print("Explanation and constraints: " + payload["notes"])
    if previous_id:
        print("Previous rejected request: " + previous_id + " (left unchanged)")
    if payload.get("proposal_file_sha256"):
        print("Untrusted Studio file SHA-256: " + payload["proposal_file_sha256"])
    print("Review SHA-256 (unsigned): " + payload["intake_sha256"])
    print("A submitted or approved request is NOT consent or a scan permit.")

    # A client-side duplicate check helps humans notice repeat submissions,
    # but does not claim atomic server-side deduplication.
    open_status = {"submitted", "under_review"}
    records = db.list_assessment_requests(ctx)
    duplicates = [
        row for row in records
        if row.status.value in open_status
        and row.requested_mode is AssessmentMode.AUTHORIZED_ASSESSMENT
        and list(row.requested_assets) == assets
        and int(row.requested_risk) == payload["requested_risk"]
        and row.notes == payload["notes"]
    ]
    if duplicates:
        print("WARNING: an identical still-open request already exists.")
        print("Existing request: " + duplicates[0].request_id)
        if _ask("Type REPEAT REQUEST to create another anyway: ") != "REPEAT REQUEST":
            print("No request created.")
            return
    if expanded:
        if _ask("Broader scope/risk. Type ACKNOWLEDGE EXPANSION: ") != "ACKNOWLEDGE EXPANSION":
            print("No request created.")
            return
    if _ask("Type SUBMIT NEW REQUEST to persist one new request: ") != "SUBMIT NEW REQUEST":
        print("No request created.")
        return

    record = db.submit_assessment_request(
        ctx, tuple(assets), AssessmentMode.AUTHORIZED_ASSESSMENT,
        RiskLevel(payload["requested_risk"]), payload["notes"],
    )
    print("SUBMITTED (not approved). Independent operator review required.")
    print("New request ID: " + record.request_id)
    if previous_id:
        print("Original rejected request unchanged: " + previous_id)


def _revise(db: DomainStore, ctx) -> None:
    from .client_request_revision import prepare_rejected_revision

    old_id = _ask("Your rejected request ID: ", max_chars=128)
    original = db.get_assessment_request(ctx, old_id)
    print("Revision input: choose m for manually edited scope or s for Studio JSON.")
    origin = _ask("Choice [m/s]: ", max_chars=1).lower()
    if origin == "m":
        new = _manual_proposal()
    elif origin == "s":
        new = _studio_proposal()
    else:
        raise ClientRequestError("choose m or s")
    revised = prepare_rejected_revision(
        original, assets=new["requested_assets"], risk=new["requested_risk"],
        notes=new["notes"],
    )
    print("\n=== REJECTED REQUEST REVISION ===")
    print("Original request: " + original.request_id + " · status: REJECTED")
    print("Original record SHA-256 (unsigned): " + revised["previous_record_sha256"])
    print("Proposed revision SHA-256 (unsigned): " + revised["revision_sha256"])
    print("New/wider asset declarations: " + ", ".join(
        revised["newly_introduced_assets"]
    ) if revised["newly_introduced_assets"] else "No new asset declarations.")
    print("Removed/narrowed assets: " + ", ".join(
        revised["removed_or_narrowed_assets"]
    ) if revised["removed_or_narrowed_assets"] else "No removed assets.")
    print("Requested risk: " + str(revised["previous_risk"])
          + " → " + str(revised["requested_risk"]))
    _decision(
        db, ctx, payload=revised, previous_id=original.request_id,
        expanded=revised["scope_expansion_requires_confirmation"],
    )


def _history(db: DomainStore, ctx) -> None:
    records = db.list_assessment_requests(ctx)
    if not records:
        print("No stored client requests.")
        return
    print("\nMost recent 30 stored requests (not grants):")
    for row in records[:30]:
        print(row.request_id + " · " + row.status.value
              + " · risk " + str(int(row.requested_risk))
              + " · " + row.created_at)
    if len(records) > 30:
        print("Showing 30 of " + str(len(records)) + "; use an export for details.")


def _export(db: DomainStore, ctx) -> None:
    from .client_request_snapshot import MAX_EXPORT_RECORDS

    path = _ask("New private HTML destination (.html): ", max_chars=2048)
    if not path:
        raise ClientRequestError("private export destination is required")
    records = db.list_assessment_requests(ctx)
    if len(records) > MAX_EXPORT_RECORDS:
        print("More than 200 stored requests. Exporting the latest 200 only.")
    snapshot = render_request_snapshot(records[:MAX_EXPORT_RECORDS])
    save_private_snapshot(Path(path).expanduser(), snapshot)
    print("Saved private unsigned, potentially stale read-only snapshot: " + path)
    print("Never share outside the owning client or treat as authorization.")


def _show(db: DomainStore, ctx) -> None:
    import json

    request_id = _ask("Your existing request ID: ", max_chars=128)
    record = db.get_assessment_request(ctx, request_id)
    print(json.dumps(_record(record, include_assets=True), indent=2))
    print("A record is NOT an actionable authorization grant.")


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Authenticated client request desk (no grants/scans)"
    )
    parser.add_argument("--db", required=True, help="existing private LightUp SQLite database")
    parser.add_argument("--email", required=True, help="your real client login email")
    options = parser.parse_args(argv)
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("client desk requires a private interactive terminal", file=sys.stderr)
        return 2
    try:
        db = DomainStore(_existing_database(options.db))
        ctx = _client_account(db, options.email)
    except (ValueError, PermissionError, OSError) as exc:
        print("Client login refused: " + str(exc), file=sys.stderr)
        return 2

    print("\nLIGHTUP / CLIENT REQUEST DESK · PLAN/LAB ONLY · DRAFT/HOLD")
    print("Authenticated client requests only. No approvals, grants or execution.")
    choices = {
        "1": ("View own request inbox", lambda: _history(db, ctx)),
        "2": ("Prepare and submit a manual request", lambda: _decision(db, ctx, payload=_manual_proposal())),
        "3": ("Import Studio proposal and submit", lambda: _decision(db, ctx, payload=_studio_proposal())),
        "4": ("Revise a rejected request", lambda: _revise(db, ctx)),
        "5": ("Inspect one own request", lambda: _show(db, ctx)),
        "6": ("Export private read-only HTML timeline", lambda: _export(db, ctx)),
    }
    while True:
        print("\n" + " | ".join(key + ": " + label for key, (label, _) in choices.items()))
        print("0: Exit without additional changes")
        try:
            selection = _ask("Select an action: ", max_chars=1)
            if selection == "0":
                print("Client session closed.")
                return 0
            if selection not in choices:
                print("Unknown selection.")
                continue
            choices[selection][1]()
        except (EOFError, KeyboardInterrupt):
            print("\nClient session closed.")
            return 0
        except (ValueError, PermissionError, KeyError, OSError) as exc:
            print("Action refused: " + str(exc), file=sys.stderr)
            print("No authorization was conferred. Return to the menu.")


if __name__ == "__main__":
    raise SystemExit(main())
