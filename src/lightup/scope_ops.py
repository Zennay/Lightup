"""Interactive original-domain scope casework with explicit, authenticated deny-only STOP.

READS: original owner Casebook and STOP grant exposure sources. WRITES: only
the existing original immutable authenticated STOP event operation, guarded
by fresh persisted identity/tenant checks. No scan, grant or resumption path.
This is a held INCUBATE product candidate, NOT wired to production dispatch.
"""
from __future__ import annotations

import argparse
from getpass import getpass
import json
import sys
from pathlib import Path

from .auth_casebook import CasebookHold, _auth_actor, _source_snapshot
from .revocation_stop import StopLedgerError, record_authenticated_stop
from .stop_exposure import _read_exposure
from .request_binding_readiness_cli import (
    _assets as canonical_request_assets,
    _source_snapshot as original_request_binding_source,
)


def _short(value: object, maximum: int = 180) -> str:
    if type(value) is not str or not 0 < len(value) <= maximum:
        raise CasebookHold("invalid persisted case identity")
    if any(ord(ch) < 33 or ord(ch) == 127 for ch in value):
        raise CasebookHold("unsafe persisted case identity")
    return value


def _load(database: str, user_id: str, client_id: str | None) -> dict:
    """Retrospective original read-only source, never consent or access token."""
    report = _source_snapshot(database, actor_id=user_id, client_id=client_id)
    if (report.get("schema") != "lightup.auth_casebook.v1"
            or report.get("authorization_granted") is not False
            or report.get("execution_allowed") is not False
            or report.get("release_approved") is not False):
        raise CasebookHold("original source is not a held report")
    return report


def _case(report: dict, engagement_id: str) -> dict:
    eid = _short(engagement_id)
    for row in report["case_overview"]:
        if row["engagement_id"] == eid:
            return row
    raise CasebookHold("engagement not part of the selected tenant")


def _list_cases(source: dict) -> None:
    def rank(row: dict) -> int:
        if row["attention"].startswith("HOLD_"):
            return 0
        if row["attention"] == "RISK_DECISION_PENDING_SOURCE_REVIEW":
            return 1
        return 2

    cases = sorted(source["case_overview"], key=rank)
    print("\nORIGINAL SOURCE REVIEW / NOT PERMISSION")
    for row in cases[:50]:
        print(f'  {_short(row["engagement_id"])} '
              f'[{_short(row["attention"])}] '
              f'grants={row["grant_count"]} risks={row["risk_record_count"]}')
    if len(cases) > 50:
        print(f"  + {len(cases)-50} original cases; enter exact engagement ID to inspect")
    print("No original risk/request/grant state is treated as consent.\n")


def _detail(database: str, user_id: str, client_id: str | None, eid: str) -> None:
    # Re-read original tenant membership immediately before showing private detail.
    source = _load(database, user_id, client_id)
    case = _case(source, eid)
    matches = [g for g in source["grants"] if g["engagement_id"] == eid]
    request_ids = {g["approved_request_id"] for g in matches if g["approved_request_id"] is not None}
    matching_requests = [r for r in source["requests"] if r["request_id"] in request_ids]
    risks = [r for r in source["risk_approvals"] if r["engagement_id"] == eid]
    # The existing read-only original owner guard rechecks current persisted
    # tenant and account. A missing ledger or altered source means HOLD.
    try:
        stop = _read_exposure(database, actor_id=user_id, engagement_id=eid)
        stop_state = ("STOP_RECORDED" if stop["stop_active"]
                      else "NO_STOP_RECORDED_NOT_AUTHORITY")
        if (stop["persisted_grant_count"] != len(matches)
                or stop["request_linked_grant_count"] != sum(g["approved_request_id"] is not None for g in matches)
                or stop["legacy_unbound_grant_count"] != sum(g["approved_request_id"] is None for g in matches)):
            stop_state = "HOLD_CROSS_SOURCE_GRANT_DRIFT"
    except (StopLedgerError, KeyError, TypeError, ValueError):
        stop_state = "HOLD_ORIGINAL_STOP_SOURCE"

    detail = {
        "status": "REVIEW_ONLY_OR_HOLD",
        "source_snapshots_atomic_together": False,
        "engagement_id": eid,
        "case": case,
        "stop_source": stop_state,
        "linked_requests": matching_requests,
        "persisted_grants": matches,
        "risk_decisions": risks,
        "client_consent_verified": False,
        "operator_consent_verified": False,
        "authorization_granted": False,
        "execution_allowed": False,
        "release_approved": False,
    }
    print(json.dumps(detail, sort_keys=True, indent=2))


def _shortlist(db: str, actor: str, source: dict, engagement: str) -> None:
    """Original source-owner administrative shortlist, never a grant."""
    print("Private request-binding preview; no asset is contacted or authorized.")
    proposed = input("Exact canonical asset literal(s), comma-separated: ").strip()
    risk_literal = input("Proposed risk 1-4: ").strip()
    try:
        if risk_literal not in ("1", "2", "3", "4"):
            raise ValueError("proposed risk must be a canonical integer")
        if not proposed or len(proposed) > 8192:
            raise ValueError("bounded canonical literal proposal required")
        # The ORIGINAL source-owner request-bound predicate remains the sole
        # matching criterion. This local menu never creates real credentials,
        # consent, a grant or authority from a candidate label.
        assets = canonical_request_assets(proposed.split(","))
        report = original_request_binding_source(
            Path(db), engagement_id=engagement, client_id=source["client_id"],
            assets=assets, risk=int(risk_literal),
            include_request_ids=False, include_labels=False,
            include_assets=False, operator_user_id=actor,
        )
        authority = report.get("authority")
        if (report.get("format") != "lightup.request_binding_preparation.v1"
                or report.get("disposition") not in (
                    "REVIEW_ONLY_SINGLE_CANDIDATE",
                    "HOLD_AMBIGUOUS_CANDIDATES",
                    "HOLD_NO_CANDIDATE",
                )
                or type(authority) is not dict
                or any(value is not False for value in authority.values())
                or not {"client_consent_verified","operator_consent_verified",
                        "authorization_granted","execution_allowed",
                        "release_approved"}.issubset(authority)):
            raise ValueError("source-owner read not admitted")
        summary = report["summary"]
        print(json.dumps({
            "status": report["disposition"],
            "summary": {
                "recorded_requests": summary["recorded_requests"],
                "approved_candidate_matches": summary["approved_candidate_matches"],
                "approved_but_not_compatible": summary["approved_but_not_compatible"],
                "unbound_legacy_grant_rows": summary["unbound_legacy_grant_rows"],
                "mismatch_reason_counts_non_authorizing": summary["mismatch_reason_counts_non_authorizing"],
            },
            "client_consent_verified": False,
            "operator_consent_verified": False,
            "authorization_granted": False,
            "execution_allowed": False,
            "release_approved": False,
        }, sort_keys=True, indent=2))
        print("Administrative shortlist is NOT independent consent, a stored grant, or a runtime permit.")
    except (ValueError, TypeError, KeyError, PermissionError, OSError, OverflowError):
        print("HOLD: original persisted operator, proposal or request-source integrity refused.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m lightup.scope_ops",
        description="Authenticated local original Casebook + deny-only emergency STOP desk.",
    )
    parser.add_argument("--database", required=True, help="existing local LightUp DomainStore SQLite")
    parser.add_argument("--email", required=True, help="existing LightUp operator or client login")
    parser.add_argument("--client", help="operator: exact existing tenant ID; clients: own tenant only")
    args = parser.parse_args(argv)
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("HOLD: private operator console requires a foreground interactive terminal")
        return 3
    try:
        password = getpass("Existing LightUp account password: ")
        actor = _auth_actor(args.database, args.email, password)
        print("PRIVATE LOCAL SOURCE. REVIEW_ONLY. The STOP event is deny-only; no runner is stopped by this console itself.")
        while True:
            source = _load(args.database, actor, args.client)
            _list_cases(source)
            print("Choose: [I]nspect, [B]inding candidate shortlist, [S]TOP, [R]efresh, [Q]uit")
            choice = input("Action: ").strip().lower()
            if choice in ("q", "quit"):
                print("Review closed; authorization_granted=false")
                return 2
            if choice in ("r", "refresh"):
                continue
            if choice not in ("i", "inspect", "s", "stop", "b", "binding"):
                print("Unknown action; no mutation")
                continue
            eid = input("Exact existing engagement ID: ").strip()
            row = _case(source, eid)
            if choice in ("i", "inspect"):
                _detail(args.database, actor, args.client, eid)
                continue
            if choice in ("b", "binding"):
                _shortlist(args.database, actor, source, eid)
                continue

            # Existing original DomainStore/STOP source still revalidates the
            # actor's credentials, role and tenant at the actual database write.
            # A stale preview cannot mint a write capability.
            print(f'Intent: permanently record a deny-only STOP for {eid}.')
            print(f'Original case: {row["attention"]}. This does not halt already running tasks or approve future execution.')
            typed = input(f"Type exactly STOP {eid} to confirm: ").strip()
            if typed != f"STOP {eid}":
                print("Cancelled without a STOP write")
                continue
            print("Recording original authenticated STOP; no grant or target work")
            try:
                result = record_authenticated_stop(
                    args.database, engagement_id=eid, email=args.email,
                    password=password, reason="scope incident desk explicit operator STOP",
                )
                if result.get("status") != "STOP_RECORDED" or result.get("authorization_granted") is not False:
                    raise StopLedgerError("original STOP response not admitted")
                print("STOP_RECORDED. This is NOT runtime kill confirmation or authorization.")
            except StopLedgerError:
                print("HOLD: original authenticated STOP was not recorded; verify original account and ledger before retry")
                return 3
    except (CasebookHold, StopLedgerError, EOFError, KeyboardInterrupt, ValueError, TypeError):
        print("HOLD: original account, source or operator console unavailable; no authority issued")
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
