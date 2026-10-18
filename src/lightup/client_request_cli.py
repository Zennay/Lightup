"""Authenticated client assessment-request inbox and explicit submission CLI.

This is request bookkeeping only: neither a submitted nor approved request is
authorization, consent to execute, or an active target grant. No network calls.
Depends on the persisted client-origin guards in domain.py (#1570).
"""
from __future__ import annotations

import argparse
import getpass
import hmac
import json
from pathlib import Path
import sys

from .domain import AccountLockedError, DomainStore, Role
from .engagements import AssessmentMode, RiskLevel
from .grant_request_binding import _asset

_MAX_ASSETS = 80
_MAX_NOTES = 4000


class ClientRequestError(ValueError):
    """A local request payload or account does not meet the admission contract."""


def canonical_assets(values: list[str]) -> tuple[str, ...]:
    """Check literal identities with the *same* parser used for grant binding.

    Never resolve DNS or expand CIDRs. Reject case aliases, duplicate entries
    and broad/invalid literals; an approval still requires independent review.
    """
    if type(values) is not list or not 1 <= len(values) <= _MAX_ASSETS:
        raise ClientRequestError("provide between 1 and 80 explicit asset literals")
    result: list[str] = []
    for value in values:
        if type(value) is not str:
            raise ClientRequestError("asset must be a literal string")
        try:
            kind, parsed = _asset(value)
        except (ValueError, TypeError) as exc:
            raise ClientRequestError(f"invalid asset literal: {exc}") from exc
        canonical = parsed if kind == "host" else (
            str(parsed.network_address) if "/" not in value else str(parsed)
        )
        if value != canonical:
            raise ClientRequestError("asset must use canonical lowercase DNS or IP/CIDR spelling")
        if value in result:
            raise ClientRequestError("duplicate asset literal")
        result.append(value)
    return tuple(result)


def prepare_request(assets: list[str], risk: int, notes: str) -> dict:
    if type(risk) is not int or not 1 <= risk <= 4:
        raise ClientRequestError("real-client requests need a risk integer from 1 to 4")
    if type(notes) is not str or len(notes) > _MAX_NOTES or "\x00" in notes:
        raise ClientRequestError("notes must contain at most 4000 characters and no NUL")
    return {
        "requested_assets": list(canonical_assets(assets)),
        "requested_mode": AssessmentMode.AUTHORIZED_ASSESSMENT.value,
        "requested_risk": risk,
        "notes": notes.strip(),
        "authorized": False,
        "consent_verified": False,
        "grant_issued": False,
        "scan_allowed": False,
        "dispatch_allowed": False,
        "release_allowed": False,
    }


def _existing_database(raw: str) -> Path:
    path = Path(raw).expanduser()
    if path.is_symlink() or not path.is_file():
        raise ClientRequestError("select an existing, non-symlink LightUp SQLite file")
    return path


def _client_account(db: DomainStore, email: str):
    if not sys.stdin.isatty():
        raise ClientRequestError("interactive terminal required: passwords are never CLI arguments")
    user = db.authenticate(email, getpass.getpass("LightUp client password: "))
    if user is None:
        raise ClientRequestError("invalid account or password")
    ctx = db.context_for_user(user.user_id)
    if ctx.role not in (Role.CLIENT_ADMIN, Role.CLIENT_MEMBER) or not ctx.client_id:
        raise ClientRequestError("only actual persisted client accounts can use this CLI")
    return ctx


def _record(record, *, include_assets: bool) -> dict:
    result = {
        "request_id": record.request_id,
        "status": record.status.value,
        "requested_mode": record.requested_mode.value,
        "requested_risk": int(record.requested_risk),
        "created_at": record.created_at,
        "decided_at": record.decided_at,
        "authorized": False,
        "grant_issued": False,
        "scan_allowed": False,
        "dispatch_allowed": False,
    }
    if include_assets:
        result["requested_assets"] = list(record.requested_assets)
        result["notes"] = record.notes
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Client assessment requests only; never executes assessments.")
    sub = parser.add_subparsers(dest="command", required=True)
    preview = sub.add_parser("preview", help="offline literal scope preview (no database access)")
    submit = sub.add_parser("submit", help="persist one request after client authentication")
    for command in (preview, submit):
        command.add_argument("--asset", action="append", help="canonical hostname, IP or CIDR; repeat")
        command.add_argument("--proposal", help="existing offline Scope Planning Studio v1 JSON export")
        command.add_argument("--risk", type=int, choices=(1, 2, 3, 4))
        command.add_argument("--notes", help="request explanation; never use secrets")
    submit.add_argument("--confirm-submit", action="store_true", help="explicitly submit for operator review")
    submit.add_argument("--expect-proposal-sha256", help="exact untrusted proposal file SHA-256 from preview")
    # A rejected request stays immutable: any edit creates an independently
    # reviewable new request, never changes an operator decision or a grant.
    for name in ("revise-preview", "revise-submit"):
        command = sub.add_parser(name, help="propose a new request from a rejected original")
        command.add_argument("--request-id", required=True, help="existing own rejected request")
        command.add_argument("--asset", action="append", help="replacement canonical in-scope asset; repeat")
        command.add_argument("--risk", type=int, choices=(1, 2, 3, 4), help="replacement risk")
        command.add_argument("--notes", help="replacement client notes")
        if name == "revise-submit":
            command.add_argument("--expect-original-sha256", required=True,
                                 help="exact prior-review snapshot hash from revise-preview")
            command.add_argument("--confirm-new-request", action="store_true",
                                 help="create a NEW submitted request, leave original rejected")
            command.add_argument("--confirm-scope-expansion", action="store_true",
                                 help="explicitly acknowledge widened assets or higher risk")
    for name in ("list", "show", "export"):
        command = sub.add_parser(name, help="read own stored requests")
        if name == "show":
            command.add_argument("--request-id", required=True)
        if name == "export":
            command.add_argument("--output", required=True, help="new private local .html file, never overwritten")
    for command in (submit, sub.choices["list"], sub.choices["show"], sub.choices["export"],
                    sub.choices["revise-preview"], sub.choices["revise-submit"]):
        command.add_argument("--db", required=True, help="existing private LightUp SQLite database")
        command.add_argument("--email", required=True, help="persisted client account email")
    args = parser.parse_args(argv)
    try:
        if args.command in ("preview", "submit"):
            if bool(args.asset) == bool(args.proposal):
                raise ClientRequestError("choose exactly one source: --asset or --proposal")
            if args.proposal:
                if args.risk is not None or args.notes is not None:
                    raise ClientRequestError("--risk and --notes cannot override a reviewed studio proposal")
                from .client_proposal_intake import load_studio_proposal

                payload = load_studio_proposal(args.proposal)
                if args.command == "submit":
                    expected = args.expect_proposal_sha256
                    if (type(expected) is not str or len(expected) != 64
                            or any(ch not in "0123456789abcdef" for ch in expected)
                            or not hmac.compare_digest(expected, payload["proposal_file_sha256"])):
                        raise ClientRequestError(
                            "proposal changed or exact --expect-proposal-sha256 is missing; "
                            "review the file again with preview before submitting"
                        )
            else:
                if args.command == "submit" and args.expect_proposal_sha256 is not None:
                    raise ClientRequestError("--expect-proposal-sha256 requires --proposal")
                if args.risk is None:
                    raise ClientRequestError("--risk is required with --asset")
                payload = prepare_request(args.asset, args.risk, args.notes or "")
        if args.command == "preview":
            output = payload
        else:
            if args.command == "submit" and not args.confirm_submit:
                raise ClientRequestError("no request created; pass --confirm-submit to persist")
            if args.command == "revise-submit" and not args.confirm_new_request:
                raise ClientRequestError("no request created; pass --confirm-new-request")
            db = DomainStore(_existing_database(args.db))
            ctx = _client_account(db, args.email)
            if args.command in ("revise-preview", "revise-submit"):
                from .client_request_revision import prepare_rejected_revision

                original = db.get_assessment_request(ctx, args.request_id)
                revision = prepare_rejected_revision(
                    original, assets=args.asset, risk=args.risk, notes=args.notes
                )
                if args.command == "revise-preview":
                    output = revision
                else:
                    expected = args.expect_original_sha256
                    if (type(expected) is not str or len(expected) != 64
                            or any(c not in "0123456789abcdef" for c in expected)
                            or not hmac.compare_digest(expected, revision["previous_record_sha256"])):
                        raise ClientRequestError(
                            "rejected source request changed or its expected hash is wrong; "
                            "use revise-preview again"
                        )
                    if (revision["scope_expansion_requires_confirmation"]
                            and not args.confirm_scope_expansion):
                        raise ClientRequestError(
                            "wider asset range or risk; pass --confirm-scope-expansion after review"
                        )
                    record = db.submit_assessment_request(
                        ctx,
                        tuple(revision["requested_assets"]),
                        AssessmentMode.AUTHORIZED_ASSESSMENT,
                        RiskLevel(revision["requested_risk"]),
                        revision["notes"],
                    )
                    output = _record(record, include_assets=True)
                    output.update({
                        "previous_rejected_request_id": original.request_id,
                        "previous_request_modified": False,
                        "new_operator_decision_required": True,
                        "scope_expansion_confirmed": bool(
                            revision["scope_expansion_requires_confirmation"]
                            and args.confirm_scope_expansion
                        ),
                        "message": "NEW request submitted for independent review; old rejection intact",
                    })
            elif args.command == "submit":
                record = db.submit_assessment_request(
                    ctx,
                    tuple(payload["requested_assets"]),
                    AssessmentMode.AUTHORIZED_ASSESSMENT,
                    RiskLevel(payload["requested_risk"]),
                    payload["notes"],
                )
                output = _record(record, include_assets=True)
                output["message"] = "SUBMITTED for independent operator review; NOT consent or a grant"
            elif args.command == "show":
                output = _record(db.get_assessment_request(ctx, args.request_id), include_assets=True)
            elif args.command == "export":
                from .client_request_snapshot import render_request_snapshot, save_private_snapshot

                records = db.list_assessment_requests(ctx)
                snapshot = render_request_snapshot(records)
                save_private_snapshot(Path(args.output), snapshot)
                output = {"saved": str(Path(args.output)), "records": len(records),
                          "authorized": False, "grant_issued": False, "scan_allowed": False,
                          "warning": "Private unsigned and possibly stale client-only snapshot"}
            else:
                records = db.list_assessment_requests(ctx)
                output = [_record(record, include_assets=False) for record in records[:100]]
        print(json.dumps(output, indent=2, ensure_ascii=True))
        return 0
    except (ClientRequestError, AccountLockedError, PermissionError, ValueError, KeyError, OSError) as exc:
        print(f"request refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
