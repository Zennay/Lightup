"""Private, authenticated scope + STOP casework briefing (never a permit).

Composes the ORIGINAL held casebook and authenticated STOP sources without
changing their policy, execution, consent or write paths. Each read is a
separate bounded retrospective SQLite snapshot, NOT an action-time gate.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
from getpass import getpass
import json
import sqlite3
from pathlib import Path

from .auth_casebook import CasebookHold, _auth_actor, _source_snapshot, _write_private_json
from .revocation_stop import StopLedgerError
from .stop_exposure import _read_exposure
from .request_binding_readiness_cli import (
    _assets as original_canonical_assets,
    _source_snapshot as original_request_selection,
)

MAX_SELECTION = 32
NO_AUTHORITY = {
    "source_authenticated": False,
    "client_consent_verified": False,
    "operator_consent_verified": False,
    "authorization_granted": False,
    "execution_allowed": False,
    "release_approved": False,
    "action_time_revocation_verified": False,
}


class ScopeBriefHold(ValueError):
    """No positive action is available from this advisory workspace."""


def compose_scope_incident_brief(
    database: str, *, email: str, password: str,
    client_id: str | None = None, engagement_ids: tuple[str, ...] = (),
    proposal_engagement: str | None = None, proposal_assets: tuple[str, ...] = (),
    proposal_risk: int | None = None,
) -> dict:
    """Read original authenticated casebook, then per-engagement STOP exposure.

    A STOP observation never permits execution, even if no STOP was recorded.
    Original STOP/source data may change between reads: deliberately disclose
    that this is NOT an atomic dispatch-time revocation observation.
    """
    if type(engagement_ids) is not tuple or len(engagement_ids) > MAX_SELECTION:
        raise ScopeBriefHold("invalid or excessive engagement selection")
    if any(type(value) is not str for value in engagement_ids):
        raise ScopeBriefHold("engagement identity must be literal text")
    if len(set(engagement_ids)) != len(engagement_ids):
        raise ScopeBriefHold("duplicate engagement selection")
    if ((proposal_engagement is None) != (proposal_risk is None)
            or (proposal_engagement is None) != (not proposal_assets)):
        raise ScopeBriefHold("proposal requires exact engagement, literals and risk")
    if proposal_engagement is not None:
        if type(proposal_risk) is not int or proposal_risk not in (1, 2, 3, 4):
            raise ScopeBriefHold("proposed risk must be original canonical range")
        if type(proposal_assets) is not tuple or len(proposal_assets) > 80:
            raise ScopeBriefHold("noncanonical proposed literal collection")
        try:
            original_canonical_assets(list(proposal_assets))
        except (ValueError, TypeError):
            raise ScopeBriefHold("invalid canonical proposed literals") from None
    actor_id = _auth_actor(database, email, password)
    source = _source_snapshot(database, actor_id=actor_id, client_id=client_id)
    original_cases = source["case_overview"]
    original_index = {row["engagement_id"]: row for row in original_cases}
    selected = engagement_ids or tuple(original_index)
    if not selected or len(selected) > MAX_SELECTION:
        raise ScopeBriefHold("select one to thirty-two original engagements")
    if any(eid not in original_index for eid in selected):
        raise ScopeBriefHold("engagement absent from selected original tenant")
    if proposal_engagement is not None and proposal_engagement not in selected:
        raise ScopeBriefHold("proposed engagement absent from selected original cases")

    readings = []
    for eid in selected:
        case = original_index[eid]
        try:
            exposure = _read_exposure(database, actor_id=actor_id, engagement_id=eid)
            if (
                exposure.get("schema") != "lightup.stop_grant_exposure.v1"
                or exposure.get("authorization_granted") is not False
                or exposure.get("execution_allowed") is not False
                or exposure.get("release_approved") is not False
                or type(exposure.get("stop_active")) is not bool
                or type(exposure.get("persisted_grant_count")) is not int
                or exposure["persisted_grant_count"] != case["grant_count"]
            ):
                raise StopLedgerError("cross-source grant revision disagreement")
            state = "STOP_ACTIVE" if exposure["stop_active"] else "NO_STOP_RECORDED_NOT_PERMISSION"
            count = exposure["persisted_grant_count"]
            linked = exposure["request_linked_grant_count"]
            unbound = exposure["legacy_unbound_grant_count"]
            warning = exposure["human_attention"]
            # A changed binding can preserve the total number of grants.
            # Verify the independent original casebook request-link classes,
            # not just the source count before reporting a reviewed row.
            source_grants = [g for g in source["grants"] if g["engagement_id"] == eid]
            source_linked = sum(g["approved_request_id"] is not None for g in source_grants)
            source_unbound = len(source_grants) - source_linked
            if (linked != source_linked or unbound != source_unbound
                    or len(source_grants) != case["grant_count"]):
                raise StopLedgerError("cross-source request binding drift")
            if type(linked) is not int or type(unbound) is not int or linked + unbound != count:
                raise StopLedgerError("stored grant source inconsistent")
        except (StopLedgerError, KeyError, TypeError, ValueError):
            state = "HOLD_STOP_SOURCE_UNAVAILABLE_OR_CHANGED"
            count = linked = unbound = None
            warning = "RECHECK_ORIGINAL_SOURCE_PRIVATELY"
        readings.append({
            "engagement_id": eid,
            "original_engagement_status": case["status"],
            "casebook_attention": case["attention"],
            "casebook_next_human_action": case["next_review_action"],
            "stop_observation": state,
            "grant_source_count": count,
            "request_linked_grant_count": linked,
            "legacy_unbound_grant_count": unbound,
            "stop_source_notice": warning,
            "authority": False,
        })

    binding_review = None
    if proposal_engagement is not None:
        # The original source-owner routine itself rechecks persisted operator
        # role and single-tenant membership in a separate readonly transaction.
        # Never reproduce its approval predicate here or infer permission.
        try:
            original = original_request_selection(
                Path(database), engagement_id=proposal_engagement,
                client_id=source["client_id"],
                assets=original_canonical_assets(list(proposal_assets)),
                risk=proposal_risk, include_request_ids=False,
                include_labels=False, include_assets=False,
                operator_user_id=actor_id,
            )
            flags = original.get("authority")
            counts = original["summary"]
            accepted_states = (
                "REVIEW_ONLY_SINGLE_CANDIDATE",
                "HOLD_AMBIGUOUS_CANDIDATES",
                "HOLD_NO_CANDIDATE",
            )
            if (original.get("format") != "lightup.request_binding_preparation.v1"
                    or original.get("disposition") not in accepted_states
                    or type(flags) is not dict
                    or not {"client_consent_verified","operator_consent_verified",
                            "authorization_granted","execution_allowed",
                            "release_approved"}.issubset(flags)
                    or any(v is not False for v in flags.values())
                    or type(counts["recorded_requests"]) is not int
                    or type(counts["approved_candidate_matches"]) is not int
                    or type(counts["prior_stored_grant_rows"]) is not int
                    or type(original["candidates"]) is not list
                    or len(original["candidates"]) != counts["recorded_requests"]
                    or len(original["candidates"]) > 100):
                raise ScopeBriefHold("unbounded or inconsistent original matching source")
            exposure = next(r for r in readings if r["engagement_id"] == proposal_engagement)
            if (exposure["grant_source_count"] is None
                    or exposure["grant_source_count"] != counts["prior_stored_grant_rows"]):
                raise ScopeBriefHold("original request/STOP grant lineage changed")
            reason_counts = counts["mismatch_reason_counts_non_authorizing"]
            if (type(reason_counts) is not dict
                    or len(reason_counts) > 40
                    or any(type(k) is not str or len(k) > 100 or type(v) is not int
                           or v < 0 for k,v in reason_counts.items())):
                raise ScopeBriefHold("invalid original human mismatch reasons")
            # The original report does not include original request or target IDs
            # unless explicitly requested. Export only its human-only counters.
            binding_review = {
                "status": original["disposition"],
                "engagement_id": proposal_engagement,
                "proposed_asset_count": len(proposal_assets),
                "proposed_risk": proposal_risk,
                "stored_request_count": counts["recorded_requests"],
                "matching_request_count": counts["approved_candidate_matches"],
                "stored_grant_count": counts["prior_stored_grant_rows"],
                "historical_legacy_unbound_count": counts["unbound_legacy_grant_rows"],
                "source_revision_sha256_unsigned": original["source"]["source_revision_sha256_unsigned"],
                "selection_digest_unsigned": original["source"]["request_selection_digest_unsigned"],
                "non_authorizing_mismatch_reasons": reason_counts,
                "source_snapshots_atomic_together": False,
                "authority": False,
            }
        except (ScopeBriefHold, ValueError, KeyError, TypeError, StopIteration,
                PermissionError, sqlite3.Error, OSError, OverflowError):
            # A failed authenticated source-owner snapshot cannot supply even
            # a retrospective candidate match. Keep private casework in HOLD.
            binding_review = {
                "status": "HOLD_BINDING_SOURCE_UNAVAILABLE_OR_CHANGED",
                "engagement_id": proposal_engagement,
                "source_snapshots_atomic_together": False,
                "authority": False,
            }
    states = Counter(r["stop_observation"] for r in readings)
    critical = sum(
        r["stop_observation"].startswith("HOLD_")
        or r["stop_observation"] == "STOP_ACTIVE"
        or r["casebook_attention"].startswith(("HOLD_", "RISK_DECISION_PENDING_"))
        for r in readings
    )
    has_hold = (binding_review is not None and binding_review["status"].startswith("HOLD_")) or critical > 0 or (
        source["declared_counts"]["grant_link_hold"] > 0
        or source["declared_counts"]["foreign_tenant_row_count"] > 0
        or source["declared_counts"]["risk_provenance_hold"] > 0
    )
    return {
        "schema": "lightup.scope_stop_casework_brief.v1",
        "status": "HOLD" if has_hold else "REVIEW_ONLY",
        "source": "original_domain_casebook_and_separately_sampled_stop_exposure",
        "source_snapshots_atomic_together": False,
        "snapshot_at": datetime.now(timezone.utc).isoformat(),
        "client_id": source["client_id"],
        "selected_engagements_only": bool(engagement_ids),
        "selected_count": len(readings),
        "casebook": source,
        "binding_review": binding_review,
        "engagements": readings,
        "summary": {
            "selected": len(readings),
            "active_stop_observations": states["STOP_ACTIVE"],
            "no_stop_recorded_not_authority": states["NO_STOP_RECORDED_NOT_PERMISSION"],
            "stop_source_hold": states["HOLD_STOP_SOURCE_UNAVAILABLE_OR_CHANGED"],
            "cases_requiring_human_attention": critical,
            "original_requests": source["declared_counts"]["requests"],
            "original_grants": source["declared_counts"]["grants"],
            "risk_provenance_hold": source["declared_counts"]["risk_provenance_hold"],
            "pending_risk_review": source["declared_counts"]["pending_risk_review"],
        },
        **NO_AUTHORITY,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m lightup.scope_incident_brief",
        description="Private original-domain scope + STOP retrospective workroom; no permissions.",
    )
    parser.add_argument("--database", required=True, help="existing local domain SQLite")
    parser.add_argument("--email", required=True, help="existing LightUp client/operator")
    parser.add_argument("--client", help="exact persisted tenant ID required for operators")
    parser.add_argument("--engagement", action="append", default=[], help="exact selected original engagement; up to 32")
    parser.add_argument("--output", help="optional NEW private owner-only JSON (0600)")
    parser.add_argument("--proposal-engagement", help="existing exact selected engagement for non-authorizing original approved-request shortlist")
    parser.add_argument("--proposed-asset", action="append", default=[], help="canonical proposed literal; never touched or scanned")
    parser.add_argument("--proposed-risk", type=int, help="proposed risk 1-4; original administrative request comparison only")
    args = parser.parse_args(argv)
    try:
        result = compose_scope_incident_brief(
            args.database, email=args.email, password=getpass("Original LightUp password: "),
            client_id=args.client, engagement_ids=tuple(args.engagement),
            proposal_engagement=args.proposal_engagement,
            proposal_assets=tuple(args.proposed_asset),
            proposal_risk=args.proposed_risk,
        )
        if args.output:
            _write_private_json(args.output, result)
        print(json.dumps({
            "schema": result["schema"],
            "status": result["status"],
            "summary": result["summary"],
            "binding_review_status": result["binding_review"]["status"] if result["binding_review"] else "NOT_REQUESTED",
            "private_output_created": bool(args.output),
            "source_snapshots_atomic_together": False,
            **NO_AUTHORITY,
        }, sort_keys=True))
        return 3 if result["status"] == "HOLD" else 2
    except (ScopeBriefHold, CasebookHold, StopLedgerError, KeyboardInterrupt, EOFError):
        print(json.dumps({"status": "HOLD", **NO_AUTHORITY}, sort_keys=True))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
