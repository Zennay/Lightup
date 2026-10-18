"""Original request-binding alternative previews inside held incident casework.

Read-only, original owner-evaluator, one source transaction for 2-8
alternatives. No grant, consent, target activity or release capability.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path

from .request_binding_scenarios import read_scenarios, compare_scenarios


class ScenarioHold(ValueError):
    """Refuse conflicting original persisted review source."""


def source_bound_scenarios(
    database: str, *, actor_id: str, client_id: str, engagement_id: str,
    original_requests: list[dict], original_grant_count: int,
    scenario_file: str,
) -> dict:
    # This is a human-supplied proposal file, NOT a trusted authorization
    # manifest. The original owner parses its exact canonical literals.
    scenarios = read_scenarios(Path(scenario_file))
    report = compare_scenarios(
        Path(database), engagement_id=engagement_id, client_id=client_id,
        operator_user_id=actor_id,
        include_request_ids=True, include_labels=False, include_assets=False,
        scenarios=scenarios,
    )
    if (type(report) is not dict
            or report.get("format") != "lightup.request_binding_scenarios_review.v1"
            or report.get("disposition") != "REVIEW_ONLY_SCENARIOS"
            or type(report.get("authority")) is not dict
            or not {"client_consent_verified","operator_consent_verified",
                    "authorization_granted","execution_allowed",
                    "release_approved"}.issubset(report["authority"])
            or any(value is not False for value in report["authority"].values())
            or type(report.get("scenarios")) is not list
            or len(report["scenarios"]) != len(scenarios)
            or not 2 <= len(scenarios) <= 8):
        raise ScenarioHold("original source scenario envelope rejected")
    earlier = {
        row["request_id"]: (row["status"], row["requested_risk"])
        for row in original_requests
    }
    if len(earlier) != len(original_requests):
        raise ScenarioHold("duplicate original request identity")
    alternatives = []
    revision = report["source_revision_sha256_unsigned"]
    if type(revision) is not str or len(revision) != 64:
        raise ScenarioHold("original source revision missing")
    for (label, assets, risk), candidate in zip(scenarios, report["scenarios"]):
        if (type(candidate) is not dict or candidate.get("label") != label):
            raise ScenarioHold("original alternative identity changed")
        source = candidate["original_source"]
        authority = source.get("authority")
        summary = source["summary"]
        if (type(authority) is not dict
                or any(value is not False for value in authority.values())
                or source["source"]["source_revision_sha256_unsigned"] != revision
                or source.get("format") != "lightup.request_binding_preparation.v1"
                or source.get("disposition") not in (
                    "REVIEW_ONLY_SINGLE_CANDIDATE",
                    "HOLD_NO_CANDIDATE", "HOLD_AMBIGUOUS_CANDIDATES",
                )
                or source["source"]["proposed_asset_count"] != len(assets)
                or source["source"]["requested_risk"] != risk
                or summary["prior_stored_grant_rows"] != original_grant_count):
            raise ScenarioHold("original request/grant lineage changed")
        items = source["candidates"]
        later = {
            row["request_id"]: (row["stored_status"], row["requested_risk"])
            for row in items
            if type(row) is dict and type(row.get("request_id")) is str
        }
        if (type(items) is not list or len(items) > 100
                or len(later) != len(items) or later != earlier
                or summary["recorded_requests"] != len(items)):
            raise ScenarioHold("original request decisions changed between source reads")
        matches = summary["approved_candidate_matches"]
        if (type(matches) is not int or not 0 <= matches <= len(items)
                or (matches == 1) != (
                    source["disposition"] == "REVIEW_ONLY_SINGLE_CANDIDATE"
                )):
            raise ScenarioHold("original request shortlist inconsistent")
        alternatives.append({
            "label": label, "proposed_risk": risk,
            "proposed_asset_count": len(assets),
            "original_stored_request_count": len(items),
            "matching_request_count": matches,
            "status": source["disposition"],
            "authority": False,
        })
    transitions = []
    for item in report["adjacent_alternative_changes"]:
        if (type(item) is not dict
                or any(type(item.get(k)) is not int or item[k] < 0
                       for k in ("still_potential", "no_longer_matched_not_revoked",
                                 "newly_matched_not_authorized"))):
            raise ScenarioHold("original candidate overlap counts malformed")
        transitions.append({
            "from_scenario": item["from_scenario"],
            "to_scenario": item["to_scenario"],
            "still_potential": item["still_potential"],
            "no_longer_matched_not_revoked": item["no_longer_matched_not_revoked"],
            "newly_matched_not_authorized": item["newly_matched_not_authorized"],
        })
    if len(transitions) != len(alternatives) - 1:
        raise ScenarioHold("original alternative sequence inconsistent")
    # Hash solely gives local proposal equality for historical review. NOT a
    # signature, consent, revocation epoch or original source authentication.
    marker = json.dumps(
        [[label, list(assets), risk] for label, assets, risk in scenarios],
        ensure_ascii=True, sort_keys=True, separators=(",", ":"),
    ).encode("ascii")
    return {
        "status": "HOLD_SCENARIOS_REQUIRE_HUMAN_SELECTION",
        "engagement_id": engagement_id,
        "source_revision_sha256_unsigned": revision,
        "scenario_selection_sha256_unsigned": sha256(marker).hexdigest(),
        "scenario_count": len(alternatives),
        "alternatives": alternatives,
        "adjacent_changes": transitions,
        "source_snapshots_atomic_together": False,
        "authority": False,
    }
