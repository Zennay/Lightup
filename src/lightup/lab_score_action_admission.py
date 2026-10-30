"""Strict, schema-closed admission of anonymous HUMAN action inventories.

No identity, consent, grants, or source provenance can be established here.
The caller must separately re-admit both original synthetic transports.
"""
from __future__ import annotations

_FIELDS = frozenset({
    "schema", "review_status", "unsigned_transport_sha256", "hold_action_rows",
    "human_review_only", "original_source_authenticated", "same_originals_proven",
    "authorization_granted", "remediation_verified", "deployment", "actions",
})
_ROW_FIELDS = frozenset({
    "transport", "anonymous_previous", "anonymous_current", "reason",
    "human_action", "completion", "authorization_granted", "remediation_verified",
})
_REASONS = {
    "evidence_reused": "RECAPTURE_INDEPENDENT_SYNTHETIC_ORIGINALS",
    "score_drift": "REVIEW_ISOLATED_SYNTHETIC_SCORER_DRIFT",
}


def admit_human_actions(data: dict) -> list[dict]:
    """Fail closed before any JSON, CSV, HTML, or HUMAN brief is rendered."""
    if type(data) is not dict or data.keys() != _FIELDS:
        raise ValueError("untrusted HUMAN action envelope")
    rows = data["actions"]
    receipts = data["unsigned_transport_sha256"]
    if (
        data["schema"] != "lightup.lab-score-human-two-transport-actions.v1"
        or data["review_status"] not in ("PASS", "HOLD")
        or type(rows) is not list or not 1 <= len(rows) <= 113
        or type(data["hold_action_rows"]) is not int
        or data["hold_action_rows"] != len(rows) - 1
        or data["human_review_only"] is not True
        or any(data[k] is not False for k in (
            "original_source_authenticated", "same_originals_proven",
            "authorization_granted", "remediation_verified", "deployment"
        ))
        or type(receipts) is not dict
        or receipts.keys() != {"baseline", "candidate"}
        or any(
            type(digest) is not str or len(digest) != 64
            or any(ch not in "0123456789abcdef" for ch in digest)
            for digest in receipts.values()
        )
        or (data["review_status"] == "PASS" and len(rows) != 1)
    ):
        raise ValueError("untrusted original HUMAN action inventory")

    seen = set()
    prior_origin = 0
    prior_pair = {"baseline": (0, 0), "candidate": (0, 0)}
    for row in rows[:-1]:
        if type(row) is not dict or row.keys() != _ROW_FIELDS:
            raise ValueError("untrusted HUMAN action row fields")
        origin = row["transport"]
        reason = row["reason"]
        p, c = row["anonymous_previous"], row["anonymous_current"]
        if (
            origin not in ("baseline", "candidate")
            or reason not in _REASONS
            or type(p) is not int or type(c) is not int
            or not 1 <= p < c <= 8
            or row["human_action"] != _REASONS[reason]
            or row["completion"] != "NOT_VERIFIED"
            or row["authorization_granted"] is not False
            or row["remediation_verified"] is not False
        ):
            raise ValueError("untrusted anonymous original HOLD action")
        current_origin = 0 if origin == "baseline" else 1
        key = (origin, p, c, reason)
        if (current_origin < prior_origin
                or (p, c) < prior_pair[origin] or key in seen):
            raise ValueError("reordered or duplicated original HOLD action")
        prior_origin = current_origin
        prior_pair[origin] = (p, c)
        seen.add(key)

    gate = rows[-1]
    if (
        type(gate) is not dict or gate.keys() != _ROW_FIELDS
        or gate["transport"] != "both_independent_origins"
        or gate["anonymous_previous"] is not None
        or gate["anonymous_current"] is not None
        or gate["reason"] != "original_source_and_identity_unverified"
        or gate["human_action"] != "HUMAN_COMPARE_ORIGINAL_PRIVATE_SOURCES_AND_APPROVALS"
        or gate["completion"] != "NOT_VERIFIED"
        or gate["authorization_granted"] is not False
        or gate["remediation_verified"] is not False
    ):
        raise ValueError("missing mandatory independent HUMAN gate")
    return rows
