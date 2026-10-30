"""Strict admission for anonymous, source-free two-transport comparison views.

Only previously verified synthetic ZIPs may provide the original comparison.
This projection never establishes identity, consent, permission or approval.
"""
from __future__ import annotations
from math import isqrt

COUNTS = (
    "original_pairs", "hold_pairs", "pass_pairs",
    "reused_evidence_pairs", "score_drift_pairs",
)
_SOURCE = frozenset((
    "global_status", "unsigned_transport_sha256", "original_archives",
    *COUNTS,
))
_FIELDS = frozenset((
    "schema", "baseline", "candidate",
    "count_change_candidate_minus_baseline", "baseline_hold_preserved",
    "review_status", "original_source_authenticated",
    "same_originals_proven", "remediation_verified",
    "authorization_granted", "external_targets_contacted",
    "deployment", "human_review_only",
))


def admit_human_comparison(value: dict) -> dict:
    """Reject foreign fields, forged status, counts and exportable HTML text."""
    if type(value) is not dict or value.keys() != _FIELDS:
        raise ValueError("untrusted HUMAN comparison envelope")
    if (
        value["schema"] != "lightup.lab-score-human-two-transport-comparison.v1"
        or value["human_review_only"] is not True
        or any(value[k] is not False for k in (
            "original_source_authenticated", "same_originals_proven",
            "remediation_verified", "authorization_granted",
            "external_targets_contacted", "deployment"
        ))
    ):
        raise ValueError("untrusted HUMAN comparison authority")
    for label in ("baseline", "candidate"):
        source = value[label]
        if type(source) is not dict or source.keys() != _SOURCE:
            raise ValueError("untrusted anonymous comparison source")
        digest = source["unsigned_transport_sha256"]
        if (
            source["global_status"] not in ("PASS", "HOLD")
            or type(digest) is not str or len(digest) != 64
            or any(ch not in "0123456789abcdef" for ch in digest)
            or type(source["original_archives"]) is not int
            or not 2 <= source["original_archives"] <= 8
            or any(type(source[k]) is not int for k in COUNTS)
        ):
            raise ValueError("untrusted synthetic comparison metrics")
        n = source["original_archives"]
        pairs = n * (n - 1) // 2
        if (
            source["original_pairs"] != pairs
            or not 0 <= source["hold_pairs"] <= pairs
            or source["pass_pairs"] + source["hold_pairs"] != pairs
            or (source["hold_pairs"] > 0 and source["global_status"] != "HOLD")
            or not 0 <= source["reused_evidence_pairs"] <= source["hold_pairs"]
            or not 0 <= source["score_drift_pairs"] <= source["hold_pairs"]
        ):
            raise ValueError("incoherent original anonymous pair counts")
    first, second = value["baseline"], value["candidate"]
    if first["unsigned_transport_sha256"] == second["unsigned_transport_sha256"]:
        raise ValueError("same unverified anonymous ZIP")
    delta = value["count_change_candidate_minus_baseline"]
    if type(delta) is not dict or delta.keys() != frozenset(COUNTS):
        raise ValueError("untrusted comparison deltas")
    if any(type(delta[k]) is not int or delta[k] != second[k] - first[k]
           for k in COUNTS):
        raise ValueError("forged anonymous count delta")
    if (
        value["baseline_hold_preserved"] is not (first["global_status"] == "HOLD")
        or value["review_status"] != (
            "HOLD" if "HOLD" in (first["global_status"], second["global_status"])
            else "PASS"
        )
    ):
        raise ValueError("forged comparison HOLD status")
    return value
