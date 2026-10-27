"""Strict single fictional actor/engagement review cohort tests (#1487).

A fictional cohort is ONLY a consistency hint; no authenticated operator
or real tenant, consent, permit, revocation ledger, scan or handler exists.
"""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import os
import random
import socket
import sqlite3
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from lightup.lab_session_lineage_1487 import FictionalLabLineageClaim, review_fictional_lab_lineage
from lightup.lab_session_lineage_cli_1487 import review_synthetic_json

NOW = datetime(2030, 1, 1, 12, 0, tzinfo=timezone.utc)


def claim(i, **updates):
    data = {
        "lab_reference": f"LAB-SYNTH-{i:04d}",
        "operator_id": "ACTOR-FICTIONAL-001",
        "session_id": f"SESSION-SYNTH-{i:04d}",
        "engagement_id": "ENG-FICTIONAL-001",
        "asset_id": f"ASSET-FICTIONAL-{i:04d}",
        "capability_id": "CAP-REVIEW-ONLY",
        "starts_at": NOW - timedelta(minutes=10),
        "expires_at": NOW + timedelta(minutes=10),
        "revoked": False,
    }
    data.update(updates)
    return FictionalLabLineageClaim(**data)


def wire_packet(values):
    def encode_one(value):
        return {
            "lab_reference": value.lab_reference,
            "operator_id": value.operator_id,
            "session_id": value.session_id,
            "engagement_id": value.engagement_id,
            "asset_id": value.asset_id,
            "capability_id": value.capability_id,
            "starts_at": "2030-01-01T11:50:00Z",
            "expires_at": "2030-01-01T12:10:00Z",
            "revoked": value.revoked,
        }
    return json.dumps({
        "schema": "FICTIONAL-LAB-LINEAGE-V1",
        "assessment_time": "2030-01-01T12:00:00Z",
        "claims": [encode_one(v) for v in values],
    }).encode()


class SyntheticSingleCohort1487(unittest.TestCase):
    def assert_review(self, value, expected):
        self.assertEqual(value.status, expected)
        for attr in ("grants_authority", "can_issue_permit", "can_dispatch", "can_release"):
            self.assertIs(getattr(value, attr), False)

    def test_one_fictional_operator_engagement_many_assets_review_only(self):
        self.assert_review(
            review_fictional_lab_lineage((claim(1), claim(2), claim(3)), NOW),
            "REVIEW_ONLY",
        )

    def test_operator_mismatch_is_atomic_hold(self):
        other = claim(2, operator_id="ACTOR-OTHER-001")
        self.assert_review(
            review_fictional_lab_lineage((claim(1), other), NOW), "HOLD"
        )

    def test_engagement_mismatch_is_atomic_hold(self):
        other = claim(2, engagement_id="ENG-OTHER-001")
        self.assert_review(
            review_fictional_lab_lineage((claim(1), other), NOW), "HOLD"
        )

    def test_two_distinct_cohorts_are_never_combined_as_review_only(self):
        other = claim(2, operator_id="ACTOR-OTHER-001", engagement_id="ENG-OTHER-001")
        for values in ((claim(1), other), (other, claim(1))):
            self.assert_review(review_fictional_lab_lineage(values, NOW), "HOLD")

    def test_cross_cohort_entry_at_every_batch_position_holds(self):
        base = [claim(1), claim(2), claim(3)]
        for position in range(4):
            data = base.copy()
            data.insert(position, claim(4, engagement_id="ENG-OTHER-001"))
            self.assert_review(
                review_fictional_lab_lineage(tuple(data), NOW), "HOLD"
            )

    def test_64_item_boundary_single_cohort_stays_only_review_only(self):
        group = tuple(claim(i) for i in range(1, 65))
        self.assert_review(review_fictional_lab_lineage(group, NOW), "REVIEW_ONLY")
        changed = group[:32] + (replace(group[32], operator_id="ACTOR-OTHER-001"),) + group[33:]
        self.assert_review(review_fictional_lab_lineage(changed, NOW), "HOLD")

    def test_permutation_repeatability_and_atomic_denial(self):
        rng = random.Random(1487)
        group = tuple(claim(i) for i in range(1, 13))
        for _ in range(180):
            proposed = list(group)
            rng.shuffle(proposed)
            self.assert_review(review_fictional_lab_lineage(tuple(proposed), NOW), "REVIEW_ONLY")
            proposed[-1] = replace(proposed[-1], engagement_id="ENG-OTHER-001")
            self.assert_review(review_fictional_lab_lineage(tuple(proposed), NOW), "HOLD")

    def test_json_cli_rejects_different_synthetic_operator(self):
        packet = wire_packet((claim(1), claim(2, operator_id="ACTOR-OTHER-001")))
        self.assertEqual(review_synthetic_json(packet), "HOLD")

    def test_json_cli_rejects_different_synthetic_engagement(self):
        packet = wire_packet((claim(1), claim(2, engagement_id="ENG-OTHER-001")))
        self.assertEqual(review_synthetic_json(packet), "HOLD")
        self.assertEqual(review_synthetic_json(wire_packet((claim(1), claim(2)))), "REVIEW_ONLY")

    def test_cohort_review_makes_no_network_database_shell_or_subprocess_call(self):
        values = (claim(1), claim(2))
        with patch.object(socket, "socket", side_effect=AssertionError("network")), (
            patch.object(socket, "getaddrinfo", side_effect=AssertionError("dns"))
        ), (
            patch.object(sqlite3, "connect", side_effect=AssertionError("db"))
        ), (
            patch.object(subprocess, "Popen", side_effect=AssertionError("process"))
        ), (
            patch.object(os, "system", side_effect=AssertionError("shell"))
        ):
            self.assert_review(review_fictional_lab_lineage(values, NOW), "REVIEW_ONLY")
            self.assert_review(
                review_fictional_lab_lineage(
                    (values[0], replace(values[1], operator_id="ACTOR-OTHER-001")), NOW
                ), "HOLD"
            )


if __name__ == "__main__":
    unittest.main()
