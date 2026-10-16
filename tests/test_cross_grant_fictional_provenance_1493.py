"""#1493: deny real/noncanonical actor provenance in fictional-only review.

These are fabricated identities at fixed 2020 UTC. No real target, client,
consent, executable permit, handler, network, database or release authority.
"""
import dataclasses
import json
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.cross_grant_lineage_review_1493 import (
    CrossGrantCandidate,
    review_cross_grant_batch,
    review_cross_grant_lineage,
)
from lightup.cross_grant_lineage_cli_1493 import evaluate_bytes
from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.models import Authorization

NOW = datetime(2020, 1, 1, 12, 0, tzinfo=timezone.utc)
BEFORE, AFTER = NOW - timedelta(minutes=30), NOW + timedelta(minutes=30)


def candidate():
    legacy = Authorization("fake-reviewer@example.test", "SYNTH-LAB-1493", BEFORE, AFTER)
    grant = AuthorizationGrant(
        "G-1", "CLIENT-1", "ENG-1",
        "fake-reviewer@example.test", "SYNTH-LAB-1493",
        ScopeDefinition(("app.example.test",), RiskLevel.STANDARD,
                        ("web-baseline",), ()),
        BEFORE - timedelta(minutes=10), AFTER + timedelta(minutes=10),
    )
    return CrossGrantCandidate(legacy, grant, "app.example.test", "web-baseline",
                               "CLIENT-1", "ENG-1", RiskLevel.LOW_IMPACT)


def evaluate(claim):
    return review_cross_grant_lineage(
        claim.legacy, claim.durable, asset=claim.asset,
        capability_id=claim.capability_id, client_id=claim.client_id,
        engagement_id=claim.engagement_id,
        requested_risk=claim.requested_risk, evaluated_at=NOW,
    )


def payload(*, actor="fake-reviewer@example.test", reference="SYNTH-LAB-1493"):
    claim = {
        "legacy": {
            "owner": actor, "reference": reference,
            "valid_from": "2020-01-01T11:30:00Z",
            "valid_until": "2020-01-01T12:30:00Z",
        },
        "durable": {
            "grant_id": "G-1", "client_id": "CLIENT-1", "engagement_id": "ENG-1",
            "approved_by": actor, "reference": reference,
            "scope": {"assets": ["app.example.test"], "max_risk": "STANDARD",
                      "allowed_capabilities": ["web-baseline"], "excluded_assets": []},
            "valid_from": "2020-01-01T11:20:00Z",
            "valid_until": "2020-01-01T12:40:00Z",
            "recurring_retest_allowed": False,
        },
        "asset": "app.example.test", "capability_id": "web-baseline",
        "client_id": "CLIENT-1", "engagement_id": "ENG-1",
        "requested_risk": "LOW_IMPACT",
    }
    return json.dumps({
        "schema": "FICTIONAL-CROSS-GRANT-V1",
        "evaluated_at": "2020-01-01T12:00:00Z",
        "candidates": [claim],
    }).encode("utf-8")


def assert_no_authority(test, receipt):
    for field in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
        test.assertIs(receipt[field] if type(receipt) is dict else getattr(receipt, field), False)


class FictionalProvenanceTests(unittest.TestCase):
    def test_synthetic_matching_actor_and_reference_remain_review_only(self):
        result = evaluate(candidate())
        self.assertEqual(result.status, "REVIEW_ONLY")
        assert_no_authority(self, result)

    def test_real_operator_email_even_when_both_claims_match_is_hold(self):
        x = candidate()
        x = dataclasses.replace(
            x, legacy=dataclasses.replace(x.legacy, owner="reviewer@realclient.com"),
            durable=dataclasses.replace(x.durable, approved_by="reviewer@realclient.com"),
        )
        result = evaluate(x)
        self.assertEqual(result.status, "HOLD")
        assert_no_authority(self, result)

    def test_double_at_in_fictional_issuer_is_hold(self):
        x = candidate()
        x = dataclasses.replace(
            x, legacy=dataclasses.replace(x.legacy, owner="fake@@example.test"),
            durable=dataclasses.replace(x.durable, approved_by="fake@@example.test"),
        )
        self.assertEqual(evaluate(x).status, "HOLD")

    def test_dot_prefixed_local_part_is_hold(self):
        x = candidate()
        x = dataclasses.replace(
            x, legacy=dataclasses.replace(x.legacy, owner=".fake@example.test"),
            durable=dataclasses.replace(x.durable, approved_by=".fake@example.test"),
        )
        self.assertEqual(evaluate(x).status, "HOLD")

    def test_appended_domain_to_fake_issuer_is_hold(self):
        x = candidate()
        x = dataclasses.replace(
            x, legacy=dataclasses.replace(x.legacy, owner="fake@example.test.malicious.net"),
            durable=dataclasses.replace(x.durable, approved_by="fake@example.test.malicious.net"),
        )
        self.assertEqual(evaluate(x).status, "HOLD")

    def test_empty_synth_reference_marker_is_hold(self):
        x = candidate()
        x = dataclasses.replace(
            x, legacy=dataclasses.replace(x.legacy, reference="SYNTH-"),
            durable=dataclasses.replace(x.durable, reference="SYNTH-"),
        )
        self.assertEqual(evaluate(x).status, "HOLD")

    def test_real_reference_even_when_both_claims_match_is_hold(self):
        x = candidate()
        x = dataclasses.replace(
            x, legacy=dataclasses.replace(x.legacy, reference="REAL-TICKET-123"),
            durable=dataclasses.replace(x.durable, reference="REAL-TICKET-123"),
        )
        self.assertEqual(evaluate(x).status, "HOLD")

    def test_invalid_approval_actor_even_when_legacy_is_fictional_is_hold(self):
        x = candidate()
        x = dataclasses.replace(x, durable=dataclasses.replace(
            x.durable, approved_by="reviewer@realclient.com"))
        self.assertEqual(evaluate(x).status, "HOLD")

    def test_invalid_synthetic_actor_in_second_batch_is_atomic_hold(self):
        first = candidate()
        second = dataclasses.replace(
            first,
            durable=dataclasses.replace(first.durable, grant_id="G-2",
                                        approved_by="fake@@example.test"),
            legacy=dataclasses.replace(first.legacy, owner="fake@@example.test"),
        )
        result = review_cross_grant_batch((first, second), evaluated_at=NOW)
        self.assertEqual((result.status, result.reviewed), ("HOLD", 0))
        assert_no_authority(self, result)

    def test_cli_invalid_double_at_actor_is_invalid_input_exit_three(self):
        result, code = evaluate_bytes(payload(actor="fake@@example.test"))
        self.assertEqual((result["status"], result["reason"], code),
                         ("HOLD", "INVALID_INPUT", 3))
        assert_no_authority(self, result)

    def test_cli_empty_synth_reference_is_invalid_input_exit_three(self):
        result, code = evaluate_bytes(payload(reference="SYNTH-"))
        self.assertEqual((result["status"], result["reason"], code),
                         ("HOLD", "INVALID_INPUT", 3))
        assert_no_authority(self, result)

    def test_cli_valid_synthetic_actor_and_reference_remain_nonzero(self):
        result, code = evaluate_bytes(payload())
        self.assertEqual((result["status"], result["reviewed"], code),
                         ("REVIEW_ONLY", 1, 2))
        assert_no_authority(self, result)


if __name__ == "__main__":
    unittest.main()
