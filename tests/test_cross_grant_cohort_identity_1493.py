"""Opaque fictional tenant/engagement/grant identity regression suite #1493.

No real client identity, consent, request, scan or dispatch is represented.
"""
from __future__ import annotations

import dataclasses
import json
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.cross_grant_lineage_cli_1493 import evaluate_bytes
from lightup.cross_grant_lineage_review_1493 import (
    CrossGrantCandidate, review_cross_grant_batch, review_cross_grant_lineage,
)
from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.models import Authorization

NOW = datetime(2020, 1, 1, 12, 0, tzinfo=timezone.utc)
START, END = NOW - timedelta(minutes=30), NOW + timedelta(minutes=30)


def claim(*, grant_id="G-1", client_id="CLIENT-1", engagement_id="ENG-1",
          request_client=None, request_engagement=None, asset="app.example.test"):
    a = Authorization("fake@example.test", "SYNTH-ID-1493", START, END)
    b = AuthorizationGrant(
        grant_id, client_id, engagement_id,
        "fake@example.test", "SYNTH-ID-1493",
        ScopeDefinition((asset,), RiskLevel.STANDARD, ("web-baseline",), ()),
        START - timedelta(minutes=10), END + timedelta(minutes=10),
    )
    return CrossGrantCandidate(a, b, asset, "web-baseline",
                               client_id if request_client is None else request_client,
                               engagement_id if request_engagement is None else request_engagement,
                               RiskLevel.LOW_IMPACT)


def review(x):
    return review_cross_grant_lineage(
        x.legacy, x.durable, asset=x.asset,
        capability_id=x.capability_id, client_id=x.client_id,
        engagement_id=x.engagement_id, requested_risk=x.requested_risk,
        evaluated_at=NOW,
    )


def input_bytes(*, grant_id="G-1", client_id="CLIENT-1",
                engagement_id="ENG-1", request_client=None):
    x = {
        "legacy": {"owner": "fake@example.test", "reference": "SYNTH-ID-1493",
                   "valid_from": "2020-01-01T11:30:00Z",
                   "valid_until": "2020-01-01T12:30:00Z"},
        "durable": {"grant_id": grant_id, "client_id": client_id,
                    "engagement_id": engagement_id, "approved_by": "fake@example.test",
                    "reference": "SYNTH-ID-1493",
                    "scope": {"assets": ["app.example.test"], "max_risk": "STANDARD",
                              "allowed_capabilities": ["web-baseline"], "excluded_assets": []},
                    "valid_from": "2020-01-01T11:20:00Z",
                    "valid_until": "2020-01-01T12:40:00Z",
                    "recurring_retest_allowed": False},
        "asset": "app.example.test", "capability_id": "web-baseline",
        "client_id": client_id if request_client is None else request_client,
        "engagement_id": engagement_id, "requested_risk": "LOW_IMPACT",
    }
    return json.dumps({"schema": "FICTIONAL-CROSS-GRANT-V1",
                       "evaluated_at": "2020-01-01T12:00:00Z",
                       "candidates": [x]}).encode("utf8")


def never_auth(tc, r):
    for name in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
        tc.assertIs(r[name] if type(r) is dict else getattr(r, name), False)


class OpaqueCohortIdentityTests(unittest.TestCase):
    def test_canonical_pair_and_grant_review_only_never_authorizes(self):
        result = review(claim())
        self.assertEqual(result.status, "REVIEW_ONLY")
        never_auth(self, result)

    def test_valid_underscore_in_fictional_client_identifier(self):
        self.assertEqual(review(claim(client_id="CLIENT_1")).status, "REVIEW_ONLY")

    def test_exact_64_char_grant_id_review_only(self):
        self.assertEqual(review(claim(grant_id="G" + "2" * 63)).status, "REVIEW_ONLY")

    def test_overlong_65_char_grant_id_hold(self):
        self.assertEqual(review(claim(grant_id="G" + "2" * 64)).status, "HOLD")

    def test_noncanonical_path_in_grant_id_hold(self):
        self.assertEqual(review(claim(grant_id="G/../OTHER")).status, "HOLD")

    def test_trailing_dash_in_grant_id_hold(self):
        self.assertEqual(review(claim(grant_id="G-")).status, "HOLD")

    def test_colon_alias_in_grant_id_hold(self):
        self.assertEqual(review(claim(grant_id="G:1")).status, "HOLD")

    def test_client_hierarchical_path_denied_even_when_both_claims_match(self):
        self.assertEqual(review(claim(client_id="CLIENT/../OTHER")).status, "HOLD")

    def test_dotted_tenant_alias_denied(self):
        self.assertEqual(review(claim(client_id="CLIENT.1")).status, "HOLD")

    def test_email_looking_client_id_denied(self):
        self.assertEqual(review(claim(client_id="CLIENT@example.test")).status, "HOLD")

    def test_engagement_path_denied_even_when_both_claims_match(self):
        self.assertEqual(review(claim(engagement_id="ENG/../OTHER")).status, "HOLD")

    def test_unicode_confusable_grant_denied(self):
        self.assertEqual(review(claim(grant_id="G-١")).status, "HOLD")

    def test_invalid_request_client_cannot_be_review_only(self):
        self.assertEqual(review(claim(request_client="CLIENT/../OTHER")).status, "HOLD")

    def test_invalid_second_grant_batch_is_atomic_hold(self):
        one = claim()
        two = claim(grant_id="G/../OTHER", asset="other.example.test")
        r = review_cross_grant_batch((one, two), evaluated_at=NOW)
        self.assertEqual((r.status, r.reviewed), ("HOLD", 0))
        never_auth(self, r)

    def test_cli_fake_grant_path_is_invalid_input_exit_three(self):
        receipt, code = evaluate_bytes(input_bytes(grant_id="G/../OTHER"))
        self.assertEqual((receipt["status"], receipt["reason"], code),
                         ("HOLD", "INVALID_INPUT", 3))
        never_auth(self, receipt)

    def test_cli_dotted_client_is_invalid_input_exit_three(self):
        receipt, code = evaluate_bytes(input_bytes(client_id="CLIENT.1"))
        self.assertEqual((receipt["status"], receipt["reason"], code),
                         ("HOLD", "INVALID_INPUT", 3))
        never_auth(self, receipt)

    def test_cli_invalid_request_client_is_invalid_input_exit_three(self):
        receipt, code = evaluate_bytes(input_bytes(request_client="CLIENT/../OTHER"))
        self.assertEqual((receipt["status"], receipt["reason"], code),
                         ("HOLD", "INVALID_INPUT", 3))
        never_auth(self, receipt)

    def test_cli_max_length_boundary_is_exact(self):
        pass_receipt, pass_code = evaluate_bytes(input_bytes(grant_id="G" + "2" * 63))
        hold_receipt, hold_code = evaluate_bytes(input_bytes(grant_id="G" + "2" * 64))
        self.assertEqual((pass_receipt["status"], pass_code), ("REVIEW_ONLY", 2))
        self.assertEqual((hold_receipt["status"], hold_code), ("HOLD", 3))
        never_auth(self, pass_receipt)
        never_auth(self, hold_receipt)


if __name__ == "__main__":
    unittest.main()
