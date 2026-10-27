"""Destructive-maximum-risk cannot be synthetic REVIEW_ONLY (#1493).

The reviewer is unwired, historical and non-authorizing. No active target,
live grant, consent, real scan or tool dispatch.
"""
from __future__ import annotations

import dataclasses
import json
import os
import socket
import sqlite3
import subprocess
import sys
import unittest
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.cross_grant_lineage_cli_1493 import evaluate_bytes
from lightup.cross_grant_lineage_review_1493 import (
    CrossGrantCandidate, review_cross_grant_batch, review_cross_grant_lineage,
)
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind
from lightup.scope import ScopePolicy
from lightup.models import Target
from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.models import Authorization

NOW = datetime(2020, 1, 1, 12, 0, tzinfo=timezone.utc)
START, END = NOW - timedelta(minutes=30), NOW + timedelta(minutes=30)


def claim(*, max_risk=RiskLevel.STANDARD, request_risk=RiskLevel.LOW_IMPACT,
          asset="app.example.test", grant_id="G-1"):
    prior = Authorization("operator@example.test", "SYNTH-RISK-1493", START, END)
    durable = AuthorizationGrant(
        grant_id, "CLIENT-1", "ENG-1",
        "operator@example.test", "SYNTH-RISK-1493",
        ScopeDefinition((asset,), max_risk, ("web-baseline",), ()),
        START - timedelta(minutes=15), END + timedelta(minutes=15),
    )
    return CrossGrantCandidate(prior, durable, asset, "web-baseline",
                               "CLIENT-1", "ENG-1", request_risk)


def review(c):
    return review_cross_grant_lineage(
        c.legacy, c.durable, asset=c.asset, capability_id=c.capability_id,
        client_id=c.client_id, engagement_id=c.engagement_id,
        requested_risk=c.requested_risk, evaluated_at=NOW,
    )


def cli_payload(*, max_risk="STANDARD", request_risk="LOW_IMPACT"):
    record = {
        "legacy": {"owner": "operator@example.test", "reference": "SYNTH-RISK-1493",
                   "valid_from": "2020-01-01T11:30:00Z",
                   "valid_until": "2020-01-01T12:30:00Z"},
        "durable": {"grant_id": "G-1", "client_id": "CLIENT-1",
                    "engagement_id": "ENG-1", "approved_by": "operator@example.test",
                    "reference": "SYNTH-RISK-1493",
                    "scope": {"assets": ["app.example.test"], "max_risk": max_risk,
                              "allowed_capabilities": ["web-baseline"],
                              "excluded_assets": []},
                    "valid_from": "2020-01-01T11:15:00Z",
                    "valid_until": "2020-01-01T12:45:00Z",
                    "recurring_retest_allowed": False},
        "asset": "app.example.test", "capability_id": "web-baseline",
        "client_id": "CLIENT-1", "engagement_id": "ENG-1",
        "requested_risk": request_risk,
    }
    return json.dumps({"schema": "FICTIONAL-CROSS-GRANT-V1",
                       "evaluated_at": "2020-01-01T12:00:00Z",
                       "candidates": [record]}).encode("utf8")


def assert_no_authority(case, result):
    for key in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
        case.assertIs(result[key] if type(result) is dict else getattr(result, key), False)


class DestructiveScopeReviewTests(unittest.TestCase):
    def test_normal_scope_remains_review_only_not_authority(self):
        outcome = review(claim())
        self.assertEqual(outcome.status, "REVIEW_ONLY")
        assert_no_authority(self, outcome)

    def test_destructive_max_scope_does_not_pass_low_risk_selected_request(self):
        outcome = review(claim(max_risk=RiskLevel.DESTRUCTIVE_LAB_ONLY))
        self.assertEqual(
            (outcome.status, outcome.reason),
            ("HOLD", "destructive grant scope outside fictional review"))
        assert_no_authority(self, outcome)

    def test_destructive_max_scope_does_not_pass_passive_selected_request(self):
        self.assertEqual(review(claim(
            max_risk=RiskLevel.DESTRUCTIVE_LAB_ONLY,
            request_risk=RiskLevel.PASSIVE)).status, "HOLD")

    def test_destructive_max_scope_does_not_pass_analysis_selected_request(self):
        self.assertEqual(review(claim(
            max_risk=RiskLevel.DESTRUCTIVE_LAB_ONLY,
            request_risk=RiskLevel.ANALYSIS_ONLY)).status, "HOLD")

    def test_requested_destructive_stays_hold_even_if_max_is_destructive(self):
        self.assertEqual(review(claim(
            max_risk=RiskLevel.DESTRUCTIVE_LAB_ONLY,
            request_risk=RiskLevel.DESTRUCTIVE_LAB_ONLY)).status, "HOLD")

    def test_elevated_max_with_low_selected_request_is_only_review(self):
        result = review(claim(max_risk=RiskLevel.ELEVATED))
        self.assertEqual(result.status, "REVIEW_ONLY")
        assert_no_authority(self, result)

    def test_batch_second_destructive_max_is_atomic_hold(self):
        one = claim()
        two = claim(max_risk=RiskLevel.DESTRUCTIVE_LAB_ONLY,
                    asset="other.example.test", grant_id="G-2")
        result = review_cross_grant_batch((one, two), evaluated_at=NOW)
        self.assertEqual((result.status, result.reviewed), ("HOLD", 0))
        assert_no_authority(self, result)

    def test_cli_canonical_destructive_max_scope_is_coherence_hold_exit_two(self):
        receipt, code = evaluate_bytes(cli_payload(max_risk="DESTRUCTIVE_LAB_ONLY"))
        self.assertEqual(
            (receipt["status"], receipt["reason"], receipt["reviewed"], code),
            ("HOLD", "COHERENCE_DENIED", 0, 2))
        assert_no_authority(self, receipt)

    def test_cli_normal_max_remains_non_authorizing_review_only(self):
        receipt, code = evaluate_bytes(cli_payload())
        self.assertEqual(
            (receipt["status"], receipt["reviewed"], code),
            ("REVIEW_ONLY", 1, 2))
        assert_no_authority(self, receipt)

    def test_real_execution_policy_low_request_still_allows_high_max_but_review_holds(self):
        # Real, unmodified policy source in memory, fabricated .example.test only.
        # A positive scope decision NEVER proves approval for the wider grant.
        now = datetime.now(timezone.utc)
        old = Authorization("operator@example.test", "SYNTH-RISK-1493",
                            now - timedelta(minutes=5), now + timedelta(minutes=5))
        grant = AuthorizationGrant(
            "G-1", "CLIENT-1", "ENG-1", "operator@example.test", "SYNTH-RISK-1493",
            ScopeDefinition(("app.example.test",), RiskLevel.DESTRUCTIVE_LAB_ONLY,
                            ("web-baseline",), ()),
            now - timedelta(minutes=10), now + timedelta(minutes=10),
        )
        original = ExecutionPolicy().decide(ExecutionRequest(
            InteractionKind.TARGET_ACTIVE, "app.example.test", "web-baseline",
            RiskLevel.LOW_IMPACT, authorization=grant,
        ))
        self.assertTrue(original.allowed)
        review_result = review_cross_grant_lineage(
            old, grant, asset="app.example.test", capability_id="web-baseline",
            client_id="CLIENT-1", engagement_id="ENG-1",
            requested_risk=RiskLevel.LOW_IMPACT, evaluated_at=now,
        )
        self.assertEqual(review_result.status, "HOLD")
        assert_no_authority(self, review_result)

    def test_original_scope_policy_does_not_certify_destructive_grant_envelope(self):
        now = datetime.now(timezone.utc)
        old = Authorization("operator@example.test", "SYNTH-RISK-1493",
                            now - timedelta(minutes=5), now + timedelta(minutes=5))
        grant = AuthorizationGrant(
            "G-1", "CLIENT-1", "ENG-1", "operator@example.test", "SYNTH-RISK-1493",
            ScopeDefinition(("app.example.test",), RiskLevel.DESTRUCTIVE_LAB_ONLY,
                            ("web-baseline",), ()),
            now - timedelta(minutes=10), now + timedelta(minutes=10),
        )
        self.assertTrue(ScopePolicy(
            explicit_hosts=frozenset({"app.example.test"})).decide(
                Target("app.example.test", authorization=old)).allowed)
        result = review_cross_grant_lineage(
            old, grant, asset="app.example.test", capability_id="web-baseline",
            client_id="CLIENT-1", engagement_id="ENG-1",
            requested_risk=RiskLevel.LOW_IMPACT, evaluated_at=now)
        self.assertEqual(result.status, "HOLD")
        assert_no_authority(self, result)

    def test_destructive_max_review_invokes_no_external_io(self):
        c = claim(max_risk=RiskLevel.DESTRUCTIVE_LAB_ONLY)
        with ExitStack() as stack:
            stack.enter_context(patch.object(socket, "socket", side_effect=AssertionError))
            stack.enter_context(patch.object(sqlite3, "connect", side_effect=AssertionError))
            stack.enter_context(patch.object(subprocess, "Popen", side_effect=AssertionError))
            stack.enter_context(patch("builtins.open", side_effect=AssertionError))
            self.assertEqual(review(c).status, "HOLD")


if __name__ == "__main__":
    unittest.main()
