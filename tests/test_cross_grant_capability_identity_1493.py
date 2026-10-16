"""Strict, fictional-only capability identity parity (#1493).

All synthetic records fixed at 2020 UTC. Never read targets or make grants.
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
from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.models import Authorization

_NOW = datetime(2020, 1, 1, 12, 0, tzinfo=timezone.utc)
_START, _END = _NOW - timedelta(minutes=30), _NOW + timedelta(minutes=30)


def _claim(capability="web-baseline", *, scope_capabilities=None, grant_id="G-1",
           asset="app.example.test"):
    legacy = Authorization("operator@example.test", "SYNTH-CAP-1493", _START, _END)
    durable = AuthorizationGrant(
        grant_id, "CLIENT-1", "ENG-1", "operator@example.test", "SYNTH-CAP-1493",
        ScopeDefinition((asset,), RiskLevel.STANDARD,
                        (capability,) if scope_capabilities is None else scope_capabilities,
                        ()),
        _START - timedelta(minutes=15), _END + timedelta(minutes=15),
    )
    return CrossGrantCandidate(
        legacy, durable, asset, capability, "CLIENT-1", "ENG-1", RiskLevel.LOW_IMPACT,
    )


def _review(claim):
    return review_cross_grant_lineage(
        claim.legacy, claim.durable, asset=claim.asset,
        capability_id=claim.capability_id, client_id=claim.client_id,
        engagement_id=claim.engagement_id,
        requested_risk=claim.requested_risk, evaluated_at=_NOW,
    )


def _raw(capability="web-baseline", *, scope_capability=None):
    c = {
        "legacy": {"owner": "operator@example.test", "reference": "SYNTH-CAP-1493",
                   "valid_from": "2020-01-01T11:30:00Z",
                   "valid_until": "2020-01-01T12:30:00Z"},
        "durable": {
            "grant_id": "G-1", "client_id": "CLIENT-1", "engagement_id": "ENG-1",
            "approved_by": "operator@example.test", "reference": "SYNTH-CAP-1493",
            "scope": {"assets": ["app.example.test"], "max_risk": "STANDARD",
                      "allowed_capabilities": [capability if scope_capability is None
                                               else scope_capability],
                      "excluded_assets": []},
            "valid_from": "2020-01-01T11:15:00Z",
            "valid_until": "2020-01-01T12:45:00Z",
            "recurring_retest_allowed": False,
        },
        "asset": "app.example.test", "capability_id": capability,
        "client_id": "CLIENT-1", "engagement_id": "ENG-1",
        "requested_risk": "LOW_IMPACT",
    }
    return json.dumps({"schema": "FICTIONAL-CROSS-GRANT-V1",
                       "evaluated_at": "2020-01-01T12:00:00Z",
                       "candidates": [c]}).encode("utf8")


class CapabilityIdentityTests(unittest.TestCase):
    def _assert_non_authorizing(self, receipt):
        for flag in ("authorized", "consent_verified",
                     "dispatch_allowed", "release_allowed"):
            self.assertIs(receipt[flag] if type(receipt) is dict
                          else getattr(receipt, flag), False)

    def test_plain_canonical_capability_is_review_only(self):
        result = _review(_claim())
        self.assertEqual(result.status, "REVIEW_ONLY")
        self._assert_non_authorizing(result)

    def test_lowercase_underscore_slug_accepted(self):
        self.assertEqual(_review(_claim("web_probe_2")).status, "REVIEW_ONLY")

    def test_capability_slug_exact_64_char_limit_accepted(self):
        self.assertEqual(_review(_claim("a" + "9" * 63)).status, "REVIEW_ONLY")

    def test_over_64_char_capability_denied(self):
        self.assertEqual(_review(_claim("a" + "9" * 64)).status, "HOLD")

    def test_uppercase_alias_denied_even_if_scope_claim_matches(self):
        self.assertEqual(_review(_claim("Web-Baseline")).status, "HOLD")

    def test_uri_scheme_capability_denied(self):
        self.assertEqual(_review(_claim("http://web-baseline")).status, "HOLD")

    def test_file_path_and_parent_segments_denied(self):
        for item in ("../web", "web/../probe", "/web", "web\\probe"):
            with self.subTest(capability=item):
                self.assertEqual(_review(_claim(item)).status, "HOLD")

    def test_unicode_confusable_capability_denied(self):
        self.assertEqual(_review(_claim("wеb-baseline")).status, "HOLD")

    def test_space_and_control_capability_denied(self):
        for item in ("web baseline", "web\nprobe", "web\tprobe"):
            with self.subTest(capability=item):
                self.assertEqual(_review(_claim(item)).status, "HOLD")

    def test_dot_dot_and_double_underscore_not_aliases(self):
        for item in (".web", "web..probe", "web:probe"):
            with self.subTest(capability=item):
                self.assertEqual(_review(_claim(item)).status, "HOLD")

    def test_invalid_unselected_scope_capability_denied(self):
        c = _claim(scope_capabilities=("web-baseline", "tool/hidden"))
        self.assertEqual(_review(c).status, "HOLD")

    def test_non_string_with_hostile_equality_denied_before_comparison(self):
        class Trap:
            def __eq__(self, _):
                raise AssertionError("invoked untrusted equality")
        c = dataclasses.replace(_claim(), capability_id=Trap())
        self.assertEqual(_review(c).status, "HOLD")

    def test_invalid_second_capability_batch_atomic_hold(self):
        one = _claim()
        two = _claim("../web", grant_id="G-2", asset="other.example.test")
        result = review_cross_grant_batch((one, two), evaluated_at=_NOW)
        self.assertEqual((result.status, result.reviewed), ("HOLD", 0))
        self._assert_non_authorizing(result)

    def test_cli_plain_slug_positive_is_non_authorizing_exit_two(self):
        receipt, code = evaluate_bytes(_raw())
        self.assertEqual((receipt["status"], receipt["reviewed"], code),
                         ("REVIEW_ONLY", 1, 2))
        self._assert_non_authorizing(receipt)

    def test_cli_wrong_case_is_invalid_input_exit_three(self):
        receipt, code = evaluate_bytes(_raw("Web-Baseline"))
        self.assertEqual((receipt["status"], receipt["reason"], code),
                         ("HOLD", "INVALID_INPUT", 3))
        self._assert_non_authorizing(receipt)

    def test_cli_invalid_unselected_scope_capability_is_invalid(self):
        receipt, code = evaluate_bytes(_raw(scope_capability="../hidden"))
        self.assertEqual((receipt["status"], receipt["reason"], code),
                         ("HOLD", "INVALID_INPUT", 3))
        self._assert_non_authorizing(receipt)

    def test_cli_64_length_positive_and_65_length_denial(self):
        r64, c64 = evaluate_bytes(_raw("a" + "9" * 63))
        r65, c65 = evaluate_bytes(_raw("a" + "9" * 64))
        self.assertEqual((r64["status"], c64), ("REVIEW_ONLY", 2))
        self.assertEqual((r65["status"], c65), ("HOLD", 3))
        self._assert_non_authorizing(r64)
        self._assert_non_authorizing(r65)

    def test_pure_denial_performs_no_io(self):
        with ExitStack() as stack:
            stack.enter_context(patch.object(socket, "socket", side_effect=AssertionError))
            stack.enter_context(patch.object(sqlite3, "connect", side_effect=AssertionError))
            stack.enter_context(patch.object(subprocess, "Popen", side_effect=AssertionError))
            stack.enter_context(patch("builtins.open", side_effect=AssertionError))
            self.assertEqual(_review(_claim("web/../probe")).status, "HOLD")


if __name__ == "__main__":
    unittest.main()
