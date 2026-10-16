"""Issue #1493: strict per-label fictional asset consistency, offline only.

All assertions are fabricated records. Neither decision nor test authorizes a
real client, grant, target, consent, permit, tool, or release.
"""
from __future__ import annotations

import dataclasses
import os
import socket
import sqlite3
import subprocess
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.cross_grant_lineage_review_1493 import (
    CrossGrantCandidate,
    review_cross_grant_batch,
    review_cross_grant_lineage,
)
from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.models import Authorization

_NOW = datetime(2020, 1, 1, 12, 0, tzinfo=timezone.utc)
_START, _END = _NOW - timedelta(minutes=30), _NOW + timedelta(minutes=30)


def _candidate(asset="app.example.test", *, exclusions=(), scope_assets=None):
    legacy = Authorization("reviewer@example.test", "SYNTH-ASSET-1493", _START, _END)
    grant = AuthorizationGrant(
        "FICTIONAL-GRANT-1", "CLIENT-1", "ENG-1",
        "reviewer@example.test", "SYNTH-ASSET-1493",
        ScopeDefinition(
            (asset,) if scope_assets is None else scope_assets,
            RiskLevel.STANDARD, ("web-baseline",), exclusions,
        ), _START - timedelta(minutes=15), _END + timedelta(minutes=15),
    )
    return CrossGrantCandidate(
        legacy, grant, asset, "web-baseline", "CLIENT-1", "ENG-1",
        RiskLevel.LOW_IMPACT,
    )


def _review(candidate):
    return review_cross_grant_lineage(
        candidate.legacy, candidate.durable, asset=candidate.asset,
        capability_id=candidate.capability_id, client_id=candidate.client_id,
        engagement_id=candidate.engagement_id,
        requested_risk=candidate.requested_risk, evaluated_at=_NOW,
    )


class CanonicalAssetReviewTests(unittest.TestCase):
    def test_normal_fictional_asset_still_review_only(self):
        receipt = _review(_candidate())
        self.assertEqual(receipt.status, "REVIEW_ONLY")
        self.assertFalse(receipt.authorized)
        self.assertFalse(receipt.release_allowed)

    def test_canonical_hyphen_inside_label_still_review_only(self):
        self.assertEqual(_review(_candidate("my-lab.example.test")).status, "REVIEW_ONLY")

    def test_exact_63_character_label_still_review_only(self):
        self.assertEqual(
            _review(_candidate("a" * 63 + ".example.test")).status,
            "REVIEW_ONLY",
        )

    def test_leading_hyphen_in_middle_label_is_hold(self):
        self.assertEqual(
            _review(_candidate("lab.-device.example.test")).status, "HOLD",
        )

    def test_trailing_hyphen_in_first_label_is_hold(self):
        self.assertEqual(_review(_candidate("device-.example.test")).status, "HOLD")

    def test_trailing_hyphen_in_middle_label_is_hold(self):
        self.assertEqual(
            _review(_candidate("app.lab-.example.test")).status, "HOLD",
        )

    def test_overlong_first_label_is_hold(self):
        self.assertEqual(
            _review(_candidate("a" * 64 + ".example.test")).status, "HOLD",
        )

    def test_overlong_middle_label_is_hold(self):
        self.assertEqual(
            _review(_candidate("app." + "x" * 64 + ".test")).status, "HOLD",
        )

    def test_noncanonical_scope_asset_is_hold_even_if_requested_asset_valid(self):
        self.assertEqual(
            _review(_candidate(scope_assets=("app.example.test", "bad-.example.test"))).status,
            "HOLD",
        )

    def test_noncanonical_scope_exclusion_is_hold(self):
        self.assertEqual(
            _review(_candidate(exclusions=("bad-.example.test",))).status,
            "HOLD",
        )

    def test_batch_second_noncanonical_asset_is_atomic_hold(self):
        normal = _candidate()
        malformed = _candidate("bad-.example.test")
        malformed = dataclasses.replace(
            malformed,
            durable=dataclasses.replace(malformed.durable, grant_id="FICTIONAL-GRANT-2"),
        )
        result = review_cross_grant_batch((normal, malformed), evaluated_at=_NOW)
        self.assertEqual((result.status, result.reviewed), ("HOLD", 0))
        self.assertFalse(result.consent_verified)
        self.assertFalse(result.dispatch_allowed)
        self.assertFalse(result.release_allowed)

    def test_bad_labels_review_is_file_network_and_process_free(self):
        with patch.object(socket, "socket", side_effect=AssertionError("network")), \
             patch.object(sqlite3, "connect", side_effect=AssertionError("database")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process")), \
             patch("builtins.open", side_effect=AssertionError("file")):
            self.assertEqual(_review(_candidate("bad-.example.test")).status, "HOLD")


if __name__ == "__main__":
    unittest.main()
