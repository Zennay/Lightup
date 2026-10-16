"""Issue #1493: latent effective-scope overlap must not inflate review proof.

Fictional, offline, read-only acceptance for a wholly unwired HOLD-only helper.
Never a production grant, consent, scanner, network target, or release gate.
"""
from __future__ import annotations

import dataclasses
import itertools
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
    CrossGrantCandidate, review_cross_grant_batch, review_cross_grant_lineage,
)
from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.models import Authorization

NOW = datetime(2020, 1, 1, 12, 0, tzinfo=timezone.utc)
START, END = NOW - timedelta(hours=1), NOW + timedelta(hours=1)


def candidate(*, grant_id, asset, capability_id, assets, capabilities, excluded=()):
    legacy = Authorization("reviewer@example.test", "SYNTH-FOOTPRINT-1493", START, END)
    durable = AuthorizationGrant(
        grant_id, "CLIENT-1", "ENG-1", "reviewer@example.test",
        "SYNTH-FOOTPRINT-1493",
        ScopeDefinition(tuple(assets), RiskLevel.STANDARD,
                        tuple(capabilities), tuple(excluded)),
        START - timedelta(hours=1), END + timedelta(hours=1),
    )
    return CrossGrantCandidate(
        legacy, durable, asset, capability_id, "CLIENT-1", "ENG-1",
        RiskLevel.LOW_IMPACT,
    )


def overlapping():
    first = candidate(
        grant_id="G-1", asset="alpha.example.test", capability_id="alpha-cap",
        assets=("alpha.example.test", "shadow.example.test"),
        capabilities=("alpha-cap", "shared-cap"),
    )
    second = candidate(
        grant_id="G-2", asset="beta.example.test", capability_id="beta-cap",
        assets=("beta.example.test", "shadow.example.test"),
        capabilities=("beta-cap", "shared-cap"),
    )
    return first, second


def review(*claims):
    return review_cross_grant_batch(tuple(claims), evaluated_at=NOW)


class FullScopeOverlapTests(unittest.TestCase):
    def test_individual_disjoint_requests_still_look_coherent(self):
        for claim in overlapping():
            with self.subTest(grant=claim.durable.grant_id):
                result = review(claim)
                self.assertEqual((result.status, result.reviewed), ("REVIEW_ONLY", 1))
                self.assertFalse(result.authorized)

    def test_unrequested_cross_grant_authority_overlap_is_atomic_hold(self):
        first, second = overlapping()
        result = review(first, second)
        self.assertEqual((result.status, result.reason, result.reviewed),
                         ("HOLD", "overlapping grant scope provenance", 0))
        self.assertFalse(result.consent_verified)
        self.assertFalse(result.dispatch_allowed)
        self.assertFalse(result.release_allowed)

    def test_reverse_order_cannot_hide_overlapping_authority(self):
        first, second = overlapping()
        self.assertEqual(review(first, second).status, "HOLD")
        self.assertEqual(review(second, first).status, "HOLD")

    def test_every_permutation_of_ambiguous_three_record_batch_is_hold(self):
        first, second = overlapping()
        extra = candidate(
            grant_id="G-3", asset="gamma.example.test", capability_id="gamma-cap",
            assets=("gamma.example.test",), capabilities=("gamma-cap",),
        )
        for ordered in itertools.permutations((first, second, extra)):
            result = review(*ordered)
            self.assertEqual((result.status, result.reviewed), ("HOLD", 0))

    def test_common_capability_with_disjoint_assets_is_only_review_only(self):
        first = candidate(
            grant_id="G-1", asset="alpha.example.test", capability_id="shared-cap",
            assets=("alpha.example.test",), capabilities=("shared-cap",),
        )
        second = candidate(
            grant_id="G-2", asset="beta.example.test", capability_id="shared-cap",
            assets=("beta.example.test",), capabilities=("shared-cap",),
        )
        self.assertEqual((review(first, second).status, review(first, second).reviewed),
                         ("REVIEW_ONLY", 2))

    def test_common_asset_with_disjoint_capabilities_is_only_review_only(self):
        first = candidate(
            grant_id="G-1", asset="alpha.example.test", capability_id="web-cap",
            assets=("alpha.example.test",), capabilities=("web-cap",),
        )
        second = candidate(
            grant_id="G-2", asset="alpha.example.test", capability_id="tls-cap",
            assets=("alpha.example.test",), capabilities=("tls-cap",),
        )
        self.assertEqual(review(first, second).status, "REVIEW_ONLY")

    def test_excluded_shadow_asset_removes_potential_overlap(self):
        first, second = overlapping()
        second = dataclasses.replace(
            second, durable=dataclasses.replace(
                second.durable,
                scope=dataclasses.replace(
                    second.durable.scope,
                    excluded_assets=("shadow.example.test",),
                ),
            ),
        )
        self.assertEqual(review(first, second).status, "REVIEW_ONLY")

    def test_same_grant_snapshot_multiple_assets_does_not_self_collide(self):
        first = candidate(
            grant_id="G-1", asset="alpha.example.test", capability_id="alpha-cap",
            assets=("alpha.example.test", "beta.example.test"),
            capabilities=("alpha-cap", "beta-cap"),
        )
        second = dataclasses.replace(first, asset="beta.example.test",
                                     capability_id="beta-cap")
        result = review(first, second)
        self.assertEqual((result.status, result.reviewed), ("REVIEW_ONLY", 2))

    def test_thirty_two_disjoint_footprints_with_shared_caps_still_review_only(self):
        batch = tuple(candidate(
            grant_id=f"G-{n}", asset=f"asset-{n}.example.test",
            capability_id="shared-cap", assets=(f"asset-{n}.example.test",),
            capabilities=("shared-cap",),
        ) for n in range(32))
        result = review(*batch)
        self.assertEqual((result.status, result.reviewed), ("REVIEW_ONLY", 32))
        self.assertFalse(result.authorized)

    def test_scope_overlap_detected_without_file_network_db_process_access(self):
        first, second = overlapping()
        with patch.object(socket, "socket", side_effect=AssertionError("network")), \\
             patch.object(sqlite3, "connect", side_effect=AssertionError("database")), \\
             patch.object(subprocess, "Popen", side_effect=AssertionError("process")), \\
             patch("builtins.open", side_effect=AssertionError("file")):
            self.assertEqual(review(first, second).status, "HOLD")


if __name__ == "__main__":
    unittest.main()
