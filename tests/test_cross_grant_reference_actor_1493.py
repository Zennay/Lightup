"""Issue #1493: fictional reference/actor coherence in a bounded cohort.

A reused *untrusted* reference cannot count as two different synthetic actors.
No live grant, identity, client, DNS, network, scan, handler or permission.
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
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.cross_grant_lineage_review_1493 import (
    CrossGrantCandidate, review_cross_grant_batch, review_cross_grant_lineage,
)
from lightup.engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from lightup.models import Authorization

_NOW = datetime(2020, 1, 1, 12, 0, tzinfo=timezone.utc)
_START, _END = _NOW - timedelta(minutes=30), _NOW + timedelta(minutes=30)


def claim(*, grant_id="G-1", asset="a.example.test",
          actor="reviewer@example.test", reference="SYNTH-REF-1"):
    old = Authorization(actor, reference, _START, _END)
    grant = AuthorizationGrant(
        grant_id, "CLIENT-1", "ENG-1", actor, reference,
        ScopeDefinition((asset,), RiskLevel.STANDARD, ("web-baseline",), ()),
        _START - timedelta(minutes=10), _END + timedelta(minutes=10),
    )
    return CrossGrantCandidate(
        old, grant, asset, "web-baseline", "CLIENT-1", "ENG-1",
        RiskLevel.LOW_IMPACT,
    )


def review(*records):
    return review_cross_grant_batch(tuple(records), evaluated_at=_NOW)


class ReferenceActorCoherenceTests(unittest.TestCase):
    def test_two_individually_matching_different_actors_remain_review_only_alone(self):
        one = claim()
        two = claim(grant_id="G-2", asset="b.example.test",
                    actor="other@example.test")
        self.assertEqual(review(one).status, "REVIEW_ONLY")
        self.assertEqual(review(two).status, "REVIEW_ONLY")

    def test_same_reference_different_actors_atomically_hold(self):
        a = claim()
        b = claim(grant_id="G-2", asset="b.example.test",
                  actor="other@example.test")
        outcome = review(a, b)
        self.assertEqual(
            (outcome.status, outcome.reason, outcome.reviewed),
            ("HOLD", "conflicting source-reference actor", 0),
        )
        self.assertFalse(outcome.consent_verified)
        self.assertFalse(outcome.dispatch_allowed)
        self.assertFalse(outcome.release_allowed)

    def test_different_actor_same_reference_reverse_order_is_hold(self):
        a = claim()
        b = claim(grant_id="G-2", asset="b.example.test",
                  actor="other@example.test")
        self.assertEqual(review(b, a).status, "HOLD")

    def test_three_record_permutations_preserve_reference_conflict(self):
        a = claim()
        b = claim(grant_id="G-2", asset="b.example.test",
                  actor="other@example.test")
        c = claim(grant_id="G-3", asset="c.example.test")
        for records in itertools.permutations((a, b, c)):
            result = review(*records)
            self.assertEqual((result.status, result.reviewed), ("HOLD", 0))

    def test_distinct_grants_same_actor_same_reference_stay_review_only(self):
        a = claim()
        b = claim(grant_id="G-2", asset="b.example.test")
        result = review(a, b)
        self.assertEqual((result.status, result.reviewed), ("REVIEW_ONLY", 2))
        self.assertFalse(result.authorized)
        self.assertFalse(result.release_allowed)

    def test_distinct_actor_with_distinct_reference_stays_review_only(self):
        a = claim()
        b = claim(grant_id="G-2", asset="b.example.test",
                  actor="other@example.test", reference="SYNTH-REF-2")
        result = review(a, b)
        self.assertEqual((result.status, result.reviewed), ("REVIEW_ONLY", 2))
        self.assertFalse(result.consent_verified)

    def test_case_alias_actor_on_one_reference_is_hold(self):
        a = claim()
        b = claim(grant_id="G-2", asset="b.example.test",
                  actor="Reviewer@example.test")
        self.assertEqual(review(a, b).status, "HOLD")

    def test_same_grant_id_changed_actor_stays_atomic_hold(self):
        a = claim()
        b = claim(grant_id="G-1", asset="b.example.test",
                  actor="other@example.test")
        self.assertEqual((review(a, b).status, review(a, b).reviewed),
                         ("HOLD", 0))

    def test_reference_actor_denial_does_not_mutate_input(self):
        a = claim()
        b = claim(grant_id="G-2", asset="b.example.test",
                  actor="other@example.test")
        before = (dataclasses.asdict(a), dataclasses.asdict(b))
        self.assertEqual(review(a, b).status, "HOLD")
        self.assertEqual((dataclasses.asdict(a), dataclasses.asdict(b)), before)

    def test_reference_actor_denial_makes_no_untrusted_io_calls(self):
        a = claim()
        b = claim(grant_id="G-2", asset="b.example.test",
                  actor="other@example.test")
        with ExitStack() as guards:
            guards.enter_context(patch.object(socket, "socket", side_effect=AssertionError))
            guards.enter_context(patch.object(sqlite3, "connect", side_effect=AssertionError))
            guards.enter_context(patch.object(subprocess, "Popen", side_effect=AssertionError))
            guards.enter_context(patch("builtins.open", side_effect=AssertionError))
            self.assertEqual(review(a, b).status, "HOLD")


if __name__ == "__main__":
    unittest.main()
