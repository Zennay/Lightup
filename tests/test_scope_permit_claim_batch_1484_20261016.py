"""Synthetic-only, offline tests for LightUp #1484; no handler or target IO."""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
import socket
import sqlite3
import subprocess
import unittest
from unittest.mock import patch

from lightup.activation import ActivationMode, ExecutionPermit
from lightup.permit_claim_review_1484 import (
    PermitClaimReview, review_fictional_permit_claim_batch,
)

CUTOFF = datetime(2026, 10, 16, 10, 0, tzinfo=timezone.utc)
STAMP = datetime(2026, 10, 16, 9, 59, tzinfo=timezone.utc)

def make_permit(**changes: object) -> ExecutionPermit:
    values = dict(permit_id="a" * 32, target="localhost", capability_id="lab.review",
                  mode=ActivationMode.LAB_ONLY, activation_reference="LAB",
                  issued_at=STAMP)
    values.update(changes)
    return ExecutionPermit(**values)

def review(*claims: ExecutionPermit, cutoff: object = CUTOFF) -> PermitClaimReview:
    return review_fictional_permit_claim_batch(tuple(claims), review_cutoff=cutoff)


class ScopePermitClaimBatch1484Tests(unittest.TestCase):
    def assertHold(self, outcome: PermitClaimReview, reason: str | None = None):
        self.assertEqual(outcome.status, "HOLD")
        self.assertEqual(outcome.inspected, 0)
        self.assertFalse(outcome.execution_allowed)
        self.assertFalse(outcome.release_allowed)
        if reason is not None:
            self.assertEqual(outcome.reason_code, reason)

    def test_synthetic_lab_shape_never_authorizes(self):
        self.assertEqual(review(make_permit()),
                         PermitClaimReview("REVIEW_ONLY", "fictional_shape_only", 1))

    def test_fictional_public_claim_never_authorizes(self):
        result = review(make_permit(target="review.example.test",
                                    mode=ActivationMode.AUTHORIZED,
                                    activation_reference="FAKE_123"))
        self.assertEqual(result.status, "REVIEW_ONLY")
        self.assertIs(result.execution_allowed, False)
        self.assertIs(result.release_allowed, False)

    def test_distinct_id_cohort(self):
        self.assertEqual(review(make_permit(), make_permit(
            permit_id="b" * 32, target="lab.example.test")).inspected, 2)

    def test_duplicate_id_atomic_hold(self):
        self.assertHold(review(make_permit(), make_permit(
            target="other.example.test")), "duplicate_in_batch")

    def test_duplicate_after_distinct_rejects_entire_batch(self):
        self.assertHold(review(make_permit(), make_permit(permit_id="b" * 32),
                               make_permit(target="later.example.test")),
                        "duplicate_in_batch")

    def test_empty_and_oversized_batch(self):
        self.assertHold(review(), "invalid_batch")
        many = tuple(make_permit(permit_id=f"{i:032d}") for i in range(65))
        self.assertHold(review(*many), "invalid_batch")

    def test_exact_limit_64(self):
        claims = tuple(make_permit(permit_id=f"{i:032d}") for i in range(64))
        self.assertEqual(review(*claims).inspected, 64)

    def test_generator_cannot_execute_callback(self):
        class Spy:
            def __iter__(self):
                raise AssertionError("unexpected iteration")
        self.assertHold(review_fictional_permit_claim_batch(
            Spy(), review_cutoff=CUTOFF), "invalid_batch")
        self.assertHold(review_fictional_permit_claim_batch(
            [make_permit()], review_cutoff=CUTOFF), "invalid_batch")

    def test_tuple_subclass_rejected(self):
        class NotTuple(tuple):
            pass
        self.assertHold(review_fictional_permit_claim_batch(
            NotTuple((make_permit(),)), review_cutoff=CUTOFF), "invalid_batch")

    def test_permit_subclass_is_not_inspected(self):
        class Forged(ExecutionPermit):
            @property
            def permit_id(self):
                raise AssertionError("do not access subclass property")
        self.assertHold(review(object.__new__(Forged)), "invalid_claim")

    def test_polymorphic_string_fields_rejected_without_coercion(self):
        class Polymorphic(str):
            def __str__(self):
                raise AssertionError("untrusted str must never run")
        original = make_permit()
        for key in ("permit_id", "target", "capability_id", "activation_reference"):
            with self.subTest(key=key):
                self.assertHold(review(make_permit(**{
                    key: Polymorphic(getattr(original, key))
                })), "invalid_claim")

    def test_token_id_shape_strict(self):
        for bad in ("", "x" * 31, "x" * 33, "x" * 31 + "=",
                    "x" * 31 + "\n"):
            with self.subTest(bad=repr(bad)):
                self.assertHold(review(make_permit(permit_id=bad)), "invalid_claim")

    def test_capability_reference_noncanonical(self):
        for bad in ("", " ", "\x00", "lab\nreview", "a" * 65, "With Caps"):
            with self.subTest(bad=repr(bad)):
                self.assertHold(review(make_permit(capability_id=bad)), "invalid_claim")
        for bad in ("", "  ", "\nA", "x" * 129):
            self.assertHold(review(make_permit(activation_reference=bad)),
                            "invalid_claim")

    def test_nonfictional_or_alias_target(self):
        for bad in ("real.com", "LOCALHOST", "127.0.0.2",
                    "http://localhost", "foo.example.test:443",
                    "foo.example.test.", "u@foo.example.test",
                    "", "example.test", "foo..example.test"):
            with self.subTest(target=bad):
                self.assertHold(review(make_permit(target=bad)), "invalid_claim")

    def test_unrecognized_mode_and_plan_only(self):
        for bad in ("lab_only", True, None, ActivationMode.PLAN_ONLY):
            with self.subTest(type=type(bad).__name__):
                self.assertHold(review(make_permit(mode=bad)), "invalid_claim")

    def test_naive_offset_datetime_subclass_and_text(self):
        class Child(datetime):
            pass
        for bad in (STAMP.replace(tzinfo=None),
                    STAMP.astimezone(timezone(timedelta(hours=2))),
                    Child(2026, 10, 16, 9, 59, tzinfo=timezone.utc),
                    "2026-10-16T09:59:00Z"):
            self.assertHold(review(make_permit(issued_at=bad)), "invalid_claim")

    def test_future_claim_microseconds_and_equal_cutoff(self):
        self.assertHold(review(make_permit(issued_at=CUTOFF + timedelta(
            microseconds=1))), "future_claim")
        self.assertEqual(review(make_permit(issued_at=CUTOFF)).status,
                         "REVIEW_ONLY")

    def test_non_exact_utc_cutoff(self):
        for bad in (None, False, "now", CUTOFF.replace(tzinfo=None),
                    CUTOFF.astimezone(timezone(timedelta(hours=-4)))):
            self.assertHold(review(make_permit(), cutoff=bad), "invalid_cutoff")

    def test_no_network_database_process_or_scan(self):
        with patch.object(socket, "socket", side_effect=AssertionError("socket")), \
             patch.object(socket, "getaddrinfo", side_effect=AssertionError("dns")), \
             patch.object(sqlite3, "connect", side_effect=AssertionError("sqlite")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process")):
            self.assertEqual(review(make_permit()).status, "REVIEW_ONLY")
            self.assertHold(review(make_permit(), make_permit()),
                            "duplicate_in_batch")

    def test_review_object_does_not_carry_executable_permission(self):
        result = review(make_permit())
        self.assertEqual(result.__dict__["execution_allowed"], False)
        self.assertEqual(result.__dict__["release_allowed"], False)
        self.assertFalse(hasattr(result, "permit"))
        self.assertFalse(hasattr(result, "authorized"))
        self.assertFalse(hasattr(result, "approved"))


if __name__ == "__main__":
    unittest.main()
