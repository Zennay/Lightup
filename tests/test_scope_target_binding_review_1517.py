"""Unwired synthetic #1517 scope-target binding review + original source RED.

No network target, DNS lookup, active handler, grant or release.
"""
import dataclasses
import pathlib
import socket
import subprocess
import unittest
from unittest.mock import patch

from lightup.activation import ActivationGate, ActivationMode, ActivationPolicy
from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy
from lightup.scope_target_binding_review_1517 import (
    BindingReview1517, review_target_binding_1517, review_target_binding_batch_1517,
)

A = ("case.example.test", "owner-alpha", "grant-alpha", 7)
B = ("case.example.test", "owner-beta", "grant-beta", 7)


class ForgedTuple(tuple):
    pass


class ForgedString(str):
    def __eq__(self, other):
        raise AssertionError("untrusted equality reached")


class TargetBindingReview1517Tests(unittest.TestCase):
    def test_stable_exact_fictional_record_review_only(self):
        receipt = review_target_binding_1517(A, tuple(A))
        self.assertEqual(receipt.status, "REVIEW_ONLY")
        for name in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            self.assertIs(getattr(receipt, name), False)

    def test_changes_in_every_identity_field_hold(self):
        variations = (
            ("other.example.test", A[1], A[2], A[3]),
            (A[0], "owner-beta", A[2], A[3]),
            (A[0], A[1], "grant-beta", A[3]),
            (A[0], A[1], A[2], 8),
        )
        for value in variations:
            with self.subTest(value=value):
                self.assertEqual(review_target_binding_1517(A, value).status, "HOLD")
                self.assertEqual(review_target_binding_1517(value, A).status, "HOLD")

    def test_rejects_type_confusion_without_polymorphic_comparison(self):
        hostile = (
            list(A), ForgedTuple(A), (ForgedString(A[0]), *A[1:]),
            (A[0], ForgedString(A[1]), A[2], A[3]),
            (A[0], A[1], ForgedString(A[2]), A[3]),
            (A[0], A[1], A[2], True),
            (A[0], A[1], A[2], 7.0),
            (A[0], A[1], A[2], 2**31),
            (A[0], A[1], A[2], 0), None, (),
            ("case.example.test", "owner-alpha", "grant-alpha"),
        )
        for value in hostile:
            with self.subTest(type=type(value).__name__):
                self.assertEqual(review_target_binding_1517(value, A).status, "HOLD")
                self.assertEqual(review_target_binding_1517(A, value).status, "HOLD")

    def test_rejects_real_public_or_noncanonical_assets(self):
        for asset in ("example.com", "127.0.0.1", "Case.example.test",
                      "case.example.test.", "case.example.test@evil.com",
                      "case.example.test\u202e", "case..example.test", "",
                      "a" * 70 + ".example.test", "localhost", "case.example.test\n"):
            with self.subTest(asset=repr(asset)):
                self.assertEqual(review_target_binding_1517(A, (asset, *A[1:])).status, "HOLD")

    def test_rejects_unknown_owner_or_grant_spelling(self):
        for record in (
            (A[0], "", A[2], A[3]),
            (A[0], "OWNER-alpha", A[2], A[3]),
            (A[0], A[1], "grant_foo", A[3]),
            (A[0], A[1], "", A[3]),
            (A[0], "owner-" + "a"*21, A[2], A[3]),
            (A[0], A[1], "grant-" + "a"*25, A[3]),
        ):
            self.assertEqual(review_target_binding_1517(A, record).status, "HOLD")

    def test_all_receipts_always_hardcode_false_authority(self):
        for value in (A, B, None):
            for receipt in (review_target_binding_1517(A, value),
                            review_target_binding_1517(value, A)):
                self.assertEqual(tuple(getattr(receipt, k) for k in
                    ("authorized", "consent_verified", "dispatch_allowed",
                     "release_allowed")), (False, False, False, False))
                self.assertNotIn("example.test", repr(receipt))

    def test_sealed_receipt_disallows_affirmative_init(self):
        with self.assertRaises((TypeError, ValueError)):
            BindingReview1517("REVIEW_ONLY", authorized=True)
        with self.assertRaises(ValueError):
            BindingReview1517("AUTHORIZED")
        with self.assertRaises((TypeError, ValueError)):
            BindingReview1517(True)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            review_target_binding_1517(A, A).authorized = True

    def test_fresh_receipts_do_not_share_mutable_authority_state(self):
        poisoned = review_target_binding_1517(A, A)
        object.__setattr__(poisoned, "authorized", True)
        clean = review_target_binding_1517(A, A)
        self.assertIsNot(clean, poisoned)
        self.assertIs(clean.authorized, False)

    def test_input_immutability_no_io(self):
        original = (A, B)
        with patch("builtins.open", side_effect=AssertionError("file I/O")), \
             patch.object(socket, "socket", side_effect=AssertionError("network")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process")), \
             patch.object(pathlib.Path, "open", side_effect=AssertionError("path I/O")):
            self.assertEqual(review_target_binding_1517(*original).status, "HOLD")
            self.assertEqual(review_target_binding_1517(A, A).status, "REVIEW_ONLY")
        self.assertEqual(original, (A, B))

    def test_current_source_stable_synthetic_target_positive(self):
        target = Target("case.example.test", Authorization("owner-alpha", "grant-alpha"))
        scope = ScopePolicy(explicit_hosts=frozenset({"case.example.test"}))
        gate = ActivationGate(scope, ActivationPolicy(ActivationMode.AUTHORIZED, "synthetic"))
        with patch("lightup.activation.token_urlsafe", return_value="offline-fixture"):
            permit = gate.issue(target, "synthetic-capability")
        self.assertEqual(permit.target, "case.example.test")
        self.assertEqual(permit.permit_id, "offline-fixture")
        self.assertEqual(target.authorization.reference, "grant-alpha")

    @unittest.expectedFailure
    def test_source_red_reject_target_authorization_rebinding_between_decision_and_issue(self):
        """ORIGINAL SOURCE RED: never interpret expectedFailure as remediation.

        Force a local-only post-decision target rebind to prove that a current
        *different* authorization can be accepted after the original decision.
        The expected strict binding rejection is not yet implemented upstream.
        """
        target = Target("case.example.test", Authorization("owner-alpha", "grant-alpha"))
        scope = ScopePolicy(explicit_hosts=frozenset({"case.example.test"}))
        gate = ActivationGate(scope, ActivationPolicy(ActivationMode.AUTHORIZED, "synthetic"))
        original_decide = ScopePolicy.decide

        def rebind_after_decide(self, supplied):
            decision = original_decide(self, supplied)
            object.__setattr__(supplied, "authorization", Authorization("owner-beta", "grant-beta"))
            return decision

        with patch.object(ScopePolicy, "decide", rebind_after_decide), \
             patch("lightup.activation.token_urlsafe", return_value="offline-fixture"):
            with self.assertRaises(PermissionError):
                gate.issue(target, "synthetic-capability")

    def test_atomic_batch_all_distinct_fictional_records(self):
        records = tuple(
            ((f"case{i}.example.test", f"owner-{i}", f"grant-{i}", i + 1),) * 2
            for i in range(64)
        )
        result = review_target_binding_batch_1517(records)
        self.assertEqual(result.status, "REVIEW_ONLY")
        self.assertIs(result.authorized, False)
        self.assertIs(result.consent_verified, False)
        self.assertIs(result.dispatch_allowed, False)
        self.assertIs(result.release_allowed, False)
        self.assertEqual(len(records), 64)

    def test_atomic_batch_rejects_all_one_position_drifts(self):
        good = tuple(
            ((f"case{i}.example.test", f"owner-{i}", f"grant-{i}", i + 1),) * 2
            for i in range(12)
        )
        for position in range(len(good)):
            for field in range(4):
                changed = list(good[position][1])
                changed[field] = (f"other{position}.example.test" if field == 0
                                  else f"owner-other{position}" if field == 1
                                  else f"grant-other{position}" if field == 2
                                  else 123456)
                candidate = list(good)
                candidate[position] = (good[position][0], tuple(changed))
                with self.subTest(position=position, field=field):
                    self.assertEqual(review_target_binding_batch_1517(tuple(candidate)).status, "HOLD")

    def test_atomic_batch_rejects_duplicates_and_ambiguous_grants(self):
        one = (A, A)
        duplicate_asset = ((A[0], "owner-beta", "grant-beta", 9),) * 2
        duplicate_grant = (("other.example.test", "owner-beta", A[2], 9),) * 2
        for value in ((one, one), (one, duplicate_asset), (one, duplicate_grant)):
            self.assertEqual(review_target_binding_batch_1517(value).status, "HOLD")
        self.assertEqual(review_target_binding_batch_1517((one,)).status, "REVIEW_ONLY")

    def test_atomic_batch_bounded_polymorphic_and_empty(self):
        item = (A, A)
        for value in ([], (), (item,) * 65, [item], ForgedTuple((item,)),
                      ((A, B),), ((A,),), (list(item),), (ForgedTuple(item),),
                      ((ForgedTuple(A), A),), ((A, (A[0], A[1], A[2], True)),)):
            self.assertEqual(review_target_binding_batch_1517(value).status, "HOLD")

    def test_batch_no_io_and_no_echo(self):
        item = (A, A)
        with patch("builtins.open", side_effect=AssertionError("file I/O")), \
             patch.object(socket, "socket", side_effect=AssertionError("network")), \
             patch.object(subprocess, "Popen", side_effect=AssertionError("process")):
            self.assertEqual(review_target_binding_batch_1517((item,)).status, "REVIEW_ONLY")
            bad = review_target_binding_batch_1517(((A, B),))
            self.assertEqual(bad.status, "HOLD")
            self.assertNotIn("example.test", repr(bad))


if __name__ == "__main__":
    unittest.main()
