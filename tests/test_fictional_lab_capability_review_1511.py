"""Issue #1511: synthetic-only LAB capability ID regression matrix.

No sockets, subprocesses, DNS, handlers, or real customer authorization.
The expected failures describe the existing *unfixed* installed source.
"""
import os
import socket
import sys
import unittest
from dataclasses import FrozenInstanceError
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.activation import ActivationGate, ActivationMode, ActivationPolicy
from lightup.fictional_lab_capability_review_1511 import (
    LabCapabilityReview1511,
    review_fictional_lab_capability_1511 as review,
)
from lightup.models import Target
from lightup.scope import ScopePolicy


class _ClaimingString(str):
    def __eq__(self, other):
        return True

    __hash__ = str.__hash__


class _ClaimingObject:
    def __eq__(self, other):
        return True


class _ClaimingTuple(tuple):
    def __contains__(self, other):
        return True


class FictionalLabCapabilityReview1511Tests(unittest.TestCase):
    def assert_not_authority(self, result):
        self.assertIs(type(result), LabCapabilityReview1511)
        self.assertIn(result.status, ("HOLD", "REVIEW_ONLY"))
        self.assertIs(result.authorized, False)
        self.assertIs(result.consent_verified, False)
        self.assertIs(result.dispatch_allowed, False)
        self.assertIs(result.release_allowed, False)

    def test_valid_fictional_review_is_never_authorizing(self):
        result = review("web-baseline", ("web-baseline", "tls-baseline"))
        self.assertEqual(result.status, "REVIEW_ONLY")
        self.assert_not_authority(result)

    def test_absent_from_allowlist_fails_closed(self):
        self.assertEqual(review("tls-baseline", ("web-baseline",)).status, "HOLD")

    def test_noncanonical_requested_ids_hold(self):
        invalid = (
            "", " ", "web baseline", "web--baseline", "web-", "-web",
            "Web-baseline", "web_baseline", "web.baseline", "web/baseline",
            "web:baseline", "web\\nbaseline", "web\nbaseline", "é", "ｗｅｂ",
            "\u200bweb", "web\x00baseline", "a" * 65,
            None, False, True, 0, b"web-baseline",
            _ClaimingString("web-baseline"), _ClaimingObject(),
        )
        for candidate in invalid:
            with self.subTest(candidate_type=type(candidate).__name__):
                result = review(candidate, ("web-baseline",))
                self.assertEqual(result.status, "HOLD")
                self.assert_not_authority(result)

    def test_allowlist_identity_and_shape_hold(self):
        invalid = (
            None, (), [], ["web-baseline"], ("web-baseline", "web-baseline"),
            (_ClaimingString("web-baseline"),), (_ClaimingObject(),),
            ("web-baseline", None), ("web-baseline", "NOT_CANONICAL"),
            _ClaimingTuple(("web-baseline",)),
            tuple("key-" + str(i) for i in range(65)),
        )
        for allowlist in invalid:
            with self.subTest(allowlist_type=type(allowlist).__name__):
                result = review("web-baseline", allowlist)
                self.assertEqual(result.status, "HOLD")
                self.assert_not_authority(result)

    def test_no_io_even_with_hostile_objects(self):
        with patch.object(socket, "socket", side_effect=AssertionError("socket forbidden")) as s:
            for value in ("web-baseline", _ClaimingObject(), _ClaimingString("web-baseline")):
                self.assert_not_authority(review(value, ("web-baseline",)))
            s.assert_not_called()

    def test_frozen_result_cannot_promote_authority(self):
        result = review("web-baseline", ("web-baseline",))
        with self.assertRaises(FrozenInstanceError):
            result.authorized = True
        with self.assertRaises(FrozenInstanceError):
            result.status = "AUTHORIZED"

    def test_caller_data_is_unchanged(self):
        allowlist = ("web-baseline", "tls-baseline")
        original = tuple(allowlist)
        review("web-baseline", allowlist)
        self.assertEqual(allowlist, original)

    def test_empty_scope_does_not_authorize(self):
        self.assertEqual(review("web-baseline", ()).status, "HOLD")

    def test_boundary_at_64_bytes_and_64_entries(self):
        good_id = "a" * 64
        ids = tuple("a" + str(i) for i in range(63)) + (good_id,)
        self.assertEqual(review(good_id, ids).status, "REVIEW_ONLY")
        self.assertEqual(review("a" * 65, ("a" * 65,)).status, "HOLD")

    @unittest.expectedFailure
    def test_installed_lab_gate_rejects_blank_capability_red(self):
        # RED, not a fix: current original runtime issues this permit.
        gate = ActivationGate(
            ScopePolicy(),
            ActivationPolicy(mode=ActivationMode.LAB_ONLY, activation_reference="LAB-TEST"),
        )
        with self.assertRaises((PermissionError, ValueError)):
            gate.issue(Target("127.0.0.1"), " ")

    @unittest.expectedFailure
    def test_installed_lab_gate_rejects_polymorphic_capability_red(self):
        gate = ActivationGate(
            ScopePolicy(),
            ActivationPolicy(mode=ActivationMode.LAB_ONLY, activation_reference="LAB-TEST"),
        )
        with self.assertRaises((PermissionError, ValueError, TypeError)):
            gate.issue(Target("127.0.0.1"), _ClaimingObject())


if __name__ == "__main__":
    unittest.main()
