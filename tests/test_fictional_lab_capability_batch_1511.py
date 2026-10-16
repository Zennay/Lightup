"""#1511 pure all-or-HOLD fictional LAB capability cohort acceptance."""
from dataclasses import asdict
import builtins
import os
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lightup.fictional_lab_capability_batch_1511 import (
    review_fictional_lab_capability_cohort_1511 as batch,
)
from lightup.fictional_lab_capability_review_1511 import (
    LabCapabilityReview1511,
    review_fictional_lab_capability_1511 as single,
)


class _SpyingId:
    def __eq__(self, other):
        raise AssertionError("untrusted equality")

    def __hash__(self):
        raise AssertionError("untrusted hash")

    def __str__(self):
        raise AssertionError("untrusted __str__")


class _SpoofedStr(str):
    def __eq__(self, other):
        raise AssertionError("subclass comparison")

    __hash__ = str.__hash__


class _SpoofedTuple(tuple):
    def __contains__(self, value):
        return True

    def __iter__(self):
        raise AssertionError("subclass iteration")


class FictionalLabCapabilityCohort1511Tests(unittest.TestCase):
    def assert_non_authority(self, result, expected):
        self.assertIs(type(result), LabCapabilityReview1511)
        self.assertEqual(asdict(result), {
            "status": expected,
            "authorized": False,
            "consent_verified": False,
            "dispatch_allowed": False,
            "release_allowed": False,
        })

    def test_valid_cohort_is_only_non_authorizing_review(self):
        self.assert_non_authority(
            batch(("web-baseline", "tls-baseline"), ("tls-baseline", "web-baseline")),
            "REVIEW_ONLY",
        )

    def test_single_item_in_fake_cohort_matches_single_review_status(self):
        allow = ("web-baseline", "tls-baseline")
        for item in ("web-baseline", "tls-baseline", "missing", "Web-baseline", ""):
            self.assertEqual(batch((item,), allow).status, single(item, allow).status)
            self.assert_non_authority(batch((item,), allow), single(item, allow).status)

    def test_missing_identity_causes_atomic_hold_not_partial_acceptance(self):
        for requested in (
            ("web-baseline", "missing"), ("missing", "web-baseline"),
            ("web-baseline", "tls-baseline", "missing"),
        ):
            self.assert_non_authority(batch(requested, ("web-baseline", "tls-baseline")), "HOLD")

    def test_duplicate_candidates_cause_hold(self):
        for requested in (
            ("web-baseline", "web-baseline"),
            ("web-baseline", "tls-baseline", "web-baseline"),
        ):
            self.assert_non_authority(batch(requested, ("web-baseline", "tls-baseline")), "HOLD")

    def test_duplicate_fake_allowlist_causes_hold_even_when_request_unique(self):
        self.assert_non_authority(batch(("web-baseline",),
                                       ("web-baseline", "web-baseline")), "HOLD")

    def test_exact_builtin_container_types_only(self):
        for requested, fake_scope in (
            ([], ("web-baseline",)),
            (("web-baseline",), ["web-baseline"]),
            (_SpoofedTuple(("web-baseline",)), ("web-baseline",)),
            (("web-baseline",), _SpoofedTuple(("web-baseline",))),
            (None, ("web-baseline",)), (("web-baseline",), None),
            (b"web-baseline", ("web-baseline",)),
        ):
            self.assert_non_authority(batch(requested, fake_scope), "HOLD")

    def test_identity_polymorphism_fails_before_poisoned_equality(self):
        for requested, fake_scope in (
            ((_SpyingId(),), ("web-baseline",)),
            (("web-baseline",), (_SpyingId(),)),
            ((_SpoofedStr("web-baseline"),), ("web-baseline",)),
            (("web-baseline",), (_SpoofedStr("web-baseline"),)),
        ):
            self.assert_non_authority(batch(requested, fake_scope), "HOLD")

    def test_noncanonical_types_hold_without_string_coercion(self):
        for token in (
            None, 7, True, 0.0, b"web-baseline", "", " ", "web baseline",
            "Web-baseline", "web--baseline", "web_baseline", "web/", "w\x00eb",
            "a" * 65, "é", "ｗｅｂ", "\u200bweb",
        ):
            with self.subTest(type=type(token).__name__):
                self.assert_non_authority(batch(("web-baseline", token),
                                                ("web-baseline",)), "HOLD")

    def test_atomic_validation_every_position_at_upper_bound(self):
        universe = tuple("a" + str(i) for i in range(64))
        self.assert_non_authority(batch(universe, universe[::-1]), "REVIEW_ONLY")
        self.assert_non_authority(batch(universe[:63], universe), "REVIEW_ONLY")
        for index in range(64):
            broken = universe[:index] + ("missing",) + universe[index + 1:]
            self.assert_non_authority(batch(broken, universe), "HOLD")
            spoof = universe[:index] + (_SpyingId(),) + universe[index + 1:]
            self.assert_non_authority(batch(spoof, universe), "HOLD")
            doubled = universe[:index] + (universe[(index + 1) % 64],) + universe[index + 1:]
            self.assert_non_authority(batch(doubled, universe), "HOLD")

    def test_65_candidate_and_65_scope_ids_hold(self):
        allow = tuple("a" + str(i) for i in range(64))
        too_many = allow + ("a64",)
        self.assert_non_authority(batch(too_many, allow), "HOLD")
        self.assert_non_authority(batch(allow, too_many), "HOLD")
        self.assert_non_authority(batch((), allow), "HOLD")
        self.assert_non_authority(batch(("a0",), ()), "HOLD")

    def test_input_purity_no_mutations_or_network(self):
        requested = ("web-baseline", "tls-baseline")
        scope = ("tls-baseline", "web-baseline")
        before = (requested[:], scope[:])
        with (
            patch.object(builtins, "open", side_effect=AssertionError("no open")),
            patch.object(os, "open", side_effect=AssertionError("no os.open")),
            patch.object(socket, "socket", side_effect=AssertionError("no socket")),
        ):
            self.assert_non_authority(batch(requested, scope), "REVIEW_ONLY")
        self.assertEqual((requested, scope), before)

    def test_independent_results_even_after_forced_instance_mutation(self):
        r1 = batch(("web-baseline",), ("web-baseline",))
        object.__setattr__(r1, "release_allowed", True)
        r2 = batch(("web-baseline",), ("web-baseline",))
        self.assertIsNot(r1, r2)
        self.assert_non_authority(r2, "REVIEW_ONLY")
        self.assert_non_authority(batch(("missing",), ("web-baseline",)), "HOLD")


if __name__ == "__main__":
    unittest.main()
