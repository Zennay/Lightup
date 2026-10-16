"""Issue #1511: constructor/instance/identity hardening, synthetic only."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, asdict
import builtins
import os
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lightup.fictional_lab_capability_review_1511 import (
    LabCapabilityReview1511,
    review_fictional_lab_capability_1511 as review,
)


class _EvilEq:
    def __eq__(self, other):
        raise AssertionError("untrusted __eq__ executed!")

    def __str__(self):
        raise AssertionError("untrusted __str__ executed!")


class _EvilString(str):
    def __eq__(self, other):
        raise AssertionError("untrusted str subclass equality executed!")

    def __hash__(self):
        raise AssertionError("untrusted str subclass hashing executed!")


class _StatusSubclass(str):
    pass


class FictionalCapabilitySealing1511Tests(unittest.TestCase):
    @staticmethod
    def assert_no_authority(value):
        assert type(value) is LabCapabilityReview1511
        assert value.status in ("HOLD", "REVIEW_ONLY")
        assert asdict(value) == {
            "status": value.status,
            "authorized": False,
            "consent_verified": False,
            "dispatch_allowed": False,
            "release_allowed": False,
        }

    def test_public_constructor_cannot_accept_authority_fields(self):
        for field in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            with self.subTest(field=field), self.assertRaises(TypeError):
                LabCapabilityReview1511("REVIEW_ONLY", **{field: True})
        with self.assertRaises(TypeError):
            LabCapabilityReview1511("HOLD", True)
        self.assert_no_authority(LabCapabilityReview1511("REVIEW_ONLY"))

    def test_constructor_rejects_invalid_and_spoofed_status(self):
        for status in (None, 0, True, b"HOLD", "AUTHORIZED", "GRANT", "",
                       "REVIEW_ONLY ", _StatusSubclass("HOLD"), _EvilEq()):
            with self.subTest(kind=type(status).__name__), self.assertRaises(ValueError):
                LabCapabilityReview1511(status)

    def test_result_instances_are_fresh_not_shared_singletons(self):
        for requested in ("web-baseline", "absent"):
            first = review(requested, ("web-baseline",))
            second = review(requested, ("web-baseline",))
            self.assertIsNot(first, second)
            self.assert_no_authority(first)
            self.assert_no_authority(second)

    def test_forced_instance_mutation_does_not_poison_later_result(self):
        first = review("web-baseline", ("web-baseline",))
        # Python dataclass frozen is not cryptographically sealed; even a
        # malicious local caller can mutate *its own* object with this escape.
        object.__setattr__(first, "authorized", True)
        object.__setattr__(first, "status", "AUTHORIZED")
        self.assertTrue(first.authorized)
        fresh = review("web-baseline", ("web-baseline",))
        self.assert_no_authority(fresh)
        self.assertEqual(fresh.status, "REVIEW_ONLY")
        hold = review("wrong", ("web-baseline",))
        self.assert_no_authority(hold)
        self.assertEqual(hold.status, "HOLD")

    def test_regular_mutation_still_raises(self):
        result = review("web-baseline", ("web-baseline",))
        for field, value in (("authorized", True), ("status", "GRANT")):
            with self.subTest(field=field), self.assertRaises(FrozenInstanceError):
                setattr(result, field, value)

    def test_poisoned_custom_value_methods_never_invoked(self):
        candidates = (
            (_EvilEq(), ("web-baseline",)),
            (_EvilString("web-baseline"), ("web-baseline",)),
            ("web-baseline", (_EvilEq(),)),
            ("web-baseline", (_EvilString("web-baseline"),)),
        )
        for requested, allowlist in candidates:
            with self.subTest(value=type(requested).__name__, scope_type=type(allowlist[0]).__name__):
                result = review(requested, allowlist)
                self.assertEqual(result.status, "HOLD")
                self.assert_no_authority(result)

    def test_no_file_socket_or_process_creation_in_pure_review(self):
        with patch.object(builtins, "open", side_effect=AssertionError("open forbidden")), \\
             patch.object(os, "open", side_effect=AssertionError("os.open forbidden")), \\
             patch.object(socket, "socket", side_effect=AssertionError("socket forbidden")):
            for requested in ("web-baseline", "missing", _EvilEq()):
                self.assert_no_authority(review(requested, ("web-baseline",)))

    def test_multiple_parallel_reviews_no_shared_state(self):
        inputs = ("web-baseline", "unknown") * 64
        with ThreadPoolExecutor(max_workers=8) as executor:
            results = tuple(executor.map(lambda item: review(item, ("web-baseline",)), inputs))
        self.assertEqual([r.status for r in results], [
            "REVIEW_ONLY" if item == "web-baseline" else "HOLD" for item in inputs
        ])
        self.assertEqual(len({id(r) for r in results}), len(results))
        for result in results:
            self.assert_no_authority(result)

    def test_valid_shape_never_is_real_attestation(self):
        for requested in ("web-baseline", "tls-baseline"):
            result = review(requested, ("web-baseline", "tls-baseline"))
            self.assertEqual(result.status, "REVIEW_ONLY")
            self.assert_no_authority(result)


if __name__ == "__main__":
    unittest.main()
