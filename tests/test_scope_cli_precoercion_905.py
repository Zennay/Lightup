"""#905: no attacker-controlled truthiness evaluation at CLI policy boundary.

Additive source-owner acceptance only; no parser changes or target I/O.
"""
from __future__ import annotations

import argparse
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.cli import _policy
from lightup.models import Target


BOOL_CALLS: list[str] = []


def namespace(marker: object) -> argparse.Namespace:
    return argparse.Namespace(
        allow_private_lab=marker,
        allow_host=[],
        allow_cidr=[],
        no_private_lab=False,
    )


class LoggingTruthy:
    def __bool__(self) -> bool:
        BOOL_CALLS.append("untrusted-bool")
        return True


class ThrowingTruthy:
    def __bool__(self) -> bool:
        BOOL_CALLS.append("throwing-bool")
        raise RuntimeError("caller-controlled __bool__ executed")


class MarkerPrecoercionSourceRED905(unittest.TestCase):
    def setUp(self) -> None:
        BOOL_CALLS.clear()

    def tearDown(self) -> None:
        BOOL_CALLS.clear()

    def test_exact_false_never_invokes_foreign_truthiness(self) -> None:
        args = namespace(False)
        policy = _policy(args)
        self.assertFalse(policy.decide(Target("10.20.30.40")).allowed)
        self.assertEqual(BOOL_CALLS, [])

    def test_exact_true_never_invokes_foreign_truthiness(self) -> None:
        args = namespace(True)
        policy = _policy(args)
        self.assertTrue(policy.decide(Target("10.20.30.40")).allowed)
        self.assertEqual(BOOL_CALLS, [])

    @unittest.expectedFailure
    def test_logging_truthy_rejected_before_bool_invocation(self) -> None:
        marker = LoggingTruthy()
        args = namespace(marker)
        with self.assertRaises(ValueError):
            _policy(args)
        self.assertEqual(BOOL_CALLS, [])
        self.assertIs(args.allow_private_lab, marker)

    @unittest.expectedFailure
    def test_throwing_truthy_rejected_before_bool_invocation(self) -> None:
        marker = ThrowingTruthy()
        args = namespace(marker)
        with self.assertRaises(ValueError):
            _policy(args)
        self.assertEqual(BOOL_CALLS, [])
        self.assertIs(args.allow_private_lab, marker)


if __name__ == "__main__":
    unittest.main()
