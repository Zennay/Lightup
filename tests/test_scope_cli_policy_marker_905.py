"""Offline source-owner acceptance for issue #905 (PR #100).

Only exercises policy construction and in-memory decisions. Expected failures
are deliberately RED on the unchanged source-owner head; they do not authorize
a target, and must become ordinary passing tests after the owner fixes _policy.
"""
from __future__ import annotations

import argparse
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.cli import _policy, build_parser
from lightup.models import Target
from lightup.scope import ScopeReason


LAB_HOST = "10.20.30.40"


def namespace(marker: object) -> argparse.Namespace:
    return argparse.Namespace(
        allow_private_lab=marker,
        allow_host=[],
        allow_cidr=[],
        no_private_lab=False,
    )


class TruthyNonBoolean:
    def __bool__(self) -> bool:
        return True


class PolicyMarkerPositiveControls905(unittest.TestCase):
    def test_false_is_exact_bool_and_denies_private_host(self) -> None:
        args = namespace(False)
        policy = _policy(args)
        decision = policy.decide(Target(LAB_HOST))
        self.assertIs(type(args.allow_private_lab), bool)
        self.assertIs(policy.allow_private_lab, False)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_true_is_exact_bool_and_allows_private_lab_only(self) -> None:
        args = namespace(True)
        policy = _policy(args)
        decision = policy.decide(Target(LAB_HOST))
        self.assertIs(policy.allow_private_lab, True)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.PRIVATE_LAB)
        self.assertFalse(policy.decide(Target("8.8.8.8")).allowed)

    def test_argparse_default_marker_is_canonical_false(self) -> None:
        args = build_parser().parse_args(["scope-check", LAB_HOST])
        self.assertIs(type(args.allow_private_lab), bool)
        self.assertIs(args.allow_private_lab, False)
        self.assertFalse(_policy(args).decide(Target(LAB_HOST)).allowed)

    def test_argparse_opt_in_is_canonical_true(self) -> None:
        args = build_parser().parse_args(
            ["scope-check", "--allow-private-lab", LAB_HOST]
        )
        self.assertIs(type(args.allow_private_lab), bool)
        self.assertIs(args.allow_private_lab, True)
        self.assertTrue(_policy(args).decide(Target(LAB_HOST)).allowed)

    def test_exact_bool_marker_never_mutates_caller_namespace(self) -> None:
        args = namespace(True)
        before = dict(vars(args))
        _policy(args)
        self.assertEqual(vars(args), before)
        self.assertIs(args.allow_private_lab, True)


class PolicyMarkerSourceOwnerRED905(unittest.TestCase):
    """Each expectedFailure is a pending source-owner denial requirement."""

    def require_rejection(self, marker: object) -> None:
        args = namespace(marker)
        original = marker
        with self.assertRaises(ValueError):
            _policy(args)
        self.assertIs(args.allow_private_lab, original)

    @unittest.expectedFailure
    def test_truthy_string_false_must_not_enable_lab(self) -> None:
        self.require_rejection("false")

    @unittest.expectedFailure
    def test_truthy_string_zero_must_not_enable_lab(self) -> None:
        self.require_rejection("0")

    @unittest.expectedFailure
    def test_truthy_integer_must_not_enable_lab(self) -> None:
        self.require_rejection(1)

    @unittest.expectedFailure
    def test_falsy_integer_must_be_rejected(self) -> None:
        self.require_rejection(0)

    @unittest.expectedFailure
    def test_none_must_be_rejected(self) -> None:
        self.require_rejection(None)

    @unittest.expectedFailure
    def test_boolean_like_object_must_be_rejected(self) -> None:
        self.require_rejection(TruthyNonBoolean())


if __name__ == "__main__":
    unittest.main()
