"""#905: exact private-lab CLI marker contract on pinned #100 source owner.

Synthetic argument inspection only, no live targets, DNS, HTTP or capabilities.
Expected failures prove a default-source coercion gap pending original owner.
"""
from __future__ import annotations

import argparse
import unittest

from lightup.cli import _policy, build_parser
from lightup.models import Target
from lightup.scope import ScopeReason


class StatefulTruthy:
    def __bool__(self):
        return True


class PrivateLabCliTypeIssue905(unittest.TestCase):
    @staticmethod
    def arguments(value):
        return argparse.Namespace(
            allow_private_lab=value, allow_host=[], allow_cidr=[],
        )

    def test_exact_false_denies_unlisted_private_address(self):
        policy = _policy(self.arguments(False))
        self.assertIs(policy.allow_private_lab, False)
        decision = policy.decide(Target("10.20.30.40"))
        self.assertFalse(decision.allowed)
        self.assertIs(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_exact_true_allows_explicit_private_lab(self):
        policy = _policy(self.arguments(True))
        self.assertIs(policy.allow_private_lab, True)
        decision = policy.decide(Target("10.20.30.40"))
        self.assertTrue(decision.allowed)
        self.assertIs(decision.reason, ScopeReason.PRIVATE_LAB)

    def test_argparse_default_is_exact_false(self):
        parsed = build_parser().parse_args(["scope-check", "10.20.30.40"])
        self.assertIs(type(parsed.allow_private_lab), bool)
        self.assertIs(parsed.allow_private_lab, False)
        self.assertFalse(_policy(parsed).allow_private_lab)

    def test_argparse_optin_is_exact_true(self):
        parsed = build_parser().parse_args([
            "scope-check", "10.20.30.40", "--allow-private-lab",
        ])
        self.assertIs(type(parsed.allow_private_lab), bool)
        self.assertIs(parsed.allow_private_lab, True)
        self.assertTrue(_policy(parsed).allow_private_lab)

    def test_argparse_no_private_lab_preserves_denial(self):
        parsed = build_parser().parse_args([
            "scope-check", "10.20.30.40", "--no-private-lab",
        ])
        self.assertIs(parsed.allow_private_lab, False)
        self.assertFalse(_policy(parsed).allow_private_lab)

    def test_argparse_conflicting_flags_rejected_before_policy(self):
        with self.assertRaises(SystemExit):
            build_parser().parse_args([
                "scope-check", "10.20.30.40",
                "--allow-private-lab", "--no-private-lab",
            ])

    @unittest.expectedFailure
    def test_red_truthy_false_string_not_coerced_to_private_lab_authority(self):
        with self.assertRaises(ValueError):
            _policy(self.arguments("false"))

    @unittest.expectedFailure
    def test_red_integer_one_not_coerced_to_private_lab_authority(self):
        with self.assertRaises(ValueError):
            _policy(self.arguments(1))

    @unittest.expectedFailure
    def test_red_truthy_container_not_coerced_to_private_lab_authority(self):
        with self.assertRaises(ValueError):
            _policy(self.arguments(["false"]))

    @unittest.expectedFailure
    def test_red_falsy_empty_string_not_silently_accepted(self):
        with self.assertRaises(ValueError):
            _policy(self.arguments(""))

    @unittest.expectedFailure
    def test_red_user_defined_bool_object_not_queried_or_accepted(self):
        with self.assertRaises(ValueError):
            _policy(self.arguments(StatefulTruthy()))

    def test_original_namespace_is_untouched_for_canonical_values(self):
        for exact in (False, True):
            ns = self.arguments(exact)
            before = vars(ns).copy()
            _policy(ns)
            self.assertEqual(vars(ns), before)

    def test_malformed_input_is_actual_type_confusion_in_current_owner_source(self):
        # Characterize rather than grant any authority: the legacy source
        # currently invokes bool() on caller-owned data. Do not use for I/O.
        ns = self.arguments("false")
        prior = vars(ns).copy()
        policy = _policy(ns)
        self.assertIs(policy.allow_private_lab, True)
        self.assertEqual(vars(ns), prior)


if __name__ == "__main__":
    unittest.main()
