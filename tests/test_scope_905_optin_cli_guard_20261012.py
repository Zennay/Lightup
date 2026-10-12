"""#905 W2: green, opt-in exact-bool guard contract on original #100 head.

The guard remains uninstalled; exercises no network, targets or CLI command.
"""
from __future__ import annotations

import argparse
import unittest
from unittest.mock import patch

from lightup.cli import build_parser
from lightup.models import Target
from lightup.private_lab_cli_guard_optin import checked_private_lab_cli_policy
from lightup.scope import ScopeReason


class PoisonBoolean:
    calls = 0

    def __bool__(self):
        self.calls += 1
        raise AssertionError("caller-defined truth conversion must not run")


class NamespaceSubclass(argparse.Namespace):
    pass


class PrivateLabCliGuardOptInTest(unittest.TestCase):
    def args(self, value):
        return argparse.Namespace(allow_private_lab=value, allow_host=[], allow_cidr=[])

    def test_exact_false_keeps_private_scope_closed(self):
        decision = checked_private_lab_cli_policy(self.args(False)).decide(
            Target("10.20.30.40")
        )
        self.assertFalse(decision.allowed)
        self.assertIs(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_exact_true_only_allows_synthetic_private_lab(self):
        decision = checked_private_lab_cli_policy(self.args(True)).decide(
            Target("10.20.30.40")
        )
        self.assertTrue(decision.allowed)
        self.assertIs(decision.reason, ScopeReason.PRIVATE_LAB)

    def test_unsupported_types_are_denied_before_delegating_to_policy(self):
        from lightup import private_lab_cli_guard_optin as gate
        for bad in ("false", "true", "", 0, 1, None, [], {}, (), b"false", 0.0):
            with self.subTest(bad=repr(bad)):
                with patch.object(gate, "_policy", side_effect=AssertionError("delegate called")) as delegate:
                    with self.assertRaises(ValueError):
                        checked_private_lab_cli_policy(self.args(bad))
                    delegate.assert_not_called()

    def test_truthy_object_cannot_trigger_its_bool_conversion(self):
        obj = PoisonBoolean()
        with self.assertRaises(ValueError):
            checked_private_lab_cli_policy(self.args(obj))
        self.assertEqual(obj.calls, 0)

    def test_canonical_namespace_required_before_subclass_properties(self):
        with self.assertRaises(ValueError):
            checked_private_lab_cli_policy(NamespaceSubclass(
                allow_private_lab=True, allow_host=[], allow_cidr=[],
            ))

    def test_missing_lab_marker_fails_without_fallback(self):
        with self.assertRaises(ValueError):
            checked_private_lab_cli_policy(argparse.Namespace(
                allow_host=[], allow_cidr=[],
            ))

    def test_existing_parser_default_false_compatible(self):
        parsed = build_parser().parse_args(["scope-check", "10.20.30.40"])
        self.assertFalse(checked_private_lab_cli_policy(parsed).allow_private_lab)

    def test_existing_explicit_parser_optin_true_compatible(self):
        parsed = build_parser().parse_args([
            "scope-check", "10.20.30.40", "--allow-private-lab",
        ])
        self.assertTrue(checked_private_lab_cli_policy(parsed).allow_private_lab)

    def test_call_does_not_mutate_caller_namespace(self):
        for valid in (False, True):
            args = self.args(valid)
            snapshot = vars(args).copy()
            checked_private_lab_cli_policy(args)
            self.assertEqual(vars(args), snapshot)

    def test_failed_call_does_not_mutate_caller_namespace(self):
        args = self.args("false")
        snapshot = vars(args).copy()
        with self.assertRaises(ValueError):
            checked_private_lab_cli_policy(args)
        self.assertEqual(vars(args), snapshot)


if __name__ == "__main__":
    unittest.main()
