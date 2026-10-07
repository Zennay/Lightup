from __future__ import annotations

import argparse
import copy
import unittest

from lightup.cli import _policy
from lightup.models import Target
from lightup.scope import ScopeReason


def _args(allow_private_lab: object) -> argparse.Namespace:
    return argparse.Namespace(
        allow_private_lab=allow_private_lab,
        no_private_lab=False,
        allow_host=[],
        allow_cidr=[],
    )


class ScopeAuthorizationCliPrivateLabTypeTest(unittest.TestCase):
    def test_exact_false_keeps_private_target_out_of_scope(self):
        args = _args(False)

        decision = _policy(args).decide(Target("10.20.30.40"))

        self.assertFalse(decision.allowed)
        self.assertIs(decision.reason, ScopeReason.OUT_OF_SCOPE)

    def test_exact_true_explicitly_allows_private_lab_target(self):
        args = _args(True)

        decision = _policy(args).decide(Target("10.20.30.40"))

        self.assertTrue(decision.allowed)
        self.assertIs(decision.reason, ScopeReason.PRIVATE_LAB)

    def test_type_confused_private_lab_markers_fail_before_policy_use(self):
        for marker in ("false", 1, object()):
            with self.subTest(marker=repr(marker)):
                args = _args(marker)
                original = copy.copy(args)

                with self.assertRaisesRegex(
                    ValueError, "private.*lab.*bool|bool.*private.*lab"
                ):
                    _policy(args)

                self.assertEqual(vars(args), vars(original))


if __name__ == "__main__":
    unittest.main()
