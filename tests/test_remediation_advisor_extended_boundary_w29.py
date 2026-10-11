"""Issue #898: malformed advisor content and third-finding batch stop.

Expected RED until original PR #846 source owner installs a fail-closed
remediation-output guard. Scripted provider only, no target/network activity.
"""
from __future__ import annotations

import copy
import unittest

from lightup.ai.gateway import ModelRole
from tests.test_remediation_advisor_batch_atomicity_w26 import BatchProvider, _input, _review


class StrSubclass(str):
    pass


class AdvisorExtendedBoundaryW29Test(unittest.TestCase):
    def test_third_invalid_advice_stops_before_report_without_input_mutation(self):
        for invalid in ("", "\u00a0\u2003", "\n\t"):
            with self.subTest(invalid=repr(invalid)):
                source = _input()
                third = copy.deepcopy(source["findings"][1])
                third["finding"] = "Synthetic third finding"
                source["findings"].append(third)
                before = copy.deepcopy(source)
                provider = BatchProvider(["Fix first", "Fix second", invalid])
                with self.assertRaisesRegex(ValueError, "remediation.*non-empty"):
                    _review(provider, source)
                self.assertEqual(source, before)
                self.assertEqual(
                    [request.role for request in provider.requests],
                    [
                        ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR,
                        ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR,
                        ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR,
                    ],
                )

    def test_invalid_advice_type_rejected_before_next_finding(self):
        for invalid in (None, 0, False, [], StrSubclass("looks valid")):
            with self.subTest(invalid=repr(invalid)):
                source = _input()
                before = copy.deepcopy(source)
                provider = BatchProvider([invalid, "Fix second"])
                with self.assertRaisesRegex(ValueError, "remediation.*non-empty"):
                    _review(provider, source)
                self.assertEqual(source, before)
                self.assertEqual(
                    [request.role for request in provider.requests],
                    [ModelRole.VERIFIER, ModelRole.REMEDIATION_ADVISOR],
                )


if __name__ == "__main__":
    unittest.main()
