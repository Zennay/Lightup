from __future__ import annotations

import unittest

import test_future_remediation_text_proposal as proposal_tests
from lightup.future_remediation_text_proposal_handoff import (
    future_remediation_text_proposal_from_json,
)


class _StringSubclass(str):
    pass


class FutureRemediationTextProposalJsonTypeTest(unittest.TestCase):
    def setUp(self):
        self.base = proposal_tests.FutureRemediationTextProposalTest(
            "test_live_valid_request_generates_bounded_non_executable_proposal"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        gateway, _ = self.base._gateway()
        self.proposal = self.base._generate(gateway)

    def test_real_producer_json_uses_exact_builtin_string_and_remains_valid(self):
        raw = self.proposal.to_json()

        parsed = future_remediation_text_proposal_from_json(raw)

        self.assertEqual(parsed, self.proposal)
        self.assertIs(type(raw), str)

    def test_json_string_subclass_is_rejected_before_decode(self):
        raw = self.proposal.to_json()
        adversarial = _StringSubclass(raw)

        with self.assertRaises(ValueError):
            future_remediation_text_proposal_from_json(adversarial)

        self.assertEqual(adversarial, raw)
        self.assertIs(type(adversarial), _StringSubclass)


if __name__ == "__main__":
    unittest.main()
