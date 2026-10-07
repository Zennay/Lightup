from __future__ import annotations

import unittest

import test_future_remediation_text_revision_proposal as revision_proposal_tests
from lightup.future_remediation_text_revision_proposal_handoff import (
    future_remediation_text_revision_proposal_from_json,
)


class _StringSubclass(str):
    pass


class FutureRemediationTextRevisionProposalJsonTypeTest(unittest.TestCase):
    def setUp(self):
        self.base = revision_proposal_tests.FutureRemediationTextRevisionProposalTest(
            "test_live_revision_request_generates_unaccepted_non_executable_proposal"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        gateway, _ = self.base._gateway()
        self.proposal = self.base._generate(gateway)

    def test_exact_builtin_json_remains_valid(self):
        raw = self.proposal.to_json()
        parsed = future_remediation_text_revision_proposal_from_json(raw)
        self.assertEqual(parsed, self.proposal)
        self.assertIs(type(raw), str)

    def test_string_subclass_is_rejected_before_decode(self):
        raw = self.proposal.to_json()
        adversarial = _StringSubclass(raw)
        with self.assertRaises(ValueError):
            future_remediation_text_revision_proposal_from_json(adversarial)
        self.assertEqual(adversarial, raw)
        self.assertIs(type(adversarial), _StringSubclass)


if __name__ == "__main__":
    unittest.main()
