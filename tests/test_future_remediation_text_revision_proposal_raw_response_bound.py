from __future__ import annotations

import unittest

import test_future_remediation_text_revision_proposal as revision_proposal_tests


class FutureRemediationTextRevisionProposalRawResponseBoundTest(unittest.TestCase):
    def setUp(self):
        self.base = revision_proposal_tests.FutureRemediationTextRevisionProposalTest(
            "test_live_revision_request_generates_unaccepted_non_executable_proposal"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def test_exact_raw_output_bound_remains_accepted(self):
        content = "x" * 16_000
        gateway, provider = self.base._gateway(content)

        result = self.base._generate(gateway)

        self.assertEqual(result.content, content)
        self.assertEqual(len(provider.requests), 1)
        self.assertFalse(result.remediation_accepted)
        self.assertFalse(result.code_change_authorized)
        self.assertFalse(result.tool_call_created)
        self.assertFalse(result.execution_allowed)
        self.assertFalse(result.target_interaction_allowed)
        self.assertFalse(result.future_state_retest_allowed)
        self.assertFalse(result.deployment_authorized)
        self.assertFalse(result.attack_path_mutation_allowed)

    def test_raw_output_must_be_bounded_before_normalization(self):
        raw_content = " " + ("x" * 16_000)
        self.assertEqual(len(raw_content), 16_001)
        self.assertEqual(len(raw_content.strip()), 16_000)

        gateway, provider = self.base._gateway(raw_content)

        with self.assertRaisesRegex(ValueError, "bounded output size"):
            self.base._generate(gateway)

        self.assertEqual(len(provider.requests), 1)

    def test_small_surrounding_whitespace_keeps_existing_canonicalization(self):
        gateway, provider = self.base._gateway(
            "  Revise only the unsupported defensive claim and retest later.  "
        )

        result = self.base._generate(gateway)

        self.assertEqual(
            result.content,
            "Revise only the unsupported defensive claim and retest later.",
        )
        self.assertEqual(len(provider.requests), 1)


if __name__ == "__main__":
    unittest.main()
