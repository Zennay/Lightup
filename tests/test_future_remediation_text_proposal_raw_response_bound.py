from __future__ import annotations

import unittest

import test_future_remediation_text_proposal as proposal_tests


class FutureRemediationTextProposalRawResponseBoundTest(unittest.TestCase):
    def setUp(self):
        self.base = proposal_tests.FutureRemediationTextProposalTest(
            "test_live_valid_request_generates_bounded_non_executable_proposal"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def test_exact_raw_output_boundary_is_accepted(self):
        gateway, provider = self.base._gateway("x" * 16_000)

        result = self.base._generate(gateway)

        self.assertEqual(result.content, "x" * 16_000)
        self.assertEqual(len(provider.requests), 1)
        self.assertTrue(result.remediation_proposal_created)
        self.assertFalse(result.code_change_authorized)
        self.assertFalse(result.tool_call_created)
        self.assertFalse(result.execution_allowed)
        self.assertFalse(result.target_interaction_allowed)
        self.assertFalse(result.future_state_retest_allowed)
        self.assertFalse(result.deployment_authorized)
        self.assertFalse(result.attack_path_mutation_allowed)

    def test_oversized_raw_output_cannot_hide_size_in_trimmed_whitespace(self):
        raw = " " + ("x" * 16_000)
        self.assertEqual(len(raw), 16_001)
        self.assertEqual(len(raw.strip()), 16_000)
        gateway, provider = self.base._gateway(raw)

        with self.assertRaisesRegex(ValueError, "bounded output size"):
            self.base._generate(gateway)

        self.assertEqual(len(provider.requests), 1)

    def test_small_surrounding_whitespace_still_normalizes_canonically(self):
        raw = "  Apply the defensive control and retest later.\n"
        gateway, provider = self.base._gateway(raw)

        result = self.base._generate(gateway)

        self.assertEqual(
            result.content,
            "Apply the defensive control and retest later.",
        )
        self.assertEqual(len(provider.requests), 1)
        self.assertFalse(result.execution_allowed)
        self.assertFalse(result.target_interaction_allowed)
        self.assertFalse(result.future_state_retest_allowed)
        self.assertFalse(result.deployment_authorized)
        self.assertFalse(result.attack_path_mutation_allowed)


if __name__ == "__main__":
    unittest.main()
