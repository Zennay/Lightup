from __future__ import annotations

import unittest

import test_future_remediation_text_proposal as proposal_tests
from lightup.future_remediation_authoring_request_handoff import (
    load_and_validate_future_remediation_authoring_request,
)
from lightup.future_remediation_text_proposal import (
    generate_future_remediation_text_proposal,
)
from lightup.future_remediation_text_proposal_handoff import (
    load_and_validate_future_remediation_text_proposal,
)


class FutureRemediationTextChainInvariantTest(unittest.TestCase):
    def setUp(self):
        self.base = proposal_tests.FutureRemediationTextProposalTest(
            "test_live_valid_request_generates_bounded_non_executable_proposal"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _strict_request(self):
        return load_and_validate_future_remediation_authoring_request(
            self.base.request.to_json(),
            self.base.bundle,
            self.base.plan,
            self.base.report,
            self.base.preview,
            self.base.transition_proposal,
            (self.base.resolution,),
            (self.base.context,),
            self.base.state,
        )

    def _generate(self, strict_request):
        gateway, provider = self.base._gateway(
            "Reduce the affected exposure using a defensive control. "
            "Treat the finding as unresolved until a separately authorized "
            "future-state retest is completed."
        )
        proposal = generate_future_remediation_text_proposal(
            strict_request,
            self.base.bundle,
            self.base.plan,
            self.base.report,
            self.base.preview,
            self.base.transition_proposal,
            (self.base.resolution,),
            (self.base.context,),
            self.base.state,
            gateway,
        )
        return proposal, provider

    def _strict_proposal(self, proposal, strict_request):
        return load_and_validate_future_remediation_text_proposal(
            proposal.to_json(),
            strict_request,
            self.base.bundle,
            self.base.plan,
            self.base.report,
            self.base.preview,
            self.base.transition_proposal,
            (self.base.resolution,),
            (self.base.context,),
            self.base.state,
        )

    def test_complete_persisted_chain_round_trips_without_action_authority(self):
        strict_request = self._strict_request()
        proposal, provider = self._generate(strict_request)
        strict_proposal = self._strict_proposal(proposal, strict_request)

        self.assertEqual(strict_proposal, proposal)
        self.assertEqual(proposal.request_sha256, strict_request.request_sha256)
        self.assertEqual(proposal.bundle_sha256, self.base.bundle.bundle_sha256)
        self.assertEqual(len(provider.requests), 1)

        self.assertTrue(strict_request.authoring_requested)
        self.assertFalse(strict_request.remediation_proposal_created)

        self.assertTrue(strict_proposal.remediation_proposal_created)
        self.assertFalse(strict_proposal.code_change_authorized)
        self.assertFalse(strict_proposal.tool_call_created)
        self.assertFalse(strict_proposal.execution_allowed)
        self.assertFalse(strict_proposal.target_interaction_allowed)
        self.assertFalse(strict_proposal.future_state_retest_allowed)
        self.assertFalse(strict_proposal.deployment_authorized)
        self.assertFalse(strict_proposal.attack_path_mutation_allowed)
        self.assertEqual(strict_proposal.future_semantics, "unresolved")
        self.assertEqual(strict_proposal.security_verdict, "not_evaluated")

        serialized = strict_proposal.to_json().lower()
        for forbidden_true in (
            '"code_change_authorized":true',
            '"tool_call_created":true',
            '"execution_allowed":true',
            '"target_interaction_allowed":true',
            '"future_state_retest_allowed":true',
            '"deployment_authorized":true',
            '"attack_path_mutation_allowed":true',
        ):
            self.assertNotIn(forbidden_true, serialized)

    def test_live_evidence_drift_invalidates_request_and_proposal_reuse(self):
        strict_request = self._strict_request()
        proposal, provider = self._generate(strict_request)
        self.assertEqual(len(provider.requests), 1)

        evidence_id = self.base.bundle.items[0].evidence[0].evidence_id
        current_sha = self.base.bundle.items[0].evidence[0].sha256
        replacement = "f" * 64 if current_sha != "f" * 64 else "e" * 64
        with self.base.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence_id),
            )

        with self.assertRaises(ValueError):
            self._strict_request()
        with self.assertRaises(ValueError):
            self._strict_proposal(proposal, strict_request)

    def test_model_text_is_not_a_retest_or_security_verdict(self):
        strict_request = self._strict_request()
        proposal, _ = self._generate(strict_request)
        strict_proposal = self._strict_proposal(proposal, strict_request)

        self.assertIn("future-state retest", strict_proposal.content)
        self.assertFalse(strict_proposal.future_state_retest_allowed)
        self.assertEqual(strict_proposal.security_verdict, "not_evaluated")
        self.assertEqual(strict_proposal.future_semantics, "unresolved")


if __name__ == "__main__":
    unittest.main()
