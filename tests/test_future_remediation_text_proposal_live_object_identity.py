from __future__ import annotations

import dataclasses
import unittest

import test_future_remediation_text_proposal as proposal_tests
from lightup.future_remediation_text_proposal import (
    FutureRemediationTextProposal,
)
from lightup.future_remediation_text_proposal_handoff import (
    validate_future_remediation_text_proposal,
)


class PolymorphicRemediationTextProposal(FutureRemediationTextProposal):
    """Producer-impossible runtime subtype accepted by the current live validator."""


class FutureRemediationTextProposalLiveObjectIdentityTest(unittest.TestCase):
    def setUp(self):
        self.base = proposal_tests.FutureRemediationTextProposalTest(
            "test_live_valid_request_generates_bounded_non_executable_proposal"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _proposal(self) -> FutureRemediationTextProposal:
        gateway, _ = self.base._gateway(
            "Tighten the affected defensive control and retest only after separate authorization."
        )
        return self.base._generate(gateway)

    @staticmethod
    def _as_subclass(
        proposal: FutureRemediationTextProposal,
        **overrides: object,
    ) -> PolymorphicRemediationTextProposal:
        values = {
            field.name: getattr(proposal, field.name)
            for field in dataclasses.fields(FutureRemediationTextProposal)
        }
        values.update(overrides)
        return PolymorphicRemediationTextProposal(**values)

    def _validate(self, proposal: FutureRemediationTextProposal):
        return validate_future_remediation_text_proposal(
            proposal,
            self.base.request,
            self.base.bundle,
            self.base.plan,
            self.base.report,
            self.base.preview,
            self.base.transition_proposal,
            (self.base.resolution,),
            (self.base.context,),
            self.base.state,
        )

    def test_exact_real_producer_proposal_remains_green(self):
        proposal = self._proposal()

        self.assertIs(type(proposal), FutureRemediationTextProposal)
        self.assertIs(self._validate(proposal), proposal)

    def test_proposal_subclass_fails_closed_at_live_boundary(self):
        proposal = self._proposal()
        polymorphic = self._as_subclass(proposal)
        before = tuple(
            (field.name, getattr(polymorphic, field.name))
            for field in dataclasses.fields(FutureRemediationTextProposal)
        )

        for _ in range(2):
            with self.assertRaisesRegex(
                ValueError,
                "proposal must be a FutureRemediationTextProposal",
            ):
                self._validate(polymorphic)

        after = tuple(
            (field.name, getattr(polymorphic, field.name))
            for field in dataclasses.fields(FutureRemediationTextProposal)
        )
        self.assertEqual(after, before)

    def test_subclass_cannot_hide_widened_execution_authority(self):
        proposal = self._proposal()
        polymorphic = self._as_subclass(proposal, execution_allowed=True)

        self.assertTrue(polymorphic.execution_allowed)
        self.assertEqual(polymorphic.proposal_sha256, proposal.proposal_sha256)

        with self.assertRaisesRegex(
            ValueError,
            "proposal must be a FutureRemediationTextProposal",
        ):
            self._validate(polymorphic)


if __name__ == "__main__":
    unittest.main()
