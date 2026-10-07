from __future__ import annotations

import unittest

import test_future_remediation_implementation_plan_revision_proposal as revision_tests


class EqualitySpoofModelId(str):
    def __new__(cls):
        return super().__new__(cls, "forged-revision-model")

    def __eq__(self, other):
        return other == "implementation-plan-revision-v1"

    def __ne__(self, other):
        return False


class FutureRemediationImplementationPlanRevisionModelIdentityTest(unittest.TestCase):
    def setUp(self):
        self.base = revision_tests.FutureRemediationImplementationPlanRevisionProposalTest(
            "test_live_revision_request_generates_unaccepted_non_executable_revised_plan"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def test_canonical_exact_model_identity_remains_accepted(self):
        gateway, _ = self.base._gateway()

        result = self.base._generate(gateway)

        self.assertIs(type(result.model_id), str)
        self.assertEqual(result.model_id, "implementation-plan-revision-v1")
        self.assertFalse(result.implementation_plan_accepted)
        self.assertFalse(result.execution_allowed)

    def test_polymorphic_model_identity_cannot_spoof_bound_model(self):
        gateway, provider = self.base._gateway(
            response_model_id=EqualitySpoofModelId(),
        )

        with self.assertRaisesRegex(ValueError, "wrong model identity"):
            self.base._generate(gateway)

        self.assertEqual(len(provider.requests), 1)


if __name__ == "__main__":
    unittest.main()
