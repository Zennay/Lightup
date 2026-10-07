from __future__ import annotations

import unittest

import test_future_remediation_implementation_plan_revision_proposal_handoff as handoff_tests
from lightup.future_remediation_implementation_plan_revision_proposal_handoff import (
    future_remediation_implementation_plan_revision_proposal_from_dict,
)


class _EqualitySpoofString(str):
    def __eq__(self, other):
        return True

    def __ne__(self, other):
        return False


class FutureRemediationImplementationPlanRevisionProposalPersistedMetadataTypesTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = (
            handoff_tests.FutureRemediationImplementationPlanRevisionProposalHandoffTest(
                "test_json_and_dict_round_trip_require_live_revision_lineage"
            )
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.revised_plan = self.base.revised_plan

    def test_canonical_fixed_metadata_are_exact_builtin_strings(self):
        payload = self.revised_plan.as_dict()

        self.assertIs(type(payload["schema_version"]), str)
        self.assertIs(type(payload["future_semantics"]), str)
        self.assertIs(type(payload["security_verdict"]), str)

        parsed = future_remediation_implementation_plan_revision_proposal_from_dict(
            payload
        )
        self.assertEqual(parsed, self.revised_plan)

    def test_fixed_metadata_string_subclasses_fail_closed_before_equality(self):
        cases = {
            "schema_version": "not-the-schema",
            "future_semantics": "not-the-future-state",
            "security_verdict": "not-the-verdict",
        }

        for field, stored_text in cases.items():
            with self.subTest(field=field):
                payload = self.revised_plan.as_dict()
                spoofed = _EqualitySpoofString(stored_text)
                payload[field] = spoofed

                self.assertIs(type(spoofed), _EqualitySpoofString)
                self.assertEqual(str(spoofed), stored_text)

                with self.assertRaises(ValueError):
                    future_remediation_implementation_plan_revision_proposal_from_dict(
                        payload
                    )

                self.assertIs(payload[field], spoofed)
                self.assertEqual(str(payload[field]), stored_text)


if __name__ == "__main__":
    unittest.main()
