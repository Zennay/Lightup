from __future__ import annotations

from dataclasses import replace
import unittest

import test_future_remediation_implementation_plan_handoff as plan_handoff_tests
from lightup.future_remediation_implementation_plan_handoff import (
    future_remediation_implementation_plan_from_json,
)
from lightup.future_remediation_implementation_plan_request_handoff import (
    future_remediation_implementation_plan_request_from_json,
)


_AUTHORITY_FLAGS = (
    "code_change_authorized",
    "tool_call_created",
    "execution_allowed",
    "target_interaction_allowed",
    "future_state_retest_allowed",
    "deployment_authorized",
    "attack_path_mutation_allowed",
)

_FORBIDDEN_KEYS = {
    "credentials",
    "target",
    "target_arguments",
    "tool_arguments",
    "arguments",
    "command",
    "commands",
    "patch",
    "diff",
    "authorization",
    "authorization_ref",
}


def _collect_keys(value):
    keys = set()
    if isinstance(value, dict):
        keys.update(value)
        for nested in value.values():
            keys.update(_collect_keys(nested))
    elif isinstance(value, (list, tuple)):
        for nested in value:
            keys.update(_collect_keys(nested))
    return keys


class FutureRemediationImplementationPlanningChainGateTest(unittest.TestCase):
    def setUp(self):
        self.fixture = plan_handoff_tests.FutureRemediationImplementationPlanHandoffTest(
            "test_round_trip_requires_exact_live_planning_lineage"
        )
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.request = self.fixture.base.planning_request
        self.plan = self.fixture.plan

    def test_request_and_plan_round_trip_through_strict_parsers(self):
        parsed_request = future_remediation_implementation_plan_request_from_json(
            self.request.to_json()
        )
        parsed_plan = future_remediation_implementation_plan_from_json(
            self.plan.to_json()
        )

        self.assertEqual(parsed_request, self.request)
        self.assertEqual(parsed_plan, self.plan)

    def test_plan_binds_exact_request_and_review_lineage(self):
        self.assertEqual(
            self.plan.implementation_request_sha256,
            self.request.implementation_request_sha256,
        )
        self.assertEqual(self.plan.review_sha256, self.request.review_sha256)
        self.assertEqual(self.plan.proposal_sha256, self.request.proposal_sha256)
        self.assertEqual(self.plan.content_sha256, self.request.content_sha256)

    def test_only_planning_lifecycle_advances_without_action_authority(self):
        self.assertTrue(self.request.implementation_planning_requested)
        self.assertFalse(self.request.implementation_plan_created)
        self.assertTrue(self.plan.implementation_plan_created)

        for artifact in (self.request, self.plan):
            with self.subTest(artifact=type(artifact).__name__):
                for field in _AUTHORITY_FLAGS:
                    self.assertFalse(getattr(artifact, field))
                self.assertEqual(artifact.future_semantics, "unresolved")
                self.assertEqual(artifact.security_verdict, "not_evaluated")

    def test_serialized_chain_remains_payload_free(self):
        for artifact in (self.request, self.plan):
            with self.subTest(artifact=type(artifact).__name__):
                keys = _collect_keys(artifact.as_dict())
                self.assertTrue(_FORBIDDEN_KEYS.isdisjoint(keys))

    def test_request_lineage_tampering_fails_strict_parser(self):
        current = self.request.review_sha256
        forged = "0" * 64 if current != "0" * 64 else "f" * 64
        tampered = replace(self.request, review_sha256=forged)

        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            future_remediation_implementation_plan_request_from_json(
                tampered.to_json()
            )

    def test_plan_request_lineage_tampering_fails_strict_parser(self):
        current = self.plan.implementation_request_sha256
        forged = "0" * 64 if current != "0" * 64 else "f" * 64
        tampered = replace(
            self.plan,
            implementation_request_sha256=forged,
        )

        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            future_remediation_implementation_plan_from_json(tampered.to_json())


if __name__ == "__main__":
    unittest.main()
