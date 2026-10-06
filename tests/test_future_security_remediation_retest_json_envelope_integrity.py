from __future__ import annotations

import unittest

import test_future_security_remediation_retest_plan_handoff as handoff_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_security_remediation_retest_plan_handoff import (
    future_security_remediation_retest_plan_from_json,
)


class FutureSecurityRemediationRetestJsonEnvelopeIntegrityTest(unittest.TestCase):
    def setUp(self):
        self.h = handoff_tests.FutureSecurityRemediationRetestPlanHandoffTest(
            "test_round_trip_accepts_exact_builder_output"
        )
        self.h.setUp()
        self.addCleanup(self.h.tearDown)

    def _plan(self):
        return self.h._plan(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="json-envelope-integrity",
        )

    def test_non_object_json_roots_fail_closed(self):
        plan = self._plan()
        canonical = plan.to_json()
        self.assertEqual(
            future_security_remediation_retest_plan_from_json(canonical),
            plan,
        )

        for raw in ("null", "[]", "true", "1", '"string-root"'):
            with self.subTest(raw=raw):
                with self.assertRaisesRegex(ValueError, "payload must be an object"):
                    future_security_remediation_retest_plan_from_json(raw)

        self.assertFalse(plan.execution_allowed)
        self.assertFalse(plan.deployment_authorized)
        self.assertFalse(plan.attack_path_mutation_allowed)
        self.assertEqual(plan.future_semantics, "unresolved")
        self.assertEqual(plan.security_verdict, "not_evaluated")

    def test_malformed_outer_json_rejection_is_repeatable(self):
        canonical = self._plan().to_json()
        malformed_inputs = (
            "",
            " ",
            "{",
            canonical[:-1],
            canonical + " trailing",
        )

        for raw in malformed_inputs:
            with self.subTest(raw=raw[:32]):
                messages = []
                for _ in range(2):
                    with self.assertRaises(ValueError) as raised:
                        future_security_remediation_retest_plan_from_json(raw)
                    messages.append(str(raised.exception))
                self.assertEqual(messages[0], messages[1])

    def test_escaped_top_level_key_aliases_are_duplicate_keys(self):
        canonical = self._plan().to_json()
        escaped_aliases = (
            canonical[:-1] + ',"\\u0070lan_complete":true}',
            canonical[:-1] + ',"\\u0069tems":[]}',
        )

        for raw in escaped_aliases:
            with self.subTest(raw=raw[-64:]):
                messages = []
                for _ in range(2):
                    with self.assertRaisesRegex(ValueError, "duplicate JSON key") as raised:
                        future_security_remediation_retest_plan_from_json(raw)
                    messages.append(str(raised.exception))
                self.assertEqual(messages[0], messages[1])


if __name__ == "__main__":
    unittest.main()
