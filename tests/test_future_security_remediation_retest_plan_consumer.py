from __future__ import annotations

import dataclasses
import json
import unittest

import test_future_security_remediation_retest_plan as plan_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_security_remediation_retest_plan_consumer import (
    load_and_validate_future_security_remediation_retest_plan,
)


class FutureSecurityRemediationRetestPlanConsumerTest(unittest.TestCase):
    def setUp(self):
        self.base = plan_tests.FutureSecurityRemediationRetestPlanTest(
            "test_plan_is_deterministic_read_only_and_json_serializable"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.state = self.base.state

    def _producer(self, classification, *, suffix: str):
        return self.base._plan(classification, suffix=suffix)

    def _consume(self, persisted: object, produced: tuple):
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            _,
        ) = produced
        return load_and_validate_future_security_remediation_retest_plan(
            persisted,
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )

    def test_real_producer_json_and_object_are_live_validated(self):
        produced = self._producer(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="plan-consumer-roundtrip",
        )
        plan = produced[-1]

        self.assertEqual(self._consume(plan.to_json(), produced), plan)
        self.assertEqual(
            self._consume(json.loads(plan.to_json()), produced),
            plan,
        )
        self.assertFalse(plan.execution_allowed)
        self.assertFalse(plan.deployment_authorized)
        self.assertFalse(plan.attack_path_mutation_allowed)
        self.assertEqual(plan.future_semantics, "unresolved")
        self.assertEqual(plan.security_verdict, "not_evaluated")

    def test_invalid_duplicate_and_non_object_json_fail_closed(self):
        produced = self._producer(
            AttackPathTransitionClassification.WORSENED,
            suffix="plan-consumer-json",
        )
        plan = produced[-1]

        with self.assertRaisesRegex(ValueError, "JSON is invalid"):
            self._consume("{", produced)

        duplicate_top = plan.to_json().replace(
            '"schema_version":',
            '"schema_version":"duplicate","schema_version":',
            1,
        )
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            self._consume(duplicate_top, produced)

        duplicate_nested = plan.to_json().replace(
            '"remediation_required":true',
            '"remediation_required":true,"remediation_required":false',
            1,
        )
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            self._consume(duplicate_nested, produced)

        with self.assertRaisesRegex(ValueError, "payload must be an object"):
            self._consume("[]", produced)

        with self.assertRaisesRegex(ValueError, "JSON text or object"):
            self._consume(123, produced)

    def test_strict_digest_tampering_fails_before_live_acceptance(self):
        produced = self._producer(
            AttackPathTransitionClassification.IMPROVED,
            suffix="plan-consumer-digest",
        )
        plan = produced[-1]
        payload = json.loads(plan.to_json())
        payload["plan_sha256"] = "0" * 64

        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            self._consume(payload, produced)

    def test_live_report_drift_rejects_canonical_persisted_plan(self):
        produced = self._producer(
            AttackPathTransitionClassification.REMOVED,
            suffix="plan-consumer-report-drift",
        )
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
        ) = produced
        drifted_report = dataclasses.replace(report, report_sha256="0" * 64)

        with self.assertRaisesRegex(ValueError, "security delta report is stale"):
            load_and_validate_future_security_remediation_retest_plan(
                plan.to_json(),
                drifted_report,
                preview,
                proposal,
                (resolution,),
                (context,),
                self.state,
            )

    def test_cross_lineage_persisted_plan_fails_live_equality_gate(self):
        first = self._producer(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="plan-consumer-lineage-a",
        )
        second = self._producer(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="plan-consumer-lineage-b",
        )

        with self.assertRaisesRegex(ValueError, "does not match live lineage rebuild"):
            self._consume(first[-1].to_json(), second)


if __name__ == "__main__":
    unittest.main()
