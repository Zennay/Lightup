from __future__ import annotations

import copy
import json
import unittest

import test_future_attack_path_security_delta_report as report_tests
from lightup.future_attack_path_security_delta_report import (
    build_future_attack_path_security_delta_report,
)
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_security_remediation_retest_plan import (
    build_future_security_remediation_retest_plan,
)
from lightup.future_security_remediation_retest_plan_handoff import (
    future_security_remediation_retest_plan_from_dict,
)


class FutureSecurityRemediationRetestPlanParserInputPurityTest(unittest.TestCase):
    def setUp(self):
        self.r = report_tests.FutureAttackPathSecurityDeltaReportTest(
            "test_all_st4_outcomes_render_exact_evidence_linked_items"
        )
        self.r.setUp()
        self.addCleanup(self.r.tearDown)
        self.state = self.r.state

    def _plan(self, classification, *, suffix):
        _, proposal, context, resolution, preview = self.r._inputs(
            classification,
            suffix=suffix,
        )
        resolutions = (resolution,)
        contexts = (context,)
        report = build_future_attack_path_security_delta_report(
            preview,
            proposal,
            resolutions,
            contexts,
            self.state,
        )
        return build_future_security_remediation_retest_plan(
            report,
            preview,
            proposal,
            resolutions,
            contexts,
            self.state,
        )

    @staticmethod
    def _container_identities(value, path="root"):
        identities = {}
        if isinstance(value, dict):
            identities[path] = id(value)
            for key, item in value.items():
                identities.update(
                    FutureSecurityRemediationRetestPlanParserInputPurityTest
                    ._container_identities(item, f"{path}[{key!r}]")
                )
        elif isinstance(value, list):
            identities[path] = id(value)
            for index, item in enumerate(value):
                identities.update(
                    FutureSecurityRemediationRetestPlanParserInputPurityTest
                    ._container_identities(item, f"{path}[{index}]")
                )
        return identities

    @staticmethod
    def _ordered_json(value):
        return json.dumps(
            value,
            separators=(",", ":"),
            ensure_ascii=True,
        )

    def _assert_payload_unchanged(
        self,
        payload,
        before_value,
        before_json,
        before_ids,
    ):
        self.assertEqual(payload, before_value)
        self.assertEqual(self._ordered_json(payload), before_json)
        self.assertEqual(self._container_identities(payload), before_ids)

    def test_successful_parse_preserves_caller_payload_for_all_classifications(self):
        classifications = (
            AttackPathTransitionClassification.INTRODUCED,
            AttackPathTransitionClassification.WORSENED,
            AttackPathTransitionClassification.IMPROVED,
            AttackPathTransitionClassification.REMOVED,
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
        )

        for classification in classifications:
            with self.subTest(classification=classification.value):
                plan = self._plan(
                    classification,
                    suffix=f"parser-input-purity-{classification.value}",
                )
                payload = json.loads(plan.to_json())
                before_value = copy.deepcopy(payload)
                before_json = self._ordered_json(payload)
                before_ids = self._container_identities(payload)

                first = future_security_remediation_retest_plan_from_dict(payload)
                second = future_security_remediation_retest_plan_from_dict(payload)

                self.assertEqual(first, plan)
                self.assertEqual(second, plan)
                self.assertEqual(first, second)
                self._assert_payload_unchanged(
                    payload,
                    before_value,
                    before_json,
                    before_ids,
                )
                self.assertFalse(first.execution_allowed)
                self.assertFalse(first.deployment_authorized)
                self.assertFalse(first.attack_path_mutation_allowed)
                self.assertEqual(first.future_semantics, "unresolved")
                self.assertEqual(first.security_verdict, "not_evaluated")

    def test_schema_rejection_preserves_caller_payload_and_container_identities(self):
        plan = self._plan(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="parser-input-purity-schema-reject",
        )
        payload = json.loads(plan.to_json())
        payload["unexpected"] = {"nested": ["caller-owned"]}
        before_value = copy.deepcopy(payload)
        before_json = self._ordered_json(payload)
        before_ids = self._container_identities(payload)

        messages = []
        for _ in range(2):
            with self.assertRaisesRegex(ValueError, "schema mismatch") as raised:
                future_security_remediation_retest_plan_from_dict(payload)
            messages.append(str(raised.exception))

        self.assertEqual(messages[0], messages[1])
        self._assert_payload_unchanged(
            payload,
            before_value,
            before_json,
            before_ids,
        )

    def test_digest_rejection_after_deep_parse_preserves_caller_payload(self):
        plan = self._plan(
            AttackPathTransitionClassification.WORSENED,
            suffix="parser-input-purity-digest-reject",
        )
        payload = json.loads(plan.to_json())
        payload["plan_sha256"] = "0" * 64
        before_value = copy.deepcopy(payload)
        before_json = self._ordered_json(payload)
        before_ids = self._container_identities(payload)

        messages = []
        for _ in range(2):
            with self.assertRaisesRegex(ValueError, "digest mismatch") as raised:
                future_security_remediation_retest_plan_from_dict(payload)
            messages.append(str(raised.exception))

        self.assertEqual(messages[0], messages[1])
        self._assert_payload_unchanged(
            payload,
            before_value,
            before_json,
            before_ids,
        )


if __name__ == "__main__":
    unittest.main()
