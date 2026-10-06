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
    future_security_remediation_retest_plan_from_json,
)


class FutureSecurityRemediationRetestPlanHandoffTest(unittest.TestCase):
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
        report = build_future_attack_path_security_delta_report(
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )
        return build_future_security_remediation_retest_plan(
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )

    def test_round_trip_accepts_exact_builder_output(self):
        for classification in (
            AttackPathTransitionClassification.INTRODUCED,
            AttackPathTransitionClassification.WORSENED,
            AttackPathTransitionClassification.IMPROVED,
            AttackPathTransitionClassification.REMOVED,
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
        ):
            with self.subTest(classification=classification.value):
                plan = self._plan(
                    classification,
                    suffix=f"handoff-{classification.value}",
                )
                parsed = future_security_remediation_retest_plan_from_json(
                    plan.to_json()
                )
                self.assertEqual(parsed, plan)

    def test_exact_schema_and_strict_primitives_fail_closed(self):
        plan = self._plan(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="handoff-schema",
        )
        payload = json.loads(plan.to_json())

        extra = copy.deepcopy(payload)
        extra["unexpected"] = False
        with self.assertRaisesRegex(ValueError, "schema mismatch"):
            future_security_remediation_retest_plan_from_dict(extra)

        missing = copy.deepcopy(payload)
        missing.pop("security_verdict")
        with self.assertRaisesRegex(ValueError, "schema mismatch"):
            future_security_remediation_retest_plan_from_dict(missing)

        bool_as_int = copy.deepcopy(payload)
        bool_as_int["remediation_item_count"] = True
        with self.assertRaisesRegex(ValueError, "non-negative integer"):
            future_security_remediation_retest_plan_from_dict(bool_as_int)

        int_as_bool = copy.deepcopy(payload)
        int_as_bool["execution_allowed"] = 0
        with self.assertRaisesRegex(ValueError, "must remain false"):
            future_security_remediation_retest_plan_from_dict(int_as_bool)

    def test_item_semantics_and_identity_fail_closed_before_follow_up_use(self):
        plan = self._plan(
            AttackPathTransitionClassification.WORSENED,
            suffix="handoff-semantics",
        )
        payload = json.loads(plan.to_json())

        mismatched = copy.deepcopy(payload)
        mismatched["items"][0]["remediation_required"] = False
        with self.assertRaisesRegex(ValueError, "semantics mismatch"):
            future_security_remediation_retest_plan_from_dict(mismatched)

        type_confused = copy.deepcopy(payload)
        type_confused["items"][0]["future_state_retest_required"] = 1
        with self.assertRaisesRegex(ValueError, "must be boolean"):
            future_security_remediation_retest_plan_from_dict(type_confused)

        duplicate = copy.deepcopy(payload)
        duplicate["items"].append(copy.deepcopy(duplicate["items"][0]))
        duplicate["remediation_item_count"] = 2
        duplicate["retest_item_count"] = 2
        with self.assertRaisesRegex(ValueError, "identity must be unique"):
            future_security_remediation_retest_plan_from_dict(duplicate)

    def test_digest_and_sha_fields_are_verified(self):
        plan = self._plan(
            AttackPathTransitionClassification.IMPROVED,
            suffix="handoff-digest",
        )
        payload = json.loads(plan.to_json())

        bad_sha = copy.deepcopy(payload)
        bad_sha["report_sha256"] = "A" * 64
        with self.assertRaisesRegex(ValueError, "canonical SHA-256"):
            future_security_remediation_retest_plan_from_dict(bad_sha)

        drifted = copy.deepcopy(payload)
        drifted["plan_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            future_security_remediation_retest_plan_from_dict(drifted)

    def test_raw_json_rejects_duplicate_keys_instead_of_last_value_wins(self):
        plan = self._plan(
            AttackPathTransitionClassification.REMOVED,
            suffix="handoff-duplicate-json",
        )
        raw = plan.to_json()
        duplicated = raw[:-1] + ',"plan_complete":true}'
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            future_security_remediation_retest_plan_from_json(duplicated)

    def test_insufficient_evidence_cannot_be_relabelled_as_ready(self):
        plan = self._plan(
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
            suffix="handoff-gap",
        )
        payload = json.loads(plan.to_json())

        relabelled = copy.deepcopy(payload)
        relabelled["contains_insufficient_evidence"] = False
        with self.assertRaisesRegex(ValueError, "insufficient-evidence state mismatch"):
            future_security_remediation_retest_plan_from_dict(relabelled)

        fake_retest = copy.deepcopy(payload)
        fake_retest["items"][0]["future_state_retest_required"] = True
        with self.assertRaisesRegex(ValueError, "semantics mismatch"):
            future_security_remediation_retest_plan_from_dict(fake_retest)


if __name__ == "__main__":
    unittest.main()
