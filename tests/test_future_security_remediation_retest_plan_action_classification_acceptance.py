from __future__ import annotations

from hashlib import sha256
import json
import unittest

import test_future_attack_path_security_delta_report as report_tests
from lightup.future_attack_path_graph_diff_preview import AttackPathGraphDiffAction
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


def _recompute_plan_sha256(payload: dict) -> str:
    digest_payload = {
        key: value
        for key, value in payload.items()
        if key != "plan_sha256"
    }
    return sha256(
        json.dumps(
            digest_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


class FutureSecurityRemediationRetestPlanActionClassificationAcceptanceTest(
    unittest.TestCase
):
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

    def test_canonical_builder_action_mapping_still_parses(self):
        for classification in AttackPathTransitionClassification:
            with self.subTest(classification=classification.value):
                plan = self._plan(
                    classification,
                    suffix=f"action-map-canonical-{classification.value}",
                )
                parsed = future_security_remediation_retest_plan_from_dict(
                    json.loads(plan.to_json())
                )
                self.assertEqual(parsed, plan)

    def test_digest_consistent_wrong_graph_action_fails_closed(self):
        wrong_action = {
            AttackPathTransitionClassification.INTRODUCED:
                AttackPathGraphDiffAction.NO_GRAPH_CHANGE_CLAIM,
            AttackPathTransitionClassification.WORSENED:
                AttackPathGraphDiffAction.REMOVE_EXISTING_PATH_CANDIDATE,
            AttackPathTransitionClassification.IMPROVED:
                AttackPathGraphDiffAction.MODIFY_EXISTING_PATH_RISK_UP,
            AttackPathTransitionClassification.REMOVED:
                AttackPathGraphDiffAction.ADD_PATH_HYPOTHESIS,
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE:
                AttackPathGraphDiffAction.ADD_PATH_HYPOTHESIS,
        }

        for classification, forged_action in wrong_action.items():
            with self.subTest(
                classification=classification.value,
                forged_action=forged_action.value,
            ):
                plan = self._plan(
                    classification,
                    suffix=f"action-map-forged-{classification.value}",
                )
                payload = json.loads(plan.to_json())
                payload["items"][0]["graph_diff_action"] = forged_action.value
                payload["plan_sha256"] = _recompute_plan_sha256(payload)

                with self.assertRaisesRegex(
                    ValueError,
                    "classification.*action|graph.*action|action.*classification",
                ):
                    future_security_remediation_retest_plan_from_dict(payload)


if __name__ == "__main__":
    unittest.main()
