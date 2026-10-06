from __future__ import annotations

import copy
from hashlib import sha256
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


def _resign(payload: dict) -> None:
    digest_payload = copy.deepcopy(payload)
    digest_payload.pop("plan_sha256")
    payload["plan_sha256"] = sha256(
        json.dumps(
            digest_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


class FutureSecurityRemediationRetestRequiredLineageAcceptanceTest(unittest.TestCase):
    def setUp(self):
        self.r = report_tests.FutureAttackPathSecurityDeltaReportTest(
            "test_all_st4_outcomes_render_exact_evidence_linked_items"
        )
        self.r.setUp()
        self.addCleanup(self.r.tearDown)
        self.state = self.r.state

    def _canonical_payload(self) -> dict:
        _, proposal, context, resolution, preview = self.r._inputs(
            AttackPathTransitionClassification.WORSENED,
            suffix="handoff-required-lineage",
        )
        report = build_future_attack_path_security_delta_report(
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )
        plan = build_future_security_remediation_retest_plan(
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )
        return json.loads(plan.to_json())

    def test_canonical_producer_payload_round_trips(self):
        payload = self._canonical_payload()
        parsed = future_security_remediation_retest_plan_from_dict(
            copy.deepcopy(payload)
        )
        self.assertEqual(json.loads(parsed.to_json()), payload)

    def test_required_upstream_lineage_collections_cannot_be_erased(self):
        payload = self._canonical_payload()

        for field in ("effect_ids", "evidence_ids", "capability_ids"):
            with self.subTest(field=field):
                self.assertTrue(payload["items"][0][field])
                tampered = copy.deepcopy(payload)
                tampered["items"][0][field] = []
                _resign(tampered)

                with self.assertRaises(ValueError):
                    future_security_remediation_retest_plan_from_dict(tampered)


if __name__ == "__main__":
    unittest.main()
