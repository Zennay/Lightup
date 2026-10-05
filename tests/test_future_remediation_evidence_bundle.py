from __future__ import annotations

import dataclasses
import json
import unittest

import test_future_security_remediation_retest_plan as plan_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_remediation_evidence_bundle import (
    BUNDLE_SCHEMA_VERSION,
    build_future_remediation_evidence_bundle,
)


class FutureRemediationEvidenceBundleTest(unittest.TestCase):
    def setUp(self):
        self.p = plan_tests.FutureSecurityRemediationRetestPlanTest(
            "test_plan_is_deterministic_read_only_and_json_serializable"
        )
        self.p.setUp()
        self.addCleanup(self.p.tearDown)
        self.state = self.p.state

    def _bundle(self, classification, *, suffix):
        (
            current,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
        ) = self.p._plan(classification, suffix=suffix)
        bundle = build_future_remediation_evidence_bundle(
            plan,
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )
        return current, proposal, context, resolution, preview, report, plan, bundle

    def test_introduced_and_worsened_bind_live_evidence_for_remediation(self):
        for classification in (
            AttackPathTransitionClassification.INTRODUCED,
            AttackPathTransitionClassification.WORSENED,
        ):
            with self.subTest(classification=classification.value):
                (
                    current,
                    proposal,
                    context,
                    resolution,
                    preview,
                    report,
                    plan,
                ) = self.p._plan(
                    classification,
                    suffix=f"remediation-evidence-{classification.value}",
                )
                before = dataclasses.asdict(current)
                bundle = build_future_remediation_evidence_bundle(
                    plan,
                    report,
                    preview,
                    proposal,
                    (resolution,),
                    (context,),
                    self.state,
                )

                self.assertEqual(bundle.schema_version, BUNDLE_SCHEMA_VERSION)
                self.assertEqual(bundle.plan_sha256, plan.plan_sha256)
                self.assertEqual(bundle.remediation_item_count, 1)
                self.assertEqual(bundle.blocking_evidence_gap_count, 0)
                self.assertTrue(bundle.remediation_authoring_ready)
                self.assertFalse(bundle.execution_allowed)
                self.assertFalse(bundle.code_change_authorized)
                self.assertFalse(bundle.target_interaction_allowed)
                self.assertFalse(bundle.deployment_authorized)
                self.assertFalse(bundle.attack_path_mutation_allowed)

                item = bundle.items[0]
                self.assertEqual(item.classification, classification)
                self.assertTrue(item.remediation_required)
                self.assertTrue(item.future_state_retest_required)
                self.assertEqual(item.resolution_id, resolution.resolution_id)
                self.assertEqual(
                    tuple(record.evidence_id for record in item.evidence),
                    tuple(sorted(resolution.evidence_ids)),
                )
                for evidence in item.evidence:
                    live = self.state.get_evidence(evidence.evidence_id)
                    self.assertEqual(evidence.run_id, context.run_id)
                    self.assertEqual(evidence.capability_id, live.capability_id)
                    self.assertEqual(evidence.kind, live.kind)
                    self.assertEqual(evidence.sha256, live.sha256)
                    self.assertEqual(len(evidence.sha256), 64)
                self.assertEqual(len(item.evidence_manifest_sha256), 64)
                self.assertEqual(dataclasses.asdict(current), before)

    def test_non_remediation_classifications_do_not_become_authoring_inputs(self):
        for classification in (
            AttackPathTransitionClassification.IMPROVED,
            AttackPathTransitionClassification.REMOVED,
        ):
            with self.subTest(classification=classification.value):
                *_, bundle = self._bundle(
                    classification,
                    suffix=f"remediation-evidence-{classification.value}",
                )
                self.assertEqual(bundle.items, ())
                self.assertEqual(bundle.remediation_item_count, 0)
                self.assertEqual(bundle.blocking_evidence_gap_count, 0)
                self.assertFalse(bundle.remediation_authoring_ready)

    def test_insufficient_evidence_blocks_authoring_readiness(self):
        *_, bundle = self._bundle(
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
            suffix="remediation-evidence-gap",
        )
        self.assertEqual(bundle.items, ())
        self.assertEqual(bundle.remediation_item_count, 0)
        self.assertEqual(bundle.blocking_evidence_gap_count, 1)
        self.assertFalse(bundle.remediation_authoring_ready)

    def test_bundle_is_deterministic_and_json_serializable(self):
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            first,
        ) = self._bundle(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="remediation-evidence-deterministic",
        )
        second = build_future_remediation_evidence_bundle(
            plan,
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )
        self.assertEqual(first, second)
        self.assertEqual(len(first.bundle_sha256), 64)
        int(first.bundle_sha256, 16)

        exported = json.loads(first.to_json())
        self.assertEqual(exported["bundle_sha256"], first.bundle_sha256)
        self.assertEqual(exported["plan_sha256"], plan.plan_sha256)
        self.assertEqual(exported["execution_allowed"], False)
        self.assertEqual(exported["code_change_authorized"], False)
        self.assertEqual(
            exported["items"][0]["classification"],
            AttackPathTransitionClassification.INTRODUCED.value,
        )

    def test_tampered_plan_is_rejected_by_live_revalidation(self):
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            _,
        ) = self._bundle(
            AttackPathTransitionClassification.WORSENED,
            suffix="remediation-evidence-tampered-plan",
        )
        tampered = dataclasses.replace(plan, plan_sha256="0" * 64)
        with self.assertRaisesRegex(ValueError, "exact live remediation plan"):
            build_future_remediation_evidence_bundle(
                tampered,
                report,
                preview,
                proposal,
                (resolution,),
                (context,),
                self.state,
            )

    def test_deleted_ledger_evidence_fails_closed(self):
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
        ) = self.p._plan(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="remediation-evidence-deleted-ledger",
        )
        evidence_id = plan.items[0].evidence_ids[0]
        with self.state.connect() as con:
            con.execute("DELETE FROM evidence WHERE evidence_id=?", (evidence_id,))

        with self.assertRaises(KeyError):
            build_future_remediation_evidence_bundle(
                plan,
                report,
                preview,
                proposal,
                (resolution,),
                (context,),
                self.state,
            )


if __name__ == "__main__":
    unittest.main()
