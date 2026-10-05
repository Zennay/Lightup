from __future__ import annotations

import dataclasses
import json
import unittest

import test_future_security_remediation_retest_plan as plan_tests
from lightup.future_attack_path_graph_diff_preview import AttackPathGraphDiffAction
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_security_evidence_collection_request import (
    REQUEST_SCHEMA_VERSION,
    build_future_security_evidence_collection_request,
    validate_future_security_evidence_collection_request,
)


class FutureSecurityEvidenceCollectionRequestTest(unittest.TestCase):
    def setUp(self):
        self.p = plan_tests.FutureSecurityRemediationRetestPlanTest(
            "test_insufficient_evidence_blocks_retest_planning_on_more_evidence"
        )
        self.p.setUp()
        self.addCleanup(self.p.tearDown)
        self.state = self.p.state

    def _request(self, classification, *, suffix):
        (
            current,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
        ) = self.p._plan(classification, suffix=suffix)
        request = build_future_security_evidence_collection_request(
            plan,
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )
        return current, proposal, context, resolution, preview, report, plan, request

    def test_insufficient_evidence_produces_fresh_evidence_request_only(self):
        (
            current,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
        ) = self.p._plan(
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
            suffix="evidence-collection-gap",
        )
        before = dataclasses.asdict(current)
        request = build_future_security_evidence_collection_request(
            plan,
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )

        self.assertEqual(request.schema_version, REQUEST_SCHEMA_VERSION)
        self.assertEqual(request.plan_sha256, plan.plan_sha256)
        self.assertEqual(request.evidence_gap_count, 1)
        self.assertFalse(request.collection_authorized)
        self.assertFalse(request.capability_selected)
        self.assertFalse(request.tool_call_created)
        self.assertFalse(request.execution_allowed)
        self.assertFalse(request.target_interaction_allowed)
        self.assertFalse(request.remediation_authoring_allowed)
        self.assertFalse(request.future_state_retest_allowed)
        self.assertFalse(request.deployment_authorized)
        self.assertFalse(request.attack_path_mutation_allowed)
        self.assertEqual(request.future_semantics, "unresolved")
        self.assertEqual(request.security_verdict, "not_evaluated")

        item = request.items[0]
        self.assertEqual(
            item.classification,
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
        )
        self.assertEqual(
            item.graph_diff_action,
            AttackPathGraphDiffAction.NO_GRAPH_CHANGE_CLAIM,
        )
        self.assertEqual(item.collection_reason, "insufficient_evidence")
        self.assertTrue(item.fresh_evidence_required)
        self.assertTrue(item.fresh_run_required)
        self.assertFalse(item.remediation_authoring_allowed)
        self.assertFalse(item.future_state_retest_allowed)
        self.assertEqual(item.resolution_id, resolution.resolution_id)
        self.assertEqual(item.prior_evidence_ids, resolution.evidence_ids)
        self.assertEqual(item.prior_capability_ids, resolution.capability_ids)
        self.assertEqual(dataclasses.asdict(current), before)

    def test_non_gap_classifications_cannot_create_collection_request(self):
        for classification in (
            AttackPathTransitionClassification.INTRODUCED,
            AttackPathTransitionClassification.WORSENED,
            AttackPathTransitionClassification.IMPROVED,
            AttackPathTransitionClassification.REMOVED,
        ):
            with self.subTest(classification=classification.value):
                (
                    _,
                    proposal,
                    context,
                    resolution,
                    preview,
                    report,
                    plan,
                ) = self.p._plan(
                    classification,
                    suffix=f"evidence-collection-{classification.value}",
                )
                with self.assertRaisesRegex(ValueError, "requires an evidence gap"):
                    build_future_security_evidence_collection_request(
                        plan,
                        report,
                        preview,
                        proposal,
                        (resolution,),
                        (context,),
                        self.state,
                    )

    def test_request_is_deterministic_and_export_is_lineage_only(self):
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            first,
        ) = self._request(
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
            suffix="evidence-collection-deterministic",
        )
        second = build_future_security_evidence_collection_request(
            plan,
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )
        self.assertEqual(first, second)
        self.assertEqual(len(first.request_sha256), 64)
        int(first.request_sha256, 16)

        exported = json.loads(first.to_json())
        self.assertEqual(exported["request_sha256"], first.request_sha256)
        self.assertEqual(exported["collection_authorized"], False)
        self.assertEqual(exported["capability_selected"], False)
        self.assertEqual(exported["tool_call_created"], False)
        self.assertEqual(exported["execution_allowed"], False)
        self.assertEqual(
            exported["items"][0]["classification"],
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE.value,
        )
        self.assertEqual(
            exported["items"][0]["graph_diff_action"],
            AttackPathGraphDiffAction.NO_GRAPH_CHANGE_CLAIM.value,
        )
        self.assertEqual(
            exported["items"][0]["prior_evidence_ids"],
            list(resolution.evidence_ids),
        )
        exported_item = exported["items"][0]
        for forbidden_key in (
            "evidence_payload",
            "source",
            "metadata",
            "target",
            "arguments",
            "credentials",
        ):
            self.assertNotIn(forbidden_key, exported_item)

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
        ) = self._request(
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
            suffix="evidence-collection-tampered",
        )
        tampered = dataclasses.replace(plan, plan_sha256="0" * 64)
        with self.assertRaisesRegex(ValueError, "exact live remediation plan"):
            build_future_security_evidence_collection_request(
                tampered,
                report,
                preview,
                proposal,
                (resolution,),
                (context,),
                self.state,
            )

    def test_deleted_live_evidence_is_rejected_before_request_exists(self):
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
        ) = self.p._plan(
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
            suffix="evidence-collection-deleted",
        )
        evidence_id = resolution.evidence_ids[0]
        with self.state.connect() as con:
            con.execute("DELETE FROM evidence WHERE evidence_id=?", (evidence_id,))

        with self.assertRaises(KeyError):
            build_future_security_evidence_collection_request(
                plan,
                report,
                preview,
                proposal,
                (resolution,),
                (context,),
                self.state,
            )


    def test_persisted_request_must_match_live_rebuilt_lineage(self):
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            request,
        ) = self._request(
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
            suffix="evidence-collection-persisted",
        )

        validated = validate_future_security_evidence_collection_request(
            request,
            plan,
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )
        self.assertEqual(validated, request)

        tampered = dataclasses.replace(request, request_sha256="0" * 64)
        with self.assertRaisesRegex(ValueError, "live validated lineage"):
            validate_future_security_evidence_collection_request(
                tampered,
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
