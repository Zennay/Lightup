from __future__ import annotations

import dataclasses
import unittest

import test_future_security_remediation_retest_plan as plan_tests
from lightup.future_attack_path_graph_diff_preview import AttackPathGraphDiffAction
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_security_evidence_collection_request import (
    REQUEST_SCHEMA_VERSION,
    build_future_security_evidence_collection_request,
)


class FutureSecurityEvidenceCollectionDirectConstructionTest(unittest.TestCase):
    def setUp(self):
        self.p = plan_tests.FutureSecurityRemediationRetestPlanTest(
            "test_insufficient_evidence_blocks_retest_planning_on_more_evidence"
        )
        self.p.setUp()
        self.addCleanup(self.p.tearDown)
        self.state = self.p.state

    def _request(self, *, suffix: str):
        (
            _current,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
        ) = self.p._plan(
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
            suffix=suffix,
        )
        request = build_future_security_evidence_collection_request(
            plan,
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )
        return request

    def test_canonical_builder_output_keeps_planning_only_stop_line(self):
        request = self._request(suffix="direct-construction-control")
        item = request.items[0]

        self.assertEqual(request.schema_version, REQUEST_SCHEMA_VERSION)
        self.assertEqual(request.evidence_gap_count, len(request.items))
        self.assertIsInstance(request.items, tuple)
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
        self.assertTrue(item.fresh_evidence_required)
        self.assertTrue(item.fresh_run_required)
        self.assertFalse(item.remediation_authoring_allowed)
        self.assertFalse(item.future_state_retest_allowed)
        self.assertEqual(item.collection_reason, "insufficient_evidence")
        self.assertIs(
            item.classification,
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
        )
        self.assertIs(
            item.graph_diff_action,
            AttackPathGraphDiffAction.NO_GRAPH_CHANGE_CLAIM,
        )
        self.assertTrue(item.effect_ids)
        self.assertTrue(item.prior_evidence_ids)
        self.assertTrue(item.prior_capability_ids)

    def test_direct_request_authority_widening_is_rejected(self):
        request = self._request(suffix="direct-request-authority")
        for field in (
            "collection_authorized",
            "capability_selected",
            "tool_call_created",
            "execution_allowed",
            "target_interaction_allowed",
            "remediation_authoring_allowed",
            "future_state_retest_allowed",
            "deployment_authorized",
            "attack_path_mutation_allowed",
        ):
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    dataclasses.replace(request, **{field: True})

    def test_direct_request_future_state_claims_are_rejected(self):
        request = self._request(suffix="direct-request-future-state")

        with self.assertRaises(ValueError):
            dataclasses.replace(request, future_semantics="resolved")
        with self.assertRaises(ValueError):
            dataclasses.replace(request, security_verdict="secure")

    def test_direct_request_structural_drift_is_rejected(self):
        request = self._request(suffix="direct-request-structure")

        with self.assertRaises(ValueError):
            dataclasses.replace(request, schema_version="st5.evidence_collection_request.v0")
        with self.assertRaises(ValueError):
            dataclasses.replace(
                request,
                evidence_gap_count=request.evidence_gap_count + 1,
            )
        with self.assertRaises(ValueError):
            dataclasses.replace(request, items=())
        with self.assertRaises(ValueError):
            dataclasses.replace(request, items=list(request.items))

    def test_direct_request_digest_and_lineage_drift_are_rejected(self):
        request = self._request(suffix="direct-request-digest")

        with self.assertRaises(ValueError):
            dataclasses.replace(request, request_sha256="0" * 64)
        with self.assertRaises(ValueError):
            dataclasses.replace(request, client_id=request.client_id + "-forged")
        with self.assertRaises(ValueError):
            dataclasses.replace(request, plan_sha256="f" * 64)

    def test_direct_request_numeric_metadata_is_canonical(self):
        request = self._request(suffix="direct-request-numeric")

        with self.assertRaises(ValueError):
            dataclasses.replace(request, current_twin_version=True)
        with self.assertRaises(ValueError):
            dataclasses.replace(request, twin_version=-1)
        with self.assertRaises(ValueError):
            dataclasses.replace(request, evidence_gap_count=True)

    def test_direct_item_freshness_weakening_is_rejected(self):
        item = self._request(suffix="direct-item-freshness").items[0]

        with self.assertRaises(ValueError):
            dataclasses.replace(item, fresh_evidence_required=False)
        with self.assertRaises(ValueError):
            dataclasses.replace(item, fresh_run_required=False)

    def test_direct_item_action_authority_widening_is_rejected(self):
        item = self._request(suffix="direct-item-authority").items[0]

        with self.assertRaises(ValueError):
            dataclasses.replace(item, remediation_authoring_allowed=True)
        with self.assertRaises(ValueError):
            dataclasses.replace(item, future_state_retest_allowed=True)

    def test_direct_item_semantic_drift_is_rejected(self):
        item = self._request(suffix="direct-item-semantics").items[0]

        with self.assertRaises(ValueError):
            dataclasses.replace(item, collection_reason="manual_override")
        with self.assertRaises(ValueError):
            dataclasses.replace(
                item,
                classification=AttackPathTransitionClassification.INTRODUCED,
            )
        alternative_action = next(
            action
            for action in AttackPathGraphDiffAction
            if action is not AttackPathGraphDiffAction.NO_GRAPH_CHANGE_CLAIM
        )
        with self.assertRaises(ValueError):
            dataclasses.replace(item, graph_diff_action=alternative_action)

    def test_direct_item_lineage_shape_is_rejected(self):
        item = self._request(suffix="direct-item-lineage").items[0]

        for field in ("change_node_id", "subject_node_id", "resolution_id"):
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    dataclasses.replace(item, **{field: ""})

        with self.assertRaises(ValueError):
            dataclasses.replace(item, resolution_sha256="not-a-sha256")
        with self.assertRaises(ValueError):
            dataclasses.replace(item, effect_ids=())
        with self.assertRaises(ValueError):
            dataclasses.replace(item, prior_evidence_ids=())
        with self.assertRaises(ValueError):
            dataclasses.replace(item, prior_capability_ids=())

    def test_direct_item_collection_types_are_canonical(self):
        item = self._request(suffix="direct-item-container-types").items[0]

        with self.assertRaises(ValueError):
            dataclasses.replace(
                item,
                prior_evidence_ids=list(item.prior_evidence_ids),
            )
        with self.assertRaises(ValueError):
            dataclasses.replace(
                item,
                prior_capability_ids=list(item.prior_capability_ids),
            )

    def test_direct_stop_line_fields_require_exact_bool_values(self):
        request = self._request(suffix="direct-exact-bool")
        item = request.items[0]

        with self.assertRaises(ValueError):
            dataclasses.replace(request, collection_authorized=0)
        with self.assertRaises(ValueError):
            dataclasses.replace(item, fresh_evidence_required=1)


if __name__ == "__main__":
    unittest.main()
