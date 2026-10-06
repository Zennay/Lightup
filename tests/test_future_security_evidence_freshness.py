from __future__ import annotations

import dataclasses
import json
import unittest

import test_future_security_evidence_collection_request as request_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_security_evidence_freshness import (
    FRESHNESS_SCHEMA_VERSION,
    build_future_security_evidence_freshness_constraints,
    validate_future_security_evidence_freshness_constraints,
)


class FutureSecurityEvidenceFreshnessConstraintsTest(unittest.TestCase):
    def setUp(self):
        self.base = request_tests.FutureSecurityEvidenceCollectionRequestTest(
            "test_insufficient_evidence_produces_fresh_evidence_request_only"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.state = self.base.state

    def _constraints(self, *, suffix):
        (
            current,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            request,
        ) = self.base._request(
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
            suffix=suffix,
        )
        constraints = build_future_security_evidence_freshness_constraints(
            request,
            plan,
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )
        return (
            current,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            request,
            constraints,
        )

    def test_live_gap_binds_prior_evidence_and_run_as_forbidden(self):
        (
            current,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            request,
        ) = self.base._request(
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
            suffix="freshness-live",
        )
        current_before = dataclasses.asdict(current)
        request_before = dataclasses.asdict(request)
        constraints = build_future_security_evidence_freshness_constraints(
            request,
            plan,
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )

        self.assertEqual(constraints.schema_version, FRESHNESS_SCHEMA_VERSION)
        self.assertEqual(constraints.request_sha256, request.request_sha256)
        self.assertEqual(constraints.freshness_item_count, 1)
        self.assertFalse(constraints.collection_authorized)
        self.assertFalse(constraints.capability_selected)
        self.assertFalse(constraints.tool_call_created)
        self.assertFalse(constraints.execution_allowed)
        self.assertFalse(constraints.target_interaction_allowed)
        self.assertFalse(constraints.remediation_authoring_allowed)
        self.assertFalse(constraints.future_state_retest_allowed)
        self.assertFalse(constraints.deployment_authorized)
        self.assertFalse(constraints.attack_path_mutation_allowed)

        item = constraints.items[0]
        self.assertEqual(item.source_resolution_id, resolution.resolution_id)
        self.assertEqual(item.source_resolution_sha256, resolution.resolution_sha256)
        self.assertEqual(item.forbidden_evidence_ids, resolution.evidence_ids)
        self.assertEqual(item.forbidden_run_ids, (context.run_id,))
        self.assertTrue(item.fresh_evidence_required)
        self.assertTrue(item.fresh_run_required)
        self.assertFalse(item.capability_selected)
        self.assertFalse(item.outcome_classification_selected)
        self.assertEqual(
            tuple(record.evidence_id for record in item.prior_evidence),
            resolution.evidence_ids,
        )
        self.assertEqual(
            {record.capability_id for record in item.prior_evidence},
            set(resolution.capability_ids),
        )
        self.assertEqual(dataclasses.asdict(current), current_before)
        self.assertEqual(dataclasses.asdict(request), request_before)

    def test_constraints_are_deterministic_and_export_provenance_only(self):
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            request,
            first,
        ) = self._constraints(suffix="freshness-deterministic")
        second = build_future_security_evidence_freshness_constraints(
            request,
            plan,
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )
        self.assertEqual(first, second)
        self.assertEqual(len(first.constraints_sha256), 64)
        int(first.constraints_sha256, 16)

        exported = json.loads(first.to_json())
        self.assertEqual(exported["constraints_sha256"], first.constraints_sha256)
        self.assertEqual(exported["request_sha256"], request.request_sha256)
        self.assertEqual(exported["execution_allowed"], False)
        evidence = exported["items"][0]["prior_evidence"][0]
        self.assertEqual(
            set(evidence),
            {"evidence_id", "run_id", "capability_id", "kind", "sha256"},
        )
        for forbidden in (
            "source",
            "metadata",
            "payload",
            "target",
            "arguments",
            "credentials",
        ):
            self.assertNotIn(forbidden, evidence)
            self.assertNotIn(forbidden, exported["items"][0])

    def test_deleted_prior_evidence_fails_closed(self):
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            request,
        ) = self.base._request(
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
            suffix="freshness-deleted",
        )
        with self.state.connect() as con:
            con.execute(
                "DELETE FROM evidence WHERE evidence_id=?",
                (resolution.evidence_ids[0],),
            )

        with self.assertRaises(KeyError):
            build_future_security_evidence_freshness_constraints(
                request,
                plan,
                report,
                preview,
                proposal,
                (resolution,),
                (context,),
                self.state,
            )

    def test_noncanonical_prior_evidence_digest_fails_closed(self):
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            request,
        ) = self.base._request(
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
            suffix="freshness-bad-digest",
        )
        with self.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                ("NOT-A-CANONICAL-DIGEST", resolution.evidence_ids[0]),
            )

        with self.assertRaisesRegex(ValueError, "canonical lowercase SHA-256"):
            build_future_security_evidence_freshness_constraints(
                request,
                plan,
                report,
                preview,
                proposal,
                (resolution,),
                (context,),
                self.state,
            )

    def test_capability_drift_fails_closed_through_live_lineage(self):
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            request,
        ) = self.base._request(
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
            suffix="freshness-capability-drift",
        )
        with self.state.connect() as con:
            con.execute(
                "UPDATE evidence SET capability_id=? WHERE evidence_id=?",
                ("drifted-capability", resolution.evidence_ids[0]),
            )

        with self.assertRaises(ValueError):
            build_future_security_evidence_freshness_constraints(
                request,
                plan,
                report,
                preview,
                proposal,
                (resolution,),
                (context,),
                self.state,
            )

    def test_persisted_constraints_must_match_live_rebuilt_state(self):
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            request,
            constraints,
        ) = self._constraints(suffix="freshness-persisted")

        validated = validate_future_security_evidence_freshness_constraints(
            constraints,
            request,
            plan,
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )
        self.assertEqual(validated, constraints)

        tampered = dataclasses.replace(constraints, constraints_sha256="0" * 64)
        with self.assertRaisesRegex(ValueError, "live validated lineage"):
            validate_future_security_evidence_freshness_constraints(
                tampered,
                request,
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
