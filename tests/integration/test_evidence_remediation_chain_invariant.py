from __future__ import annotations

import dataclasses
import json
import unittest

import test_future_security_evidence_freshness_coverage as coverage_tests
from lightup.future_security_evidence_freshness_coverage import (
    build_future_security_evidence_freshness_coverage,
    future_security_evidence_freshness_coverage_from_dict,
    validate_future_security_evidence_freshness_coverage,
)


class EvidenceRemediationChainInvariantIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.base = coverage_tests.FutureSecurityEvidenceFreshnessCoverageTest(
            "test_exact_live_admission_marks_only_its_gap_covered"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.state = self.base.state

    def test_full_freshness_chain_never_grants_closure_or_execution(self):
        (
            current,
            proposal,
            source_context,
            resolution,
            preview,
            report,
            plan,
            request,
            constraints,
            candidate_context,
            evidence_id,
            admission,
        ) = self.base._admission_base(suffix="integration-evidence-remediation-chain")

        current_before = dataclasses.asdict(current)
        request_before = dataclasses.asdict(request)
        constraints_before = dataclasses.asdict(constraints)

        # The admitted candidate is real StateStore evidence from a genuinely
        # new lab run, not a hand-constructed fingerprint.
        live_evidence = self.state.get_evidence(evidence_id)
        self.assertEqual(live_evidence.evidence_id, evidence_id)
        self.assertEqual(live_evidence.run_id, candidate_context.run_id)
        self.assertNotEqual(candidate_context.run_id, source_context.run_id)
        self.assertNotIn(
            candidate_context.run_id,
            constraints.items[0].forbidden_run_ids,
        )
        self.assertNotIn(
            evidence_id,
            constraints.items[0].forbidden_evidence_ids,
        )

        coverage = build_future_security_evidence_freshness_coverage(
            constraints,
            (admission,),
            (candidate_context,),
            request=request,
            plan=plan,
            report=report,
            preview=preview,
            proposal=proposal,
            resolutions=(resolution,),
            source_contexts=(source_context,),
            state=self.state,
        )
        restored = future_security_evidence_freshness_coverage_from_dict(
            json.loads(coverage.to_json())
        )

        # Preserve exact digest lineage end to end.
        self.assertEqual(constraints.request_sha256, request.request_sha256)
        self.assertEqual(admission.request_sha256, request.request_sha256)
        self.assertEqual(
            admission.constraints_sha256,
            constraints.constraints_sha256,
        )
        self.assertEqual(coverage.request_sha256, request.request_sha256)
        self.assertEqual(
            coverage.constraints_sha256,
            constraints.constraints_sha256,
        )
        self.assertEqual(
            coverage.items[0].admission_sha256,
            admission.admission_sha256,
        )
        self.assertEqual(restored, coverage)
        live_validated = validate_future_security_evidence_freshness_coverage(
            restored,
            constraints,
            (admission,),
            (candidate_context,),
            request=request,
            plan=plan,
            report=report,
            preview=preview,
            proposal=proposal,
            resolutions=(resolution,),
            source_contexts=(source_context,),
            state=self.state,
        )
        self.assertEqual(live_validated, coverage)

        # 100% freshness coverage is only a freshness fact. It must never
        # imply sufficiency, closure, classification, or any action authority.
        self.assertEqual(coverage.total_gap_count, 1)
        self.assertEqual(coverage.covered_gap_count, 1)
        self.assertEqual(coverage.missing_gap_count, 0)
        self.assertTrue(coverage.all_gaps_have_fresh_candidates)

        false_flags = (
            "evidence_sufficiency_evaluated",
            "gap_closed",
            "classification_selected",
            "transition_resolution_created",
            "collection_authorized",
            "tool_call_created",
            "execution_allowed",
            "target_interaction_allowed",
            "remediation_authoring_allowed",
            "future_state_retest_allowed",
            "deployment_authorized",
            "attack_path_mutation_allowed",
        )
        for artifact in (coverage, restored, live_validated):
            for field in false_flags:
                with self.subTest(artifact=type(artifact).__name__, field=field):
                    self.assertFalse(getattr(artifact, field))
            self.assertEqual(artifact.future_semantics, "unresolved")
            self.assertEqual(artifact.security_verdict, "not_evaluated")

        # Earlier artifacts also remain non-authoritative throughout the
        # successful freshness path.
        for artifact in (request, constraints, admission):
            for field in (
                "collection_authorized",
                "tool_call_created",
                "execution_allowed",
                "target_interaction_allowed",
                "remediation_authoring_allowed",
                "future_state_retest_allowed",
                "deployment_authorized",
                "attack_path_mutation_allowed",
            ):
                with self.subTest(artifact=type(artifact).__name__, field=field):
                    self.assertFalse(getattr(artifact, field))

        self.assertFalse(admission.classification_selected)
        self.assertFalse(admission.transition_resolution_created)

        # The current twin and upstream immutable contracts are untouched.
        self.assertEqual(dataclasses.asdict(current), current_before)
        self.assertEqual(dataclasses.asdict(request), request_before)
        self.assertEqual(dataclasses.asdict(constraints), constraints_before)

    def test_persisted_full_coverage_rejects_live_evidence_drift(self):
        (
            _,
            proposal,
            source_context,
            resolution,
            preview,
            report,
            plan,
            request,
            constraints,
            candidate_context,
            evidence_id,
            admission,
        ) = self.base._admission_base(
            suffix="integration-evidence-remediation-live-drift"
        )

        coverage = build_future_security_evidence_freshness_coverage(
            constraints,
            (admission,),
            (candidate_context,),
            request=request,
            plan=plan,
            report=report,
            preview=preview,
            proposal=proposal,
            resolutions=(resolution,),
            source_contexts=(source_context,),
            state=self.state,
        )
        restored = future_security_evidence_freshness_coverage_from_dict(
            json.loads(coverage.to_json())
        )

        # The persisted object remains internally canonical, but a later live
        # evidence-ledger change must invalidate it before any consumer can
        # treat complete freshness coverage as current.
        with self.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                ("0" * 64, evidence_id),
            )

        with self.assertRaises(ValueError):
            validate_future_security_evidence_freshness_coverage(
                restored,
                constraints,
                (admission,),
                (candidate_context,),
                request=request,
                plan=plan,
                report=report,
                preview=preview,
                proposal=proposal,
                resolutions=(resolution,),
                source_contexts=(source_context,),
                state=self.state,
            )


if __name__ == "__main__":
    unittest.main()
