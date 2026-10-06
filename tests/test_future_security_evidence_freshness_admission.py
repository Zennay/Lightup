from __future__ import annotations

import dataclasses
import json
import unittest

import test_future_security_evidence_freshness as freshness_tests
from lightup.ai.orchestration import RunContext
from lightup.engagements import AssessmentMode
from lightup.future_security_evidence_freshness_admission import (
    ADMISSION_SCHEMA_VERSION,
    admit_future_security_evidence_freshness,
    validate_future_security_evidence_freshness_admission,
)


class FutureSecurityEvidenceFreshnessAdmissionTest(unittest.TestCase):
    def setUp(self):
        self.base = freshness_tests.FutureSecurityEvidenceFreshnessConstraintsTest(
            "test_live_gap_binds_prior_evidence_and_run_as_forbidden"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.state = self.base.state

    def _candidate(
        self,
        source_context: RunContext,
        *,
        suffix: str,
        capability_id: str = "web",
    ):
        run_id = self.state.create_run(
            target=f"127.0.0.1-{suffix}",
            activation_mode="lab_autonomous",
        )
        context = RunContext.for_lab(
            run_id,
            engagement_id=source_context.engagement_id,
            client_id=source_context.client_id,
        )
        evidence_id = self.state.add_evidence(
            run_id,
            capability_id,
            "freshness-candidate",
            f"test://{suffix}",
            f"fresh-{suffix}".encode("utf-8"),
            metadata={"purpose": "freshness-only"},
        )
        return context, evidence_id

    def _admission(self, *, suffix: str):
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
        ) = self.base._constraints(suffix=suffix)
        candidate_context, evidence_id = self._candidate(
            source_context,
            suffix=f"{suffix}-candidate",
        )
        admission = admit_future_security_evidence_freshness(
            constraints,
            source_resolution_id=resolution.resolution_id,
            candidate_evidence_ids=(evidence_id,),
            candidate_context=candidate_context,
            request=request,
            plan=plan,
            report=report,
            preview=preview,
            proposal=proposal,
            resolutions=(resolution,),
            source_contexts=(source_context,),
            state=self.state,
        )
        return (
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
        )

    def test_fresh_new_run_evidence_passes_without_security_classification(self):
        (
            current,
            _,
            source_context,
            resolution,
            _,
            _,
            _,
            request,
            constraints,
            candidate_context,
            evidence_id,
            admission,
        ) = self._admission(suffix="admission-fresh")
        current_before = dataclasses.asdict(current)
        request_before = dataclasses.asdict(request)
        constraints_before = dataclasses.asdict(constraints)

        self.assertEqual(admission.schema_version, ADMISSION_SCHEMA_VERSION)
        self.assertEqual(admission.constraints_sha256, constraints.constraints_sha256)
        self.assertEqual(admission.request_sha256, request.request_sha256)
        self.assertEqual(admission.source_resolution_id, resolution.resolution_id)
        self.assertEqual(admission.candidate_run_id, candidate_context.run_id)
        self.assertEqual(admission.candidate_evidence_ids, (evidence_id,))
        self.assertNotEqual(candidate_context.run_id, source_context.run_id)
        self.assertNotIn(candidate_context.run_id, constraints.items[0].forbidden_run_ids)
        self.assertTrue(admission.freshness_check_passed)
        self.assertFalse(admission.evidence_suitability_evaluated)
        self.assertFalse(admission.classification_selected)
        self.assertFalse(admission.transition_resolution_created)
        self.assertFalse(admission.collection_authorized)
        self.assertFalse(admission.tool_call_created)
        self.assertFalse(admission.execution_allowed)
        self.assertFalse(admission.target_interaction_allowed)
        self.assertFalse(admission.remediation_authoring_allowed)
        self.assertFalse(admission.future_state_retest_allowed)
        self.assertFalse(admission.deployment_authorized)
        self.assertFalse(admission.attack_path_mutation_allowed)
        self.assertEqual(dataclasses.asdict(current), current_before)
        self.assertEqual(dataclasses.asdict(request), request_before)
        self.assertEqual(dataclasses.asdict(constraints), constraints_before)

    def test_reused_prior_evidence_id_fails_closed(self):
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
        ) = self.base._constraints(suffix="admission-reused-evidence")
        candidate_context, _ = self._candidate(
            source_context,
            suffix="admission-reused-evidence-new-run",
        )

        with self.assertRaisesRegex(ValueError, "reuses forbidden prior evidence"):
            admit_future_security_evidence_freshness(
                constraints,
                source_resolution_id=resolution.resolution_id,
                candidate_evidence_ids=(resolution.evidence_ids[0],),
                candidate_context=candidate_context,
                request=request,
                plan=plan,
                report=report,
                preview=preview,
                proposal=proposal,
                resolutions=(resolution,),
                source_contexts=(source_context,),
                state=self.state,
            )

    def test_new_evidence_on_forbidden_prior_run_fails_closed(self):
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
        ) = self.base._constraints(suffix="admission-reused-run")
        new_evidence_id = self.state.add_evidence(
            source_context.run_id,
            "web",
            "freshness-candidate",
            "test://same-old-run",
            b"new-id-old-run",
            metadata={"purpose": "freshness-only"},
        )
        candidate_context = RunContext.for_lab(
            source_context.run_id,
            engagement_id=source_context.engagement_id,
            client_id=source_context.client_id,
        )

        with self.assertRaisesRegex(ValueError, "reuses a forbidden prior run"):
            admit_future_security_evidence_freshness(
                constraints,
                source_resolution_id=resolution.resolution_id,
                candidate_evidence_ids=(new_evidence_id,),
                candidate_context=candidate_context,
                request=request,
                plan=plan,
                report=report,
                preview=preview,
                proposal=proposal,
                resolutions=(resolution,),
                source_contexts=(source_context,),
                state=self.state,
            )

    def test_cross_run_cross_client_and_non_lab_candidates_fail_closed(self):
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
        ) = self.base._constraints(suffix="admission-context")
        candidate_context, evidence_id = self._candidate(
            source_context,
            suffix="admission-context-a",
        )
        other_context, other_evidence_id = self._candidate(
            source_context,
            suffix="admission-context-b",
        )

        with self.assertRaisesRegex(ValueError, "belongs to another run"):
            admit_future_security_evidence_freshness(
                constraints,
                source_resolution_id=resolution.resolution_id,
                candidate_evidence_ids=(other_evidence_id,),
                candidate_context=candidate_context,
                request=request,
                plan=plan,
                report=report,
                preview=preview,
                proposal=proposal,
                resolutions=(resolution,),
                source_contexts=(source_context,),
                state=self.state,
            )

        wrong_client = dataclasses.replace(candidate_context, client_id="other-client")
        with self.assertRaisesRegex(ValueError, "another client"):
            admit_future_security_evidence_freshness(
                constraints,
                source_resolution_id=resolution.resolution_id,
                candidate_evidence_ids=(evidence_id,),
                candidate_context=wrong_client,
                request=request,
                plan=plan,
                report=report,
                preview=preview,
                proposal=proposal,
                resolutions=(resolution,),
                source_contexts=(source_context,),
                state=self.state,
            )

        non_lab = dataclasses.replace(
            other_context,
            is_lab=False,
            mode=AssessmentMode.ANALYSIS_ONLY,
        )
        with self.assertRaisesRegex(PermissionError, "must come from a lab run"):
            admit_future_security_evidence_freshness(
                constraints,
                source_resolution_id=resolution.resolution_id,
                candidate_evidence_ids=(other_evidence_id,),
                candidate_context=non_lab,
                request=request,
                plan=plan,
                report=report,
                preview=preview,
                proposal=proposal,
                resolutions=(resolution,),
                source_contexts=(source_context,),
                state=self.state,
            )

    def test_deleted_or_malformed_candidate_evidence_fails_closed(self):
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
        ) = self.base._constraints(suffix="admission-ledger")

        deleted_context, deleted_id = self._candidate(
            source_context,
            suffix="admission-deleted",
        )
        with self.state.connect() as con:
            con.execute("DELETE FROM evidence WHERE evidence_id=?", (deleted_id,))
        with self.assertRaises(KeyError):
            admit_future_security_evidence_freshness(
                constraints,
                source_resolution_id=resolution.resolution_id,
                candidate_evidence_ids=(deleted_id,),
                candidate_context=deleted_context,
                request=request,
                plan=plan,
                report=report,
                preview=preview,
                proposal=proposal,
                resolutions=(resolution,),
                source_contexts=(source_context,),
                state=self.state,
            )

        malformed_context, malformed_id = self._candidate(
            source_context,
            suffix="admission-malformed",
        )
        with self.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                ("NOT-A-CANONICAL-DIGEST", malformed_id),
            )
        with self.assertRaisesRegex(ValueError, "canonical lowercase SHA-256"):
            admit_future_security_evidence_freshness(
                constraints,
                source_resolution_id=resolution.resolution_id,
                candidate_evidence_ids=(malformed_id,),
                candidate_context=malformed_context,
                request=request,
                plan=plan,
                report=report,
                preview=preview,
                proposal=proposal,
                resolutions=(resolution,),
                source_contexts=(source_context,),
                state=self.state,
            )

    def test_deterministic_bounded_export_and_persisted_live_validation(self):
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
            first,
        ) = self._admission(suffix="admission-deterministic")
        second = admit_future_security_evidence_freshness(
            constraints,
            source_resolution_id=resolution.resolution_id,
            candidate_evidence_ids=(evidence_id,),
            candidate_context=candidate_context,
            request=request,
            plan=plan,
            report=report,
            preview=preview,
            proposal=proposal,
            resolutions=(resolution,),
            source_contexts=(source_context,),
            state=self.state,
        )
        self.assertEqual(first, second)
        self.assertEqual(len(first.admission_sha256), 64)
        int(first.admission_sha256, 16)

        exported = json.loads(first.to_json())
        fingerprint = exported["candidate_evidence"][0]
        self.assertEqual(
            set(fingerprint),
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
            self.assertNotIn(forbidden, fingerprint)

        validated = validate_future_security_evidence_freshness_admission(
            first,
            constraints,
            candidate_context=candidate_context,
            request=request,
            plan=plan,
            report=report,
            preview=preview,
            proposal=proposal,
            resolutions=(resolution,),
            source_contexts=(source_context,),
            state=self.state,
        )
        self.assertEqual(validated, first)

        tampered = dataclasses.replace(first, admission_sha256="0" * 64)
        with self.assertRaisesRegex(ValueError, "live validated evidence"):
            validate_future_security_evidence_freshness_admission(
                tampered,
                constraints,
                candidate_context=candidate_context,
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
