from __future__ import annotations

import dataclasses
import json
import unittest

import test_future_remediation_evidence_bundle as bundle_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_remediation_authoring_request import (
    AUTHORING_REQUEST_SCHEMA_VERSION,
    build_future_remediation_authoring_request,
    validate_future_remediation_authoring_request,
)


class FutureRemediationAuthoringRequestTest(unittest.TestCase):
    def setUp(self):
        self.base = bundle_tests.FutureRemediationEvidenceBundleTest(
            "test_bundle_is_deterministic_and_json_serializable"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.state = self.base.state

    def _request(self, classification, *, suffix: str):
        produced = self.base._bundle(classification, suffix=suffix)
        (
            current,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            bundle,
        ) = produced
        request = build_future_remediation_authoring_request(
            bundle,
            plan,
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )
        return (*produced, request)

    def test_introduced_and_worsened_create_bounded_text_authoring_requests(self):
        for classification in (
            AttackPathTransitionClassification.INTRODUCED,
            AttackPathTransitionClassification.WORSENED,
        ):
            with self.subTest(classification=classification.value):
                *_, bundle, request = self._request(
                    classification,
                    suffix=f"authoring-request-{classification.value}",
                )

                self.assertEqual(
                    request.schema_version,
                    AUTHORING_REQUEST_SCHEMA_VERSION,
                )
                self.assertEqual(request.bundle_sha256, bundle.bundle_sha256)
                self.assertEqual(request.item_count, 1)
                self.assertTrue(request.authoring_requested)
                self.assertFalse(request.remediation_proposal_created)
                self.assertFalse(request.code_change_authorized)
                self.assertFalse(request.tool_call_created)
                self.assertFalse(request.execution_allowed)
                self.assertFalse(request.target_interaction_allowed)
                self.assertFalse(request.future_state_retest_allowed)
                self.assertFalse(request.deployment_authorized)
                self.assertFalse(request.attack_path_mutation_allowed)
                self.assertEqual(request.future_semantics, "unresolved")
                self.assertEqual(request.security_verdict, "not_evaluated")

                item = request.items[0]
                self.assertEqual(item.classification, classification)
                self.assertEqual(item.requested_output, "remediation_text_proposal")
                self.assertTrue(item.remediation_required)
                self.assertTrue(item.future_state_retest_required)
                self.assertEqual(
                    item.evidence_manifest_sha256,
                    bundle.items[0].evidence_manifest_sha256,
                )
                self.assertEqual(
                    tuple(record.evidence_id for record in item.evidence),
                    tuple(record.evidence_id for record in bundle.items[0].evidence),
                )

    def test_nonready_bundles_cannot_create_authoring_requests(self):
        for classification in (
            AttackPathTransitionClassification.IMPROVED,
            AttackPathTransitionClassification.REMOVED,
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
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
                    bundle,
                ) = self.base._bundle(
                    classification,
                    suffix=f"authoring-request-denied-{classification.value}",
                )
                with self.assertRaisesRegex(
                    PermissionError,
                    "not ready for authoring",
                ):
                    build_future_remediation_authoring_request(
                        bundle,
                        plan,
                        report,
                        preview,
                        proposal,
                        (resolution,),
                        (context,),
                        self.state,
                    )

    def test_request_is_deterministic_and_export_is_bounded(self):
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            bundle,
            first,
        ) = self._request(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="authoring-request-deterministic",
        )
        second = build_future_remediation_authoring_request(
            bundle,
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
        self.assertEqual(exported["authoring_requested"], True)
        self.assertEqual(exported["remediation_proposal_created"], False)
        self.assertEqual(exported["code_change_authorized"], False)
        self.assertEqual(exported["tool_call_created"], False)
        self.assertEqual(exported["execution_allowed"], False)

        evidence = exported["items"][0]["evidence"][0]
        self.assertEqual(
            set(evidence),
            {"evidence_id", "run_id", "capability_id", "kind", "sha256"},
        )
        serialized = first.to_json().lower()
        for forbidden in (
            '"payload"',
            '"source"',
            '"metadata"',
            '"credentials"',
            '"target_arguments"',
            '"patch"',
        ):
            self.assertNotIn(forbidden, serialized)

    def test_live_validator_accepts_exact_request_and_rejects_tampering(self):
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            bundle,
            request,
        ) = self._request(
            AttackPathTransitionClassification.WORSENED,
            suffix="authoring-request-live",
        )

        self.assertEqual(
            validate_future_remediation_authoring_request(
                request,
                bundle,
                plan,
                report,
                preview,
                proposal,
                (resolution,),
                (context,),
                self.state,
            ),
            request,
        )

        tampered = dataclasses.replace(request, request_sha256="0" * 64)
        with self.assertRaisesRegex(
            ValueError,
            "does not match its live validated lineage",
        ):
            validate_future_remediation_authoring_request(
                tampered,
                bundle,
                plan,
                report,
                preview,
                proposal,
                (resolution,),
                (context,),
                self.state,
            )

    def test_live_ledger_drift_invalidates_existing_authoring_request(self):
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            bundle,
            request,
        ) = self._request(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="authoring-request-ledger-drift",
        )
        evidence_id = bundle.items[0].evidence[0].evidence_id
        current_sha = bundle.items[0].evidence[0].sha256
        replacement = "f" * 64 if current_sha != "f" * 64 else "e" * 64

        with self.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence_id),
            )

        with self.assertRaisesRegex(
            ValueError,
            "does not match its live validated lineage",
        ):
            validate_future_remediation_authoring_request(
                request,
                bundle,
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
