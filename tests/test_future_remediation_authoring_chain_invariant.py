from __future__ import annotations

import unittest

import test_future_remediation_evidence_bundle as bundle_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_remediation_authoring_request import (
    build_future_remediation_authoring_request,
)
from lightup.future_remediation_authoring_request_handoff import (
    future_remediation_authoring_request_from_json,
    load_and_validate_future_remediation_authoring_request,
)
from lightup.future_remediation_evidence_bundle_handoff import (
    future_remediation_evidence_bundle_from_json,
    load_and_validate_future_remediation_evidence_bundle,
)


class FutureRemediationAuthoringChainInvariantTest(unittest.TestCase):
    def setUp(self):
        self.base = bundle_tests.FutureRemediationEvidenceBundleTest(
            "test_bundle_is_deterministic_and_json_serializable"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.state = self.base.state

    def _bundle(self, classification, *, suffix: str):
        return self.base._bundle(classification, suffix=suffix)

    def _strict_bundle(self, produced: tuple):
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            bundle,
        ) = produced
        parsed = future_remediation_evidence_bundle_from_json(bundle.to_json())
        validated = load_and_validate_future_remediation_evidence_bundle(
            bundle.to_json(),
            plan,
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )
        self.assertEqual(parsed, validated)
        return validated

    def _authoring_request(self, produced: tuple):
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            _,
        ) = produced
        bundle = self._strict_bundle(produced)
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
        parsed = future_remediation_authoring_request_from_json(
            request.to_json()
        )
        validated = load_and_validate_future_remediation_authoring_request(
            request.to_json(),
            bundle,
            plan,
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )
        self.assertEqual(parsed, validated)
        return bundle, validated

    def test_real_remediation_chain_round_trips_without_gaining_authority(self):
        for classification in (
            AttackPathTransitionClassification.INTRODUCED,
            AttackPathTransitionClassification.WORSENED,
        ):
            with self.subTest(classification=classification.value):
                produced = self._bundle(
                    classification,
                    suffix=f"authoring-chain-{classification.value}",
                )
                bundle, request = self._authoring_request(produced)

                self.assertEqual(request.bundle_sha256, bundle.bundle_sha256)
                self.assertEqual(request.report_sha256, bundle.report_sha256)
                self.assertEqual(request.plan_sha256, bundle.plan_sha256)
                self.assertEqual(request.item_count, bundle.remediation_item_count)
                self.assertTrue(request.authoring_requested)

                self.assertFalse(bundle.execution_allowed)
                self.assertFalse(bundle.code_change_authorized)
                self.assertFalse(bundle.target_interaction_allowed)
                self.assertFalse(bundle.deployment_authorized)
                self.assertFalse(bundle.attack_path_mutation_allowed)

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

                serialized = request.to_json().lower()
                for forbidden in (
                    '"payload"',
                    '"source"',
                    '"metadata"',
                    '"credentials"',
                    '"target_arguments"',
                    '"patch"',
                ):
                    self.assertNotIn(forbidden, serialized)

    def test_nonready_outcomes_stop_before_authoring_request(self):
        for classification in (
            AttackPathTransitionClassification.IMPROVED,
            AttackPathTransitionClassification.REMOVED,
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
        ):
            with self.subTest(classification=classification.value):
                produced = self._bundle(
                    classification,
                    suffix=f"authoring-chain-denied-{classification.value}",
                )
                (
                    _,
                    proposal,
                    context,
                    resolution,
                    preview,
                    report,
                    plan,
                    _,
                ) = produced
                bundle = self._strict_bundle(produced)

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

    def test_duplicate_key_persisted_inputs_fail_at_both_boundaries(self):
        produced = self._bundle(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="authoring-chain-duplicates",
        )
        bundle = produced[-1]
        duplicate_bundle = (
            bundle.to_json()[:-1]
            + ',"bundle_sha256":"'
            + ("0" * 64)
            + '"}'
        )
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            future_remediation_evidence_bundle_from_json(duplicate_bundle)

        _, request = self._authoring_request(produced)
        duplicate_request = (
            request.to_json()[:-1]
            + ',"request_sha256":"'
            + ("0" * 64)
            + '"}'
        )
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            future_remediation_authoring_request_from_json(duplicate_request)

    def test_live_ledger_drift_invalidates_persisted_authoring_chain(self):
        produced = self._bundle(
            AttackPathTransitionClassification.WORSENED,
            suffix="authoring-chain-ledger-drift",
        )
        (
            _,
            proposal,
            context,
            resolution,
            preview,
            report,
            plan,
            _,
        ) = produced
        bundle, request = self._authoring_request(produced)

        evidence_id = bundle.items[0].evidence[0].evidence_id
        current_sha = bundle.items[0].evidence[0].sha256
        replacement = "f" * 64 if current_sha != "f" * 64 else "e" * 64
        with self.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence_id),
            )

        with self.assertRaises(ValueError):
            load_and_validate_future_remediation_authoring_request(
                request.to_json(),
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
