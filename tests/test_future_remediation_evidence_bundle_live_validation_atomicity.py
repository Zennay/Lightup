from __future__ import annotations

import copy
import dataclasses
import json
import unittest
from unittest import mock

import test_future_remediation_evidence_bundle as bundle_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_remediation_evidence_bundle_handoff import (
    load_and_validate_future_remediation_evidence_bundle,
)


class FutureRemediationEvidenceBundleLiveValidationAtomicityTest(unittest.TestCase):
    def setUp(self):
        self.base = bundle_tests.FutureRemediationEvidenceBundleTest(
            "test_bundle_is_deterministic_and_json_serializable"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.state = self.base.state

    def _bundle(self, classification, *, suffix: str):
        return self.base._bundle(classification, suffix=suffix)

    @staticmethod
    def _snapshot_lineage(produced: tuple) -> tuple:
        # proposal, context, resolution, preview, report, plan
        return tuple(
            dataclasses.asdict(value)
            if dataclasses.is_dataclass(value)
            else copy.deepcopy(value)
            for value in produced[1:7]
        )

    def _consume(self, persisted: object, produced: tuple):
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
        return load_and_validate_future_remediation_evidence_bundle(
            persisted,
            plan,
            report,
            preview,
            proposal,
            (resolution,),
            (context,),
            self.state,
        )

    def _write_sentinels(self):
        return (
            mock.patch.object(
                self.state,
                "create_run",
                side_effect=AssertionError("live validation must not create runs"),
            ),
            mock.patch.object(
                self.state,
                "acquire_lease",
                side_effect=AssertionError("live validation must not acquire leases"),
            ),
            mock.patch.object(
                self.state,
                "add_evidence",
                side_effect=AssertionError("live validation must not add evidence"),
            ),
        )

    def test_successful_live_validation_is_repeatable_and_input_atomic(self):
        produced = self._bundle(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="bundle-live-validation-atomic-success",
        )
        bundle = produced[-1]
        payload = json.loads(bundle.to_json())
        payload_before = copy.deepcopy(payload)
        lineage_before = self._snapshot_lineage(produced)

        evidence_id = bundle.items[0].evidence[0].evidence_id
        evidence_before = dataclasses.asdict(self.state.get_evidence(evidence_id))

        run_patch, lease_patch, evidence_patch = self._write_sentinels()
        with run_patch, lease_patch, evidence_patch:
            first = self._consume(payload, produced)
            second = self._consume(payload, produced)

        self.assertEqual(first, bundle)
        self.assertEqual(second, bundle)
        self.assertEqual(payload, payload_before)
        self.assertEqual(self._snapshot_lineage(produced), lineage_before)
        self.assertEqual(
            dataclasses.asdict(self.state.get_evidence(evidence_id)),
            evidence_before,
        )

        self.assertFalse(first.execution_allowed)
        self.assertFalse(first.code_change_authorized)
        self.assertFalse(first.target_interaction_allowed)
        self.assertFalse(first.deployment_authorized)
        self.assertFalse(first.attack_path_mutation_allowed)
        self.assertEqual(first.future_semantics, "unresolved")
        self.assertEqual(first.security_verdict, "not_evaluated")

    def test_live_rejection_is_repeatable_and_input_atomic(self):
        produced = self._bundle(
            AttackPathTransitionClassification.WORSENED,
            suffix="bundle-live-validation-atomic-reject",
        )
        bundle = produced[-1]
        payload = json.loads(bundle.to_json())
        payload_before = copy.deepcopy(payload)
        lineage_before = self._snapshot_lineage(produced)

        evidence_id = bundle.items[0].evidence[0].evidence_id
        current_sha = bundle.items[0].evidence[0].sha256
        replacement = "f" * 64 if current_sha != "f" * 64 else "e" * 64
        with self.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence_id),
            )
        stale_evidence_before = dataclasses.asdict(
            self.state.get_evidence(evidence_id)
        )

        messages: list[str] = []
        run_patch, lease_patch, evidence_patch = self._write_sentinels()
        with run_patch, lease_patch, evidence_patch:
            for _ in range(2):
                with self.assertRaisesRegex(
                    ValueError,
                    "does not match its live validated lineage",
                ) as caught:
                    self._consume(payload, produced)
                messages.append(str(caught.exception))

        self.assertEqual(messages[0], messages[1])
        self.assertEqual(payload, payload_before)
        self.assertEqual(self._snapshot_lineage(produced), lineage_before)
        self.assertEqual(
            dataclasses.asdict(self.state.get_evidence(evidence_id)),
            stale_evidence_before,
        )


if __name__ == "__main__":
    unittest.main()
