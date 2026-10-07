from __future__ import annotations

import copy
import json
import unittest

import test_future_remediation_evidence_bundle as bundle_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_remediation_evidence_bundle_handoff import (
    future_remediation_evidence_bundle_from_dict,
)


class _CountIntSubclass(int):
    pass


class FutureRemediationEvidenceBundleCountTypesTest(unittest.TestCase):
    def setUp(self):
        self.base = bundle_tests.FutureRemediationEvidenceBundleTest(
            "test_bundle_is_deterministic_and_json_serializable"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _payload(self) -> tuple[dict, object]:
        produced = self.base._bundle(
            AttackPathTransitionClassification.WORSENED,
            suffix="bundle-handoff-count-types",
        )
        bundle = produced[-1]
        return json.loads(bundle.to_json()), bundle

    def _assert_rejected_without_mutation(self, adversarial: dict) -> None:
        before = copy.deepcopy(adversarial)

        with self.assertRaises(ValueError):
            future_remediation_evidence_bundle_from_dict(adversarial)

        self.assertEqual(adversarial, before)

    def test_real_producer_counts_are_exact_builtin_integers(self):
        payload, bundle = self._payload()

        parsed = future_remediation_evidence_bundle_from_dict(payload)

        self.assertEqual(parsed, bundle)
        self.assertIs(type(payload["remediation_item_count"]), int)
        self.assertIs(type(payload["blocking_evidence_gap_count"]), int)

    def test_remediation_item_count_int_subclass_is_rejected(self):
        payload, _ = self._payload()
        payload["remediation_item_count"] = _CountIntSubclass(
            payload["remediation_item_count"]
        )

        self._assert_rejected_without_mutation(payload)

    def test_blocking_evidence_gap_count_int_subclass_is_rejected(self):
        payload, _ = self._payload()
        payload["blocking_evidence_gap_count"] = _CountIntSubclass(
            payload["blocking_evidence_gap_count"]
        )

        self._assert_rejected_without_mutation(payload)


if __name__ == "__main__":
    unittest.main()
