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


class _CanonicalLookingKey(str):
    """Non-exact string key carrying canonical text/hash/equality."""


def _replace_key(mapping: dict, key: str) -> dict:
    return {
        (_CanonicalLookingKey(existing) if existing == key else existing): value
        for existing, value in mapping.items()
    }


class FutureRemediationEvidenceBundleMappingKeyTypesTest(unittest.TestCase):
    def setUp(self):
        self.base = bundle_tests.FutureRemediationEvidenceBundleTest(
            "test_bundle_is_deterministic_and_json_serializable"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _payload(self) -> tuple[dict, object]:
        produced = self.base._bundle(
            AttackPathTransitionClassification.WORSENED,
            suffix="bundle-handoff-key-types",
        )
        bundle = produced[-1]
        return json.loads(bundle.to_json()), bundle

    def test_real_producer_payload_with_exact_builtin_keys_remains_valid(self):
        payload, bundle = self._payload()

        parsed = future_remediation_evidence_bundle_from_dict(payload)

        self.assertEqual(parsed, bundle)
        self.assertTrue(all(type(key) is str for key in payload))
        self.assertTrue(all(type(key) is str for key in payload["items"][0]))
        self.assertTrue(
            all(type(key) is str for key in payload["items"][0]["evidence"][0])
        )

    def test_top_level_mapping_key_subclass_is_rejected_without_input_mutation(self):
        payload, _ = self._payload()
        adversarial = _replace_key(payload, "client_id")
        before = copy.deepcopy(adversarial)

        self.assertTrue(
            any(
                type(key) is _CanonicalLookingKey and str(key) == "client_id"
                for key in adversarial
            )
        )
        with self.assertRaisesRegex(ValueError, "schema|key"):
            future_remediation_evidence_bundle_from_dict(adversarial)

        self.assertEqual(adversarial, before)

    def test_item_mapping_key_subclass_is_rejected_without_input_mutation(self):
        payload, _ = self._payload()
        adversarial = copy.deepcopy(payload)
        adversarial["items"][0] = _replace_key(
            adversarial["items"][0],
            "classification",
        )
        before = copy.deepcopy(adversarial)

        self.assertTrue(
            any(
                type(key) is _CanonicalLookingKey and str(key) == "classification"
                for key in adversarial["items"][0]
            )
        )
        with self.assertRaisesRegex(ValueError, "schema|key"):
            future_remediation_evidence_bundle_from_dict(adversarial)

        self.assertEqual(adversarial, before)

    def test_evidence_mapping_key_subclass_is_rejected_without_input_mutation(self):
        payload, _ = self._payload()
        adversarial = copy.deepcopy(payload)
        adversarial["items"][0]["evidence"][0] = _replace_key(
            adversarial["items"][0]["evidence"][0],
            "evidence_id",
        )
        before = copy.deepcopy(adversarial)

        self.assertTrue(
            any(
                type(key) is _CanonicalLookingKey and str(key) == "evidence_id"
                for key in adversarial["items"][0]["evidence"][0]
            )
        )
        with self.assertRaisesRegex(ValueError, "schema|key"):
            future_remediation_evidence_bundle_from_dict(adversarial)

        self.assertEqual(adversarial, before)


if __name__ == "__main__":
    unittest.main()
