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


class _DictSubclass(dict):
    pass


class _ListSubclass(list):
    pass


class FutureRemediationEvidenceBundleContainerTypesTest(unittest.TestCase):
    def setUp(self):
        self.base = bundle_tests.FutureRemediationEvidenceBundleTest(
            "test_bundle_is_deterministic_and_json_serializable"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _payload(self) -> tuple[dict, object]:
        produced = self.base._bundle(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="bundle-handoff-container-types",
        )
        bundle = produced[-1]
        return json.loads(bundle.to_json()), bundle

    def test_real_producer_payload_uses_exact_builtin_containers_and_remains_valid(self):
        payload, bundle = self._payload()

        parsed = future_remediation_evidence_bundle_from_dict(payload)

        self.assertEqual(parsed, bundle)
        self.assertIs(type(payload), dict)
        self.assertIs(type(payload["items"]), list)
        self.assertIs(type(payload["items"][0]), dict)
        self.assertIs(type(payload["items"][0]["evidence"]), list)
        self.assertIs(type(payload["items"][0]["evidence"][0]), dict)

    def test_top_level_dict_subclass_is_rejected_without_input_mutation(self):
        payload, _ = self._payload()
        adversarial = _DictSubclass(payload)
        before = copy.deepcopy(adversarial)

        with self.assertRaises(ValueError):
            future_remediation_evidence_bundle_from_dict(adversarial)

        self.assertEqual(adversarial, before)
        self.assertIs(type(adversarial), _DictSubclass)

    def test_items_list_subclass_is_rejected_without_input_mutation(self):
        payload, _ = self._payload()
        adversarial = copy.deepcopy(payload)
        adversarial["items"] = _ListSubclass(adversarial["items"])
        before = copy.deepcopy(adversarial)

        with self.assertRaises(ValueError):
            future_remediation_evidence_bundle_from_dict(adversarial)

        self.assertEqual(adversarial, before)
        self.assertIs(type(adversarial["items"]), _ListSubclass)

    def test_item_dict_subclass_is_rejected_without_input_mutation(self):
        payload, _ = self._payload()
        adversarial = copy.deepcopy(payload)
        adversarial["items"][0] = _DictSubclass(adversarial["items"][0])
        before = copy.deepcopy(adversarial)

        with self.assertRaises(ValueError):
            future_remediation_evidence_bundle_from_dict(adversarial)

        self.assertEqual(adversarial, before)
        self.assertIs(type(adversarial["items"][0]), _DictSubclass)

    def test_evidence_list_subclass_is_rejected_without_input_mutation(self):
        payload, _ = self._payload()
        adversarial = copy.deepcopy(payload)
        adversarial["items"][0]["evidence"] = _ListSubclass(
            adversarial["items"][0]["evidence"]
        )
        before = copy.deepcopy(adversarial)

        with self.assertRaises(ValueError):
            future_remediation_evidence_bundle_from_dict(adversarial)

        self.assertEqual(adversarial, before)
        self.assertIs(type(adversarial["items"][0]["evidence"]), _ListSubclass)

    def test_evidence_dict_subclass_is_rejected_without_input_mutation(self):
        payload, _ = self._payload()
        adversarial = copy.deepcopy(payload)
        adversarial["items"][0]["evidence"][0] = _DictSubclass(
            adversarial["items"][0]["evidence"][0]
        )
        before = copy.deepcopy(adversarial)

        with self.assertRaises(ValueError):
            future_remediation_evidence_bundle_from_dict(adversarial)

        self.assertEqual(adversarial, before)
        self.assertIs(
            type(adversarial["items"][0]["evidence"][0]),
            _DictSubclass,
        )


if __name__ == "__main__":
    unittest.main()
