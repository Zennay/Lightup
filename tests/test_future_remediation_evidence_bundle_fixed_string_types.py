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


class _CanonicalStringSubclass(str):
    pass


class FutureRemediationEvidenceBundleFixedStringTypesTest(unittest.TestCase):
    def setUp(self):
        self.base = bundle_tests.FutureRemediationEvidenceBundleTest(
            "test_bundle_is_deterministic_and_json_serializable"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _payload(self) -> tuple[dict, object]:
        produced = self.base._bundle(
            AttackPathTransitionClassification.WORSENED,
            suffix="bundle-handoff-fixed-string-types",
        )
        bundle = produced[-1]
        return json.loads(bundle.to_json()), bundle

    def _assert_rejected_without_mutation(self, adversarial: dict) -> None:
        before = copy.deepcopy(adversarial)

        with self.assertRaises(ValueError):
            future_remediation_evidence_bundle_from_dict(adversarial)

        self.assertEqual(adversarial, before)

    def test_real_producer_fixed_strings_are_exact_builtin_values(self):
        payload, bundle = self._payload()

        parsed = future_remediation_evidence_bundle_from_dict(payload)

        self.assertEqual(parsed, bundle)
        self.assertIs(type(payload["schema_version"]), str)
        self.assertIs(type(payload["items"][0]["classification"]), str)
        self.assertIs(type(payload["future_semantics"]), str)
        self.assertIs(type(payload["security_verdict"]), str)

    def test_schema_version_string_subclass_is_rejected(self):
        payload, _ = self._payload()
        payload["schema_version"] = _CanonicalStringSubclass(
            payload["schema_version"]
        )

        self._assert_rejected_without_mutation(payload)

    def test_classification_string_subclass_is_rejected(self):
        payload, _ = self._payload()
        payload["items"][0]["classification"] = _CanonicalStringSubclass(
            payload["items"][0]["classification"]
        )

        self._assert_rejected_without_mutation(payload)

    def test_future_semantics_string_subclass_is_rejected(self):
        payload, _ = self._payload()
        payload["future_semantics"] = _CanonicalStringSubclass(
            payload["future_semantics"]
        )

        self._assert_rejected_without_mutation(payload)

    def test_security_verdict_string_subclass_is_rejected(self):
        payload, _ = self._payload()
        payload["security_verdict"] = _CanonicalStringSubclass(
            payload["security_verdict"]
        )

        self._assert_rejected_without_mutation(payload)


if __name__ == "__main__":
    unittest.main()
