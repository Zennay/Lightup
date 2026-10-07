from __future__ import annotations

import unittest

import test_future_remediation_evidence_bundle as bundle_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_remediation_evidence_bundle_handoff import (
    future_remediation_evidence_bundle_from_json,
)


class _StringSubclass(str):
    pass


class FutureRemediationEvidenceBundleJsonTypeTest(unittest.TestCase):
    def setUp(self):
        self.base = bundle_tests.FutureRemediationEvidenceBundleTest(
            "test_bundle_is_deterministic_and_json_serializable"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _raw_payload(self) -> tuple[str, object]:
        produced = self.base._bundle(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="bundle-handoff-json-type",
        )
        bundle = produced[-1]
        return bundle.to_json(), bundle

    def test_real_producer_json_uses_exact_builtin_string_and_remains_valid(self):
        raw, bundle = self._raw_payload()

        parsed = future_remediation_evidence_bundle_from_json(raw)

        self.assertEqual(parsed, bundle)
        self.assertIs(type(raw), str)

    def test_json_string_subclass_is_rejected_before_decode(self):
        raw, _ = self._raw_payload()
        adversarial = _StringSubclass(raw)

        with self.assertRaises(ValueError):
            future_remediation_evidence_bundle_from_json(adversarial)

        self.assertEqual(adversarial, raw)
        self.assertIs(type(adversarial), _StringSubclass)


if __name__ == "__main__":
    unittest.main()
