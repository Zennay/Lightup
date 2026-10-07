from __future__ import annotations

import unittest

import test_future_remediation_authoring_request as request_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_remediation_authoring_request_handoff import (
    future_remediation_authoring_request_from_json,
)


class _StringSubclass(str):
    pass


class FutureRemediationAuthoringRequestJsonTypeTest(unittest.TestCase):
    def setUp(self):
        self.base = request_tests.FutureRemediationAuthoringRequestTest(
            "test_request_is_deterministic_and_export_is_bounded"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _raw_request(self) -> tuple[str, object]:
        produced = self.base._request(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="authoring-request-json-type",
        )
        request = produced[-1]
        return request.to_json(), request

    def test_real_producer_json_uses_exact_builtin_string_and_remains_valid(self):
        raw, request = self._raw_request()

        parsed = future_remediation_authoring_request_from_json(raw)

        self.assertEqual(parsed, request)
        self.assertIs(type(raw), str)

    def test_json_string_subclass_is_rejected_before_decode(self):
        raw, _ = self._raw_request()
        adversarial = _StringSubclass(raw)

        with self.assertRaises(ValueError):
            future_remediation_authoring_request_from_json(adversarial)

        self.assertEqual(adversarial, raw)
        self.assertIs(type(adversarial), _StringSubclass)


if __name__ == "__main__":
    unittest.main()
