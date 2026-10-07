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


class _DigestStringSubclass(str):
    pass


class FutureRemediationEvidenceBundleDigestTypesTest(unittest.TestCase):
    def setUp(self):
        self.base = bundle_tests.FutureRemediationEvidenceBundleTest(
            "test_bundle_is_deterministic_and_json_serializable"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _payload(self) -> tuple[dict, object]:
        produced = self.base._bundle(
            AttackPathTransitionClassification.WORSENED,
            suffix="bundle-handoff-digest-types",
        )
        bundle = produced[-1]
        return json.loads(bundle.to_json()), bundle

    def _assert_rejected_without_mutation(self, adversarial: dict) -> None:
        before = copy.deepcopy(adversarial)

        with self.assertRaises(ValueError):
            future_remediation_evidence_bundle_from_dict(adversarial)

        self.assertEqual(adversarial, before)

    def test_real_producer_digest_values_are_exact_builtin_strings(self):
        payload, bundle = self._payload()

        parsed = future_remediation_evidence_bundle_from_dict(payload)

        self.assertEqual(parsed, bundle)
        self.assertIs(type(payload["report_sha256"]), str)
        self.assertIs(type(payload["plan_sha256"]), str)
        self.assertIs(type(payload["bundle_sha256"]), str)
        self.assertIs(type(payload["items"][0]["resolution_sha256"]), str)
        self.assertIs(type(payload["items"][0]["evidence_manifest_sha256"]), str)
        self.assertIs(type(payload["items"][0]["evidence"][0]["sha256"]), str)

    def test_report_digest_string_subclass_is_rejected(self):
        payload, _ = self._payload()
        payload["report_sha256"] = _DigestStringSubclass(payload["report_sha256"])
        self._assert_rejected_without_mutation(payload)

    def test_plan_digest_string_subclass_is_rejected(self):
        payload, _ = self._payload()
        payload["plan_sha256"] = _DigestStringSubclass(payload["plan_sha256"])
        self._assert_rejected_without_mutation(payload)

    def test_bundle_digest_string_subclass_is_rejected(self):
        payload, _ = self._payload()
        payload["bundle_sha256"] = _DigestStringSubclass(payload["bundle_sha256"])
        self._assert_rejected_without_mutation(payload)

    def test_resolution_digest_string_subclass_is_rejected(self):
        payload, _ = self._payload()
        item = payload["items"][0]
        item["resolution_sha256"] = _DigestStringSubclass(
            item["resolution_sha256"]
        )
        self._assert_rejected_without_mutation(payload)

    def test_manifest_digest_string_subclass_is_rejected(self):
        payload, _ = self._payload()
        item = payload["items"][0]
        item["evidence_manifest_sha256"] = _DigestStringSubclass(
            item["evidence_manifest_sha256"]
        )
        self._assert_rejected_without_mutation(payload)

    def test_evidence_digest_string_subclass_is_rejected(self):
        payload, _ = self._payload()
        evidence = payload["items"][0]["evidence"][0]
        evidence["sha256"] = _DigestStringSubclass(evidence["sha256"])
        self._assert_rejected_without_mutation(payload)


if __name__ == "__main__":
    unittest.main()
