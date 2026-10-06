from __future__ import annotations

import json
import unittest

import test_future_remediation_evidence_bundle_handoff as handoff_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_remediation_evidence_bundle_handoff import (
    future_remediation_evidence_bundle_from_dict,
)


_FALSE_AUTHORITY_FLAGS = (
    "execution_allowed",
    "code_change_authorized",
    "target_interaction_allowed",
    "deployment_authorized",
    "attack_path_mutation_allowed",
)


class FutureRemediationEvidenceBundleSnapshotIsolationTest(unittest.TestCase):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationEvidenceBundleHandoffTest()
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _ready(self):
        produced = self.base._bundle(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="bundle-snapshot-ready",
        )
        return produced[-1]

    def _blocked(self):
        produced = self.base._bundle(
            AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
            suffix="bundle-snapshot-blocked",
        )
        return produced[-1]

    def test_to_json_is_byte_deterministic_for_ready_and_blocked_bundles(self):
        for factory in (self._ready, self._blocked):
            with self.subTest(factory=factory.__name__):
                bundle = factory()
                first = bundle.to_json()
                second = bundle.to_json()
                third = bundle.to_json()

                self.assertEqual(first, second)
                self.assertEqual(second, third)
                self.assertEqual(
                    future_remediation_evidence_bundle_from_dict(json.loads(first)),
                    bundle,
                )

    def test_nested_as_dict_mutation_cannot_change_source_ready_bundle(self):
        bundle = self._ready()
        original_json = bundle.to_json()
        snapshot = bundle.as_dict()
        item = snapshot["items"][0]

        snapshot["remediation_item_count"] = 999
        snapshot["blocking_evidence_gap_count"] = 999
        snapshot["remediation_authoring_ready"] = False
        snapshot["execution_allowed"] = True
        snapshot["future_semantics"] = "resolved"
        snapshot["security_verdict"] = "secure"
        item["change_node_id"] = "forged-change"
        item["current_attack_path_ids"] = ("forged-path",)
        item["capability_ids"] = ("forged-capability",)
        item["remediation_required"] = False
        item["future_state_retest_required"] = False
        item["evidence"][0]["evidence_id"] = "forged-evidence"
        item["evidence"][0]["sha256"] = "0" * 64

        self.assertEqual(bundle.to_json(), original_json)
        self.assertTrue(bundle.remediation_authoring_ready)
        self.assertFalse(bundle.execution_allowed)
        self.assertEqual(bundle.future_semantics, "unresolved")
        self.assertEqual(bundle.security_verdict, "not_evaluated")
        self.assertTrue(bundle.items[0].remediation_required)
        self.assertTrue(bundle.items[0].future_state_retest_required)
        self.assertNotEqual(bundle.items[0].change_node_id, "forged-change")
        self.assertNotEqual(bundle.items[0].evidence[0].evidence_id, "forged-evidence")

    def test_separate_as_dict_snapshots_do_not_alias_nested_evidence(self):
        bundle = self._ready()
        first = bundle.as_dict()
        second = bundle.as_dict()

        self.assertIsNot(first, second)
        self.assertIsNot(first["items"], second["items"])
        self.assertIsNot(first["items"][0], second["items"][0])
        self.assertIsNot(first["items"][0]["evidence"], second["items"][0]["evidence"])
        self.assertIsNot(
            first["items"][0]["evidence"][0],
            second["items"][0]["evidence"][0],
        )
        self.assertIsNot(
            first["items"][0]["capability_ids"],
            second["items"][0]["capability_ids"],
        )

        first["items"][0]["evidence"][0]["evidence_id"] = "changed-only-in-first"
        first["items"][0]["capability_ids"] = ("changed-only-in-first",)

        self.assertEqual(
            second["items"][0]["evidence"][0]["evidence_id"],
            bundle.items[0].evidence[0].evidence_id,
        )
        self.assertEqual(
            second["items"][0]["capability_ids"],
            bundle.items[0].capability_ids,
        )

    def test_parser_detaches_from_caller_owned_nested_json_containers(self):
        bundle = self._ready()
        persisted = json.loads(bundle.to_json())
        items = persisted["items"]
        item = items[0]
        current_paths = item["current_attack_path_ids"]
        effect_ids = item["effect_ids"]
        capability_ids = item["capability_ids"]
        evidence = item["evidence"]
        record = evidence[0]

        parsed = future_remediation_evidence_bundle_from_dict(persisted)
        parsed_json = parsed.to_json()

        current_paths.append("forged-path-after-parse")
        effect_ids[0] = "forged-effect-after-parse"
        capability_ids[0] = "forged-capability-after-parse"
        record["evidence_id"] = "forged-evidence-after-parse"
        record["run_id"] = "forged-run-after-parse"
        record["sha256"] = "0" * 64
        evidence.clear()
        item["remediation_required"] = False
        items.clear()

        self.assertEqual(parsed.to_json(), parsed_json)
        self.assertEqual(parsed, bundle)
        self.assertEqual(parsed.items[0].current_attack_path_ids, bundle.items[0].current_attack_path_ids)
        self.assertEqual(parsed.items[0].effect_ids, bundle.items[0].effect_ids)
        self.assertEqual(parsed.items[0].capability_ids, bundle.items[0].capability_ids)
        self.assertEqual(parsed.items[0].evidence, bundle.items[0].evidence)
        self.assertTrue(parsed.items[0].remediation_required)

    def test_authoring_readiness_is_derived_and_snapshot_mutation_is_local(self):
        blocked = self._blocked()
        original_json = blocked.to_json()
        snapshot = blocked.as_dict()
        snapshot["remediation_authoring_ready"] = True
        snapshot["blocking_evidence_gap_count"] = 0

        self.assertEqual(blocked.to_json(), original_json)
        self.assertFalse(blocked.remediation_authoring_ready)
        self.assertGreater(blocked.blocking_evidence_gap_count, 0)

        forged = json.loads(original_json)
        forged["remediation_authoring_ready"] = True
        with self.assertRaisesRegex(ValueError, "authoring readiness is inconsistent"):
            future_remediation_evidence_bundle_from_dict(forged)

    def test_item_obligations_and_authority_forgery_fail_closed(self):
        bundle = self._ready()

        for field in _FALSE_AUTHORITY_FLAGS:
            with self.subTest(field=field):
                payload = json.loads(bundle.to_json())
                payload[field] = True
                with self.assertRaises(ValueError):
                    future_remediation_evidence_bundle_from_dict(payload)

        for item_field in ("remediation_required", "future_state_retest_required"):
            with self.subTest(item_field=item_field):
                payload = json.loads(bundle.to_json())
                payload["items"][0][item_field] = False
                with self.assertRaises(ValueError):
                    future_remediation_evidence_bundle_from_dict(payload)

        for field, value in (
            ("future_semantics", "resolved"),
            ("security_verdict", "secure"),
        ):
            with self.subTest(field=field):
                payload = json.loads(bundle.to_json())
                payload[field] = value
                with self.assertRaises(ValueError):
                    future_remediation_evidence_bundle_from_dict(payload)


if __name__ == "__main__":
    unittest.main()
