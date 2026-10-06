from __future__ import annotations

import json
import unittest

import test_future_security_evidence_collection_handoff as handoff_tests
from lightup.future_security_evidence_collection_request import (
    future_security_evidence_collection_request_from_dict,
)


_SAFETY_FALSE_FIELDS = (
    "collection_authorized",
    "capability_selected",
    "tool_call_created",
    "execution_allowed",
    "target_interaction_allowed",
    "remediation_authoring_allowed",
    "future_state_retest_allowed",
    "deployment_authorized",
    "attack_path_mutation_allowed",
)


class FutureSecurityEvidenceCollectionRequestSnapshotIsolationTest(
    unittest.TestCase
):
    def setUp(self):
        self.handoff = handoff_tests.FutureSecurityEvidenceCollectionHandoffTest(
            "test_round_trip_restores_exact_typed_request"
        )
        self.handoff.setUp()
        self.addCleanup(self.handoff.tearDown)
        self.request, _ = self.handoff._payload()

    def _persisted_dict(self):
        return json.loads(self.request.to_json())

    def test_json_is_byte_deterministic_and_json_derived_dict_round_trips(self):
        first = self.request.to_json()
        second = self.request.to_json()
        third = self.request.to_json()

        self.assertEqual(first, second)
        self.assertEqual(second, third)
        restored = future_security_evidence_collection_request_from_dict(
            json.loads(first)
        )
        self.assertEqual(restored, self.request)

    def test_producer_snapshot_nested_mutation_cannot_change_source_request(self):
        original_json = self.request.to_json()
        snapshot = self.request.as_dict()

        snapshot["evidence_gap_count"] = 999
        snapshot["collection_authorized"] = True
        snapshot["execution_allowed"] = True
        snapshot["future_semantics"] = "resolved"
        snapshot["security_verdict"] = "secure"
        snapshot["items"][0]["change_node_id"] = "forged-change"
        snapshot["items"][0]["effect_ids"] = ("forged-effect",)
        snapshot["items"][0]["prior_evidence_ids"] = ("forged-evidence",)
        snapshot["items"][0]["fresh_evidence_required"] = False

        self.assertEqual(self.request.to_json(), original_json)
        self.assertEqual(self.request.evidence_gap_count, len(self.request.items))
        self.assertFalse(self.request.collection_authorized)
        self.assertFalse(self.request.execution_allowed)
        self.assertEqual(self.request.future_semantics, "unresolved")
        self.assertEqual(self.request.security_verdict, "not_evaluated")
        self.assertTrue(self.request.items[0].fresh_evidence_required)

    def test_independent_producer_snapshots_do_not_alias_nested_state(self):
        first = self.request.as_dict()
        second = self.request.as_dict()

        self.assertIsNot(first, second)
        self.assertIsNot(first["items"], second["items"])
        self.assertIsNot(first["items"][0], second["items"][0])

        first["items"][0]["change_node_id"] = "changed-only-in-first"
        first["items"][0]["effect_ids"] = ("changed-only-in-first",)
        first["items"][0]["prior_evidence_ids"] = ("changed-only-in-first",)

        self.assertNotEqual(
            first["items"][0]["change_node_id"],
            second["items"][0]["change_node_id"],
        )
        self.assertNotEqual(
            first["items"][0]["effect_ids"],
            second["items"][0]["effect_ids"],
        )
        self.assertNotEqual(
            first["items"][0]["prior_evidence_ids"],
            second["items"][0]["prior_evidence_ids"],
        )

    def test_parser_detaches_from_mutable_nested_persisted_state(self):
        persisted = self._persisted_dict()
        items = persisted["items"]
        item = items[0]
        effect_ids = item["effect_ids"]
        evidence_ids = item["prior_evidence_ids"]
        capability_ids = item["prior_capability_ids"]
        path_ids = item["current_attack_path_ids"]

        parsed = future_security_evidence_collection_request_from_dict(persisted)
        parsed_json = parsed.to_json()

        item["change_node_id"] = "forged-after-parse"
        effect_ids[0] = "forged-effect-after-parse"
        effect_ids.append("extra-effect-after-parse")
        evidence_ids[0] = "forged-evidence-after-parse"
        capability_ids[0] = "forged-capability-after-parse"
        path_ids.append("forged-path-after-parse")
        items.append(dict(item))
        persisted["execution_allowed"] = True

        self.assertEqual(parsed.to_json(), parsed_json)
        self.assertEqual(parsed, self.request)
        self.assertNotIn("forged-effect-after-parse", parsed.items[0].effect_ids)
        self.assertNotIn(
            "forged-evidence-after-parse",
            parsed.items[0].prior_evidence_ids,
        )
        self.assertNotIn(
            "forged-capability-after-parse",
            parsed.items[0].prior_capability_ids,
        )
        self.assertFalse(parsed.execution_allowed)

    def test_forged_gap_authority_and_future_state_fail_closed(self):
        mutations = {
            "evidence_gap_count": self.request.evidence_gap_count + 1,
            "future_semantics": "resolved",
            "security_verdict": "secure",
        }
        for field in _SAFETY_FALSE_FIELDS:
            mutations[field] = True

        for field, value in mutations.items():
            with self.subTest(field=field):
                persisted = self._persisted_dict()
                persisted[field] = value
                with self.assertRaises(ValueError):
                    future_security_evidence_collection_request_from_dict(
                        persisted
                    )

    def test_forged_item_planning_and_lineage_state_fail_closed(self):
        classification = self._persisted_dict()
        classification["items"][0]["classification"] = "introduced"
        with self.assertRaises(ValueError):
            future_security_evidence_collection_request_from_dict(classification)

        graph_action = self._persisted_dict()
        graph_action["items"][0]["graph_diff_action"] = "add_path"
        with self.assertRaises(ValueError):
            future_security_evidence_collection_request_from_dict(graph_action)

        fresh = self._persisted_dict()
        fresh["items"][0]["fresh_evidence_required"] = False
        with self.assertRaisesRegex(ValueError, "must require fresh evidence"):
            future_security_evidence_collection_request_from_dict(fresh)

        remediation = self._persisted_dict()
        remediation["items"][0]["remediation_authoring_allowed"] = True
        with self.assertRaisesRegex(ValueError, "cannot authorize remediation"):
            future_security_evidence_collection_request_from_dict(remediation)

        duplicate = self._persisted_dict()
        evidence_id = duplicate["items"][0]["prior_evidence_ids"][0]
        duplicate["items"][0]["prior_evidence_ids"].append(evidence_id)
        with self.assertRaisesRegex(ValueError, "sorted and unique"):
            future_security_evidence_collection_request_from_dict(duplicate)

    def test_post_parse_top_level_mutation_cannot_change_typed_request(self):
        persisted = self._persisted_dict()
        parsed = future_security_evidence_collection_request_from_dict(persisted)
        parsed_json = parsed.to_json()

        persisted["client_id"] = "changed-after-parse"
        persisted["request_sha256"] = "0" * 64
        persisted["collection_authorized"] = True
        persisted["security_verdict"] = "secure"

        self.assertEqual(parsed.to_json(), parsed_json)
        self.assertEqual(parsed, self.request)
        self.assertFalse(parsed.collection_authorized)
        self.assertEqual(parsed.security_verdict, "not_evaluated")


if __name__ == "__main__":
    unittest.main()
