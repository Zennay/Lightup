from __future__ import annotations

import json
import unittest

import test_future_security_evidence_freshness_constraints_consumer as consumer_tests
from lightup.future_security_evidence_freshness import (
    future_security_evidence_freshness_constraints_from_dict,
)


_FALSE_AUTHORITY_FLAGS = (
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


class FutureSecurityEvidenceFreshnessConstraintsSnapshotIsolationTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = consumer_tests.FutureSecurityEvidenceFreshnessConstraintsConsumerTest()
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.produced = self.base._producer(suffix="constraints-snapshot-isolation")
        self.constraints = self.produced[-1]

    def test_to_json_is_byte_deterministic_and_json_snapshot_round_trips(self):
        first = self.constraints.to_json()
        second = self.constraints.to_json()
        third = self.constraints.to_json()

        self.assertEqual(first, second)
        self.assertEqual(second, third)
        self.assertEqual(
            future_security_evidence_freshness_constraints_from_dict(
                json.loads(first)
            ),
            self.constraints,
        )

    def test_nested_as_dict_mutation_cannot_change_source_constraints(self):
        original_json = self.constraints.to_json()
        snapshot = self.constraints.as_dict()
        item = snapshot["items"][0]

        snapshot["freshness_item_count"] = 999
        snapshot["collection_authorized"] = True
        snapshot["future_semantics"] = "resolved"
        snapshot["security_verdict"] = "secure"
        item["change_node_id"] = "forged-change"
        item["effect_ids"] = ("forged-effect",)
        item["fresh_evidence_required"] = False
        item["capability_selected"] = True
        item["prior_evidence"][0]["evidence_id"] = "forged-evidence"
        item["forbidden_evidence_ids"] = ("forged-evidence",)
        item["forbidden_run_ids"] = ("forged-run",)

        self.assertEqual(self.constraints.to_json(), original_json)
        self.assertFalse(self.constraints.collection_authorized)
        self.assertEqual(self.constraints.future_semantics, "unresolved")
        self.assertEqual(self.constraints.security_verdict, "not_evaluated")
        self.assertTrue(self.constraints.items[0].fresh_evidence_required)
        self.assertFalse(self.constraints.items[0].capability_selected)
        self.assertNotEqual(self.constraints.items[0].change_node_id, "forged-change")

    def test_separate_as_dict_snapshots_do_not_alias_nested_state(self):
        first = self.constraints.as_dict()
        second = self.constraints.as_dict()

        self.assertIsNot(first, second)
        self.assertIsNot(first["items"], second["items"])
        self.assertIsNot(first["items"][0], second["items"][0])
        self.assertIsNot(
            first["items"][0]["prior_evidence"],
            second["items"][0]["prior_evidence"],
        )
        self.assertIsNot(
            first["items"][0]["prior_evidence"][0],
            second["items"][0]["prior_evidence"][0],
        )
        self.assertIsNot(
            first["items"][0]["forbidden_evidence_ids"],
            second["items"][0]["forbidden_evidence_ids"],
        )

        first["items"][0]["prior_evidence"][0]["evidence_id"] = "changed-only-in-first"
        first["items"][0]["forbidden_run_ids"] = ("changed-only-in-first",)

        self.assertEqual(
            second["items"][0]["prior_evidence"][0]["evidence_id"],
            self.constraints.items[0].prior_evidence[0].evidence_id,
        )
        self.assertEqual(
            second["items"][0]["forbidden_run_ids"],
            self.constraints.items[0].forbidden_run_ids,
        )

    def test_parser_detaches_from_all_nested_caller_owned_json_containers(self):
        persisted = json.loads(self.constraints.to_json())
        items = persisted["items"]
        item = items[0]
        effect_ids = item["effect_ids"]
        attack_path_ids = item["current_attack_path_ids"]
        capability_ids = item["prior_capability_ids"]
        prior_evidence = item["prior_evidence"]
        prior = prior_evidence[0]
        forbidden_evidence_ids = item["forbidden_evidence_ids"]
        forbidden_run_ids = item["forbidden_run_ids"]

        parsed = future_security_evidence_freshness_constraints_from_dict(persisted)
        parsed_json = parsed.to_json()

        effect_ids[0] = "forged-effect-after-parse"
        attack_path_ids.append("forged-path-after-parse")
        capability_ids[0] = "forged-capability-after-parse"
        prior["evidence_id"] = "forged-evidence-after-parse"
        prior["run_id"] = "forged-run-after-parse"
        prior["sha256"] = "0" * 64
        prior_evidence.clear()
        forbidden_evidence_ids[0] = "forged-evidence-after-parse"
        forbidden_run_ids[0] = "forged-run-after-parse"
        item["fresh_evidence_required"] = False
        items.clear()

        self.assertEqual(parsed.to_json(), parsed_json)
        self.assertEqual(parsed, self.constraints)
        self.assertEqual(parsed.items[0].effect_ids, self.constraints.items[0].effect_ids)
        self.assertEqual(
            parsed.items[0].prior_evidence,
            self.constraints.items[0].prior_evidence,
        )
        self.assertEqual(
            parsed.items[0].forbidden_evidence_ids,
            self.constraints.items[0].forbidden_evidence_ids,
        )
        self.assertEqual(
            parsed.items[0].forbidden_run_ids,
            self.constraints.items[0].forbidden_run_ids,
        )

    def test_freshness_obligations_and_authority_forgery_fail_closed(self):
        for field in _FALSE_AUTHORITY_FLAGS:
            with self.subTest(field=field):
                payload = json.loads(self.constraints.to_json())
                payload[field] = True
                with self.assertRaises(ValueError):
                    future_security_evidence_freshness_constraints_from_dict(payload)

        for item_field, value in (
            ("fresh_evidence_required", False),
            ("fresh_run_required", False),
            ("capability_selected", True),
            ("outcome_classification_selected", True),
        ):
            with self.subTest(item_field=item_field):
                payload = json.loads(self.constraints.to_json())
                payload["items"][0][item_field] = value
                with self.assertRaises(ValueError):
                    future_security_evidence_freshness_constraints_from_dict(payload)

        for field, value in (
            ("future_semantics", "resolved"),
            ("security_verdict", "secure"),
        ):
            with self.subTest(field=field):
                payload = json.loads(self.constraints.to_json())
                payload[field] = value
                with self.assertRaises(ValueError):
                    future_security_evidence_freshness_constraints_from_dict(payload)

    def test_forbidden_lineage_remains_bound_to_prior_evidence(self):
        original_json = self.constraints.to_json()
        snapshot = self.constraints.as_dict()
        snapshot["items"][0]["forbidden_evidence_ids"] = ("forged-evidence",)
        snapshot["items"][0]["forbidden_run_ids"] = ("forged-run",)

        self.assertEqual(self.constraints.to_json(), original_json)

        wrong_evidence = json.loads(original_json)
        wrong_evidence["items"][0]["forbidden_evidence_ids"] = ["forged-evidence"]
        with self.assertRaisesRegex(ValueError, "must match prior evidence"):
            future_security_evidence_freshness_constraints_from_dict(wrong_evidence)

        wrong_run = json.loads(original_json)
        wrong_run["items"][0]["forbidden_run_ids"] = ["forged-run"]
        with self.assertRaisesRegex(ValueError, "must match prior evidence"):
            future_security_evidence_freshness_constraints_from_dict(wrong_run)


if __name__ == "__main__":
    unittest.main()
