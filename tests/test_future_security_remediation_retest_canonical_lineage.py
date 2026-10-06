from __future__ import annotations

import copy
from hashlib import sha256
import json
import unittest

import test_future_security_remediation_retest_plan_handoff as handoff_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_security_remediation_retest_plan_handoff import (
    future_security_remediation_retest_plan_from_dict,
)


def _rehash(payload: dict) -> str:
    digest_payload = copy.deepcopy(payload)
    digest_payload.pop("plan_sha256")
    return sha256(
        json.dumps(
            digest_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


class FutureSecurityRemediationRetestCanonicalLineageAcceptanceTest(
    unittest.TestCase
):
    def setUp(self):
        self.h = handoff_tests.FutureSecurityRemediationRetestPlanHandoffTest(
            "test_round_trip_accepts_exact_builder_output"
        )
        self.h.setUp()
        self.addCleanup(self.h.tearDown)

    def _payload(self, classification, *, suffix):
        plan = self.h._plan(classification, suffix=suffix)
        return plan, json.loads(plan.to_json())

    def test_canonical_producer_payloads_still_round_trip(self):
        for classification in AttackPathTransitionClassification:
            with self.subTest(classification=classification.value):
                plan, payload = self._payload(
                    classification,
                    suffix=f"canonical-lineage-ok-{classification.value}",
                )
                self.assertEqual(
                    future_security_remediation_retest_plan_from_dict(payload),
                    plan,
                )

    def test_nonblank_noncanonical_scalar_lineage_fails_with_matching_digest(self):
        cases = (
            ("client_id", lambda value: f" {value}"),
            ("current_twin_id", lambda value: f"{value} "),
            ("twin_id", lambda value: f"{value}\nembedded"),
            ("changeset_id", lambda _value: "x" * 257),
        )

        for field, mutate in cases:
            with self.subTest(field=field):
                _, payload = self._payload(
                    AttackPathTransitionClassification.WORSENED,
                    suffix=f"canonical-lineage-top-{field}",
                )
                payload[field] = mutate(payload[field])
                payload["plan_sha256"] = _rehash(payload)

                with self.assertRaisesRegex(
                    ValueError,
                    "canonical|control|256|whitespace|identifier",
                ):
                    future_security_remediation_retest_plan_from_dict(payload)

    def test_nonblank_noncanonical_item_lineage_fails_with_matching_digest(self):
        cases = (
            ("change_node_id", lambda value: f" {value}"),
            ("subject_node_id", lambda value: f"{value} "),
            ("resolution_id", lambda value: f"{value}\u0007embedded"),
        )

        for field, mutate in cases:
            with self.subTest(field=field):
                _, payload = self._payload(
                    AttackPathTransitionClassification.WORSENED,
                    suffix=f"canonical-lineage-item-{field}",
                )
                payload["items"][0][field] = mutate(payload["items"][0][field])
                payload["plan_sha256"] = _rehash(payload)

                with self.assertRaisesRegex(
                    ValueError,
                    "canonical|control|256|whitespace|identifier",
                ):
                    future_security_remediation_retest_plan_from_dict(payload)

    def test_lineage_collection_values_preserve_canonical_identifier_shape(self):
        for field in (
            "current_attack_path_ids",
            "effect_ids",
            "evidence_ids",
            "capability_ids",
        ):
            with self.subTest(field=field):
                _, payload = self._payload(
                    AttackPathTransitionClassification.WORSENED,
                    suffix=f"canonical-lineage-list-{field}",
                )
                self.assertTrue(payload["items"][0][field])
                original = payload["items"][0][field][0]
                payload["items"][0][field][0] = f" {original}"
                payload["plan_sha256"] = _rehash(payload)

                with self.assertRaisesRegex(
                    ValueError,
                    "canonical|control|256|whitespace|identifier",
                ):
                    future_security_remediation_retest_plan_from_dict(payload)

    def test_unsorted_lineage_collections_fail_with_matching_digest(self):
        for field in (
            "current_attack_path_ids",
            "effect_ids",
            "evidence_ids",
            "capability_ids",
        ):
            with self.subTest(field=field):
                _, payload = self._payload(
                    AttackPathTransitionClassification.WORSENED,
                    suffix=f"canonical-lineage-order-{field}",
                )
                payload["items"][0][field] = ["z-lineage-id", "a-lineage-id"]
                payload["plan_sha256"] = _rehash(payload)

                with self.assertRaisesRegex(ValueError, "sorted|canonical"):
                    future_security_remediation_retest_plan_from_dict(payload)


if __name__ == "__main__":
    unittest.main()
