from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import unittest

import test_future_remediation_authoring_request as request_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_remediation_authoring_request_handoff import (
    future_remediation_authoring_request_from_dict,
)


def _digest_json(value: object) -> str:
    return sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _rehash_item_evidence(item: dict) -> None:
    item["evidence_manifest_sha256"] = _digest_json(item["evidence"])


def _rehash_request(payload: dict) -> None:
    digest_payload = deepcopy(payload)
    digest_payload.pop("request_sha256")
    payload["request_sha256"] = _digest_json(digest_payload)


def _alternate_resolution_id(value: str) -> str:
    prefix, separator, suffix = value.rpartition(":")
    if (
        separator != ":"
        or prefix != "transition-resolution"
        or len(suffix) != 24
        or any(character not in "0123456789abcdef" for character in suffix)
    ):
        raise AssertionError(f"unexpected canonical producer resolution id: {value!r}")
    replacement = "0" if suffix[0] != "0" else "1"
    return f"{prefix}:{replacement}{suffix[1:]}"


class FutureRemediationAuthoringRequestCrossItemLineageAcceptanceTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = request_tests.FutureRemediationAuthoringRequestTest(
            "test_request_is_deterministic_and_export_is_bounded"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _payload(self, *, suffix: str) -> tuple[object, dict]:
        produced = self.base._request(
            AttackPathTransitionClassification.WORSENED,
            suffix=suffix,
        )
        request = produced[-1]
        payload = json.loads(request.to_json())
        self.assertEqual(len(payload["items"]), 1)
        self.assertTrue(payload["items"][0]["current_attack_path_ids"])
        return request, payload

    def _append_distinct_item(
        self,
        payload: dict,
        *,
        duplicate_change: bool = False,
        duplicate_resolution: bool = False,
        duplicate_current_path: bool = False,
    ) -> None:
        original = payload["items"][0]
        cloned = deepcopy(original)

        cloned["change_node_id"] = (
            original["change_node_id"]
            if duplicate_change
            else f'{original["change_node_id"]}-alt'
        )
        cloned["subject_node_id"] = f'{original["subject_node_id"]}-alt'
        cloned["resolution_id"] = (
            original["resolution_id"]
            if duplicate_resolution
            else _alternate_resolution_id(original["resolution_id"])
        )
        cloned["current_attack_path_ids"] = (
            list(original["current_attack_path_ids"])
            if duplicate_current_path
            else [
                f"{path_id}-alt"
                for path_id in original["current_attack_path_ids"]
            ]
        )

        for evidence in cloned["evidence"]:
            evidence["evidence_id"] = f'{evidence["evidence_id"]}-alt'
        _rehash_item_evidence(cloned)

        payload["items"].append(cloned)
        payload["items"].sort(
            key=lambda item: (
                item["change_node_id"],
                item["subject_node_id"],
                item["resolution_id"],
            )
        )
        payload["item_count"] = len(payload["items"])
        _rehash_request(payload)

    def test_canonical_single_item_request_round_trips(self):
        request, payload = self._payload(
            suffix="authoring-cross-item-lineage-control"
        )
        self.assertEqual(
            future_remediation_authoring_request_from_dict(payload),
            request,
        )

    def test_distinct_items_cannot_reuse_change_node_id(self):
        _, payload = self._payload(
            suffix="authoring-cross-item-lineage-duplicate-change"
        )
        self._append_distinct_item(payload, duplicate_change=True)

        with self.assertRaisesRegex(
            ValueError,
            "change|unique|lineage|identity",
        ):
            future_remediation_authoring_request_from_dict(payload)

    def test_distinct_items_cannot_reuse_resolution_id(self):
        _, payload = self._payload(
            suffix="authoring-cross-item-lineage-duplicate-resolution"
        )
        self._append_distinct_item(payload, duplicate_resolution=True)

        with self.assertRaisesRegex(
            ValueError,
            "resolution|unique|lineage|identity",
        ):
            future_remediation_authoring_request_from_dict(payload)

    def test_different_changes_cannot_reuse_current_attack_path_id(self):
        _, payload = self._payload(
            suffix="authoring-cross-item-lineage-duplicate-current-path"
        )
        self._append_distinct_item(payload, duplicate_current_path=True)

        with self.assertRaisesRegex(
            ValueError,
            "current|attack|path|unique|lineage|identity",
        ):
            future_remediation_authoring_request_from_dict(payload)


if __name__ == "__main__":
    unittest.main()
