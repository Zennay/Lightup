from __future__ import annotations

from dataclasses import replace
import unittest

import test_future_remediation_authoring_request as authoring_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)


class FutureRemediationAuthoringRequestDirectIntegrityTest(unittest.TestCase):
    def setUp(self):
        self.base = authoring_tests.FutureRemediationAuthoringRequestTest(
            "test_introduced_and_worsened_create_bounded_text_authoring_requests"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        *_, self.request = self.base._request(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="authoring-request-direct-integrity",
        )
        self.item = self.request.items[0]

    def test_valid_request_preserves_canonical_metadata(self):
        self.assertEqual(self.request.item_count, len(self.request.items))
        self.assertTrue(self.request.client_id)
        self.assertTrue(self.request.current_twin_id)
        self.assertTrue(self.request.twin_id)
        self.assertTrue(self.request.changeset_id)
        self.assertEqual(len(self.request.request_sha256), 64)

    def test_direct_construction_rejects_schema_and_identity_forgery(self):
        with self.assertRaisesRegex(ValueError, "schema version mismatch"):
            replace(self.request, schema_version="st5.remediation_authoring_request.v0")

        for field in ("client_id", "current_twin_id", "twin_id", "changeset_id"):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "non-empty string"):
                    replace(self.request, **{field: ""})

    def test_direct_construction_rejects_version_and_count_type_confusion(self):
        with self.assertRaisesRegex(ValueError, "non-negative integer"):
            replace(self.request, current_twin_version=True)
        with self.assertRaisesRegex(ValueError, "non-negative integer"):
            replace(self.request, twin_version=-1)
        with self.assertRaisesRegex(ValueError, "non-negative integer"):
            replace(self.request, item_count=True)

    def test_direct_construction_rejects_noncanonical_top_level_digests(self):
        for field in (
            "report_sha256",
            "plan_sha256",
            "bundle_sha256",
            "request_sha256",
        ):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "canonical lowercase SHA-256"):
                    replace(self.request, **{field: "ABC"})

    def test_direct_construction_rejects_malformed_item_container(self):
        with self.assertRaisesRegex(ValueError, "non-empty tuple"):
            replace(self.request, items=list(self.request.items))
        with self.assertRaisesRegex(ValueError, "non-empty tuple"):
            replace(self.request, items=())
        with self.assertRaisesRegex(
            ValueError,
            "FutureRemediationAuthoringRequestItem",
        ):
            replace(self.request, items=("forged",))

    def test_direct_construction_rejects_duplicate_and_unordered_item_identities(self):
        with self.assertRaisesRegex(ValueError, "identity must be unique"):
            replace(
                self.request,
                items=(self.item, self.item),
                item_count=2,
            )

        earlier = replace(
            self.item,
            change_node_id="0-" + self.item.change_node_id,
        )
        with self.assertRaisesRegex(ValueError, "canonically ordered"):
            replace(
                self.request,
                items=(self.item, earlier),
                item_count=2,
            )

    def test_direct_construction_rejects_item_count_mismatch(self):
        with self.assertRaisesRegex(ValueError, "item count mismatch"):
            replace(self.request, item_count=0)

    def test_direct_construction_recomputes_request_digest(self):
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            replace(self.request, request_sha256="0" * 64)

        changed_item = replace(
            self.item,
            change_node_id=self.item.change_node_id + "-changed",
        )
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            replace(self.request, items=(changed_item,))


if __name__ == "__main__":
    unittest.main()
