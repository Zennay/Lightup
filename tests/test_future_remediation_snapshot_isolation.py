from __future__ import annotations

import json
import unittest

import test_future_remediation_direct_constructor_gate as gate_tests
from lightup.future_remediation_authoring_request_handoff import (
    future_remediation_authoring_request_from_json,
)
from lightup.future_remediation_text_proposal_handoff import (
    future_remediation_text_proposal_from_json,
)
from lightup.future_remediation_text_review_request_handoff import (
    future_remediation_text_review_request_from_json,
)
from lightup.future_remediation_text_review_handoff import (
    future_remediation_text_review_from_json,
)
from lightup.future_remediation_text_revision_request_handoff import (
    future_remediation_text_revision_request_from_json,
)
from lightup.future_remediation_text_revision_proposal_handoff import (
    future_remediation_text_revision_proposal_from_json,
)
from lightup.future_remediation_text_revision_review_request_handoff import (
    future_remediation_text_revision_review_request_from_json,
)
from lightup.future_remediation_text_revision_review_handoff import (
    future_remediation_text_revision_review_from_json,
)


class FutureRemediationSnapshotIsolationTest(unittest.TestCase):
    def setUp(self):
        self.gate = gate_tests.FutureRemediationDirectConstructorGateTest(
            "test_all_direct_artifacts_round_trip_through_strict_parsers"
        )
        self.gate.setUp()
        self.addCleanup(self.gate.tearDown)

    def _artifacts_and_parsers(self):
        return tuple(
            zip(
                self.gate._all_artifacts(),
                (
                    future_remediation_authoring_request_from_json,
                    future_remediation_text_proposal_from_json,
                    future_remediation_text_review_request_from_json,
                    future_remediation_text_review_from_json,
                    future_remediation_text_revision_request_from_json,
                    future_remediation_text_revision_proposal_from_json,
                    future_remediation_text_revision_review_request_from_json,
                    future_remediation_text_revision_review_from_json,
                ),
                strict=True,
            )
        )

    def test_all_top_level_json_is_byte_deterministic_and_canonical(self):
        for artifact, parser in self._artifacts_and_parsers():
            with self.subTest(artifact=type(artifact).__name__):
                first = artifact.to_json()
                second = artifact.to_json()
                self.assertEqual(first, second)
                self.assertEqual(
                    first,
                    json.dumps(
                        json.loads(first),
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=True,
                    ),
                )
                self.assertEqual(parser(first), artifact)

    def test_top_level_snapshot_mutation_cannot_change_artifact_or_json(self):
        for artifact, parser in self._artifacts_and_parsers():
            with self.subTest(artifact=type(artifact).__name__):
                baseline = artifact.to_json()
                snapshot = artifact.as_dict()
                snapshot["future_semantics"] = "resolved"
                snapshot["security_verdict"] = "pass"
                self.assertEqual(artifact.to_json(), baseline)
                self.assertEqual(parser(baseline), artifact)

    def test_authoring_item_and_evidence_snapshot_mutation_is_deeply_isolated(self):
        request = self.gate._original_artifacts()[0]
        baseline = request.to_json()
        snapshot = request.as_dict()

        snapshot["items"][0]["change_node_id"] = "forged-change"
        snapshot["items"][0]["capability_ids"] = ("forged-capability",)
        snapshot["items"][0]["evidence"][0]["evidence_id"] = "forged-evidence"
        snapshot["items"][0]["evidence"][0]["sha256"] = "0" * 64

        self.assertEqual(request.to_json(), baseline)
        self.assertNotEqual(
            snapshot["items"][0]["change_node_id"],
            request.items[0].change_node_id,
        )
        self.assertNotEqual(
            snapshot["items"][0]["evidence"][0]["evidence_id"],
            request.items[0].evidence[0].evidence_id,
        )
        self.assertEqual(
            future_remediation_authoring_request_from_json(baseline),
            request,
        )

    def test_original_review_check_snapshot_mutation_is_deeply_isolated(self):
        review = self.gate._original_artifacts()[-1]
        baseline = review.to_json()
        snapshot = review.as_dict()

        snapshot["checks"][0]["result"] = "fail"
        snapshot["checks"][0]["check"] = "forged-check"
        snapshot["summary"] = "forged summary"

        self.assertEqual(review.to_json(), baseline)
        self.assertNotEqual(snapshot["checks"][0]["result"], review.checks[0].result)
        self.assertEqual(future_remediation_text_review_from_json(baseline), review)

    def test_revised_review_check_snapshot_mutation_is_deeply_isolated(self):
        review = self.gate._revised_artifacts()[-1]
        baseline = review.to_json()
        snapshot = review.as_dict()

        snapshot["checks"][0]["result"] = "fail"
        snapshot["checks"][0]["check"] = "forged-check"
        snapshot["summary"] = "forged revised summary"

        self.assertEqual(review.to_json(), baseline)
        self.assertNotEqual(snapshot["checks"][0]["result"], review.checks[0].result)
        self.assertEqual(
            future_remediation_text_revision_review_from_json(baseline),
            review,
        )

    def test_repeated_snapshots_are_independent_copies(self):
        for artifact, _ in self._artifacts_and_parsers():
            with self.subTest(artifact=type(artifact).__name__):
                first = artifact.as_dict()
                second = artifact.as_dict()
                self.assertEqual(first, second)
                self.assertIsNot(first, second)

                first["future_semantics"] = "mutated"
                self.assertEqual(second["future_semantics"], "unresolved")
                self.assertEqual(artifact.future_semantics, "unresolved")


if __name__ == "__main__":
    unittest.main()
