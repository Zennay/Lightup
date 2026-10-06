from __future__ import annotations

from dataclasses import replace
import unittest

import test_future_remediation_text_review_handoff as original_handoff_tests
import test_future_remediation_text_revision_review_handoff as revision_handoff_tests
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


_AUTHORITY_FLAGS = (
    "code_change_authorized",
    "tool_call_created",
    "execution_allowed",
    "target_interaction_allowed",
    "future_state_retest_allowed",
    "deployment_authorized",
    "attack_path_mutation_allowed",
)


class FutureRemediationDirectConstructorGateTest(unittest.TestCase):
    def setUp(self):
        self.original = original_handoff_tests.FutureRemediationTextReviewHandoffTest(
            "test_approved_review_round_trips_without_action_authority"
        )
        self.original.setUp()
        self.addCleanup(self.original.tearDown)

        self.revised = (
            revision_handoff_tests.FutureRemediationTextRevisionReviewHandoffTest(
                "test_approved_review_round_trips_without_action_authority"
            )
        )
        self.revised.setUp()
        self.addCleanup(self.revised.tearDown)

    def _original_artifacts(self):
        return (
            self.original.base.base.request,
            self.original.base.proposal,
            self.original.base.review_request,
            self.original.review,
        )

    def _revised_artifacts(self):
        return (
            self.revised.base.base.base.base.base.base.revision_request,
            self.revised.base.base.base.base.base.proposal,
            self.revised.base.base.base.request,
            self.revised.review,
        )

    def _all_artifacts(self):
        return self._original_artifacts() + self._revised_artifacts()

    def test_all_direct_artifacts_round_trip_through_strict_parsers(self):
        parsers = (
            future_remediation_authoring_request_from_json,
            future_remediation_text_proposal_from_json,
            future_remediation_text_review_request_from_json,
            future_remediation_text_review_from_json,
            future_remediation_text_revision_request_from_json,
            future_remediation_text_revision_proposal_from_json,
            future_remediation_text_revision_review_request_from_json,
            future_remediation_text_revision_review_from_json,
        )

        for artifact, parser in zip(self._all_artifacts(), parsers, strict=True):
            with self.subTest(artifact=type(artifact).__name__):
                self.assertEqual(parser(artifact.to_json()), artifact)

    def test_final_reviews_still_pass_complete_live_lineage_validation(self):
        self.assertEqual(self.original._load(), self.original.review)
        self.assertEqual(self.revised._load(), self.revised.review)

    def test_structural_parsing_does_not_replace_live_evidence_validation(self):
        original_evidence = self.original.base.base.bundle.items[0].evidence[0]
        original_replacement = (
            "f" * 64 if original_evidence.sha256 != "f" * 64 else "e" * 64
        )
        with self.original.base.base.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (original_replacement, original_evidence.evidence_id),
            )

        self.assertEqual(
            future_remediation_text_review_from_json(
                self.original.review.to_json()
            ),
            self.original.review,
        )
        with self.assertRaises(ValueError):
            self.original._load()

        revised_evidence = (
            self.revised.base.base.base.base.base.base.base.base.bundle.items[0]
            .evidence[0]
        )
        revised_replacement = (
            "f" * 64 if revised_evidence.sha256 != "f" * 64 else "e" * 64
        )
        with (
            self.revised.base.base.base.base.base.base.base.base.state.connect()
            as con
        ):
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (revised_replacement, revised_evidence.evidence_id),
            )

        self.assertEqual(
            future_remediation_text_revision_review_from_json(
                self.revised.review.to_json()
            ),
            self.revised.review,
        )
        with self.assertRaises(ValueError):
            self.revised._load()

    def test_all_top_level_artifacts_reject_every_authority_widening(self):
        for artifact in self._all_artifacts():
            for field in _AUTHORITY_FLAGS:
                with self.subTest(artifact=type(artifact).__name__, field=field):
                    with self.assertRaisesRegex(ValueError, "authority flag"):
                        replace(artifact, **{field: True})

    def test_all_artifact_structures_remain_bounded_and_payload_free(self):
        forbidden_keys = {
            "source",
            "metadata",
            "payload",
            "credentials",
            "target_arguments",
            "arguments",
            "authorization_ref",
            "patch",
            "command",
            "tool_arguments",
        }

        def collect_keys(value):
            keys = set()
            if isinstance(value, dict):
                keys.update(value)
                for nested in value.values():
                    keys.update(collect_keys(nested))
            elif isinstance(value, (list, tuple)):
                for nested in value:
                    keys.update(collect_keys(nested))
            return keys

        for artifact in self._all_artifacts():
            with self.subTest(artifact=type(artifact).__name__):
                self.assertTrue(forbidden_keys.isdisjoint(collect_keys(artifact.as_dict())))

    def test_all_strict_json_parsers_reject_unknown_top_level_fields(self):
        artifacts_and_parsers = (
            (self._original_artifacts()[0], future_remediation_authoring_request_from_json),
            (self._original_artifacts()[1], future_remediation_text_proposal_from_json),
            (
                self._original_artifacts()[2],
                future_remediation_text_review_request_from_json,
            ),
            (self._original_artifacts()[3], future_remediation_text_review_from_json),
            (
                self._revised_artifacts()[0],
                future_remediation_text_revision_request_from_json,
            ),
            (
                self._revised_artifacts()[1],
                future_remediation_text_revision_proposal_from_json,
            ),
            (
                self._revised_artifacts()[2],
                future_remediation_text_revision_review_request_from_json,
            ),
            (
                self._revised_artifacts()[3],
                future_remediation_text_revision_review_from_json,
            ),
        )

        for artifact, parser in artifacts_and_parsers:
            raw = artifact.to_json()
            widened = raw[:-1] + ',"unexpected_field":"forged"}'
            with self.subTest(artifact=type(artifact).__name__):
                with self.assertRaisesRegex(ValueError, "schema mismatch"):
                    parser(widened)

    def test_all_strict_json_parsers_reject_duplicate_primary_digest_keys(self):
        artifacts_parsers_and_fields = (
            (
                self._original_artifacts()[0],
                future_remediation_authoring_request_from_json,
                "request_sha256",
            ),
            (
                self._original_artifacts()[1],
                future_remediation_text_proposal_from_json,
                "proposal_sha256",
            ),
            (
                self._original_artifacts()[2],
                future_remediation_text_review_request_from_json,
                "review_request_sha256",
            ),
            (
                self._original_artifacts()[3],
                future_remediation_text_review_from_json,
                "review_sha256",
            ),
            (
                self._revised_artifacts()[0],
                future_remediation_text_revision_request_from_json,
                "revision_request_sha256",
            ),
            (
                self._revised_artifacts()[1],
                future_remediation_text_revision_proposal_from_json,
                "revision_proposal_sha256",
            ),
            (
                self._revised_artifacts()[2],
                future_remediation_text_revision_review_request_from_json,
                "review_request_sha256",
            ),
            (
                self._revised_artifacts()[3],
                future_remediation_text_revision_review_from_json,
                "review_sha256",
            ),
        )

        for artifact, parser, field in artifacts_parsers_and_fields:
            raw = artifact.to_json()
            duplicate = (
                raw[:-1]
                + ',"'
                + field
                + '":"'
                + getattr(artifact, field)
                + '"}'
            )
            with self.subTest(artifact=type(artifact).__name__, field=field):
                with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                    parser(duplicate)

    def test_all_top_level_artifacts_reject_integer_authority_lookalikes(self):
        for artifact in self._all_artifacts():
            for field in _AUTHORITY_FLAGS:
                with self.subTest(artifact=type(artifact).__name__, field=field):
                    with self.assertRaisesRegex(ValueError, "authority flag"):
                        replace(artifact, **{field: 0})

    def test_all_top_level_artifacts_reject_future_state_or_verdict_forgery(self):
        for artifact in self._all_artifacts():
            with self.subTest(artifact=type(artifact).__name__, field="future_semantics"):
                with self.assertRaisesRegex(ValueError, "future_semantics"):
                    replace(artifact, future_semantics="resolved")
            with self.subTest(artifact=type(artifact).__name__, field="security_verdict"):
                with self.assertRaisesRegex(ValueError, "security_verdict"):
                    replace(artifact, security_verdict="pass")

    def test_each_artifact_rejects_canonical_shape_but_stale_primary_digest(self):
        artifacts_and_digest_fields = (
            (self._original_artifacts()[0], "request_sha256"),
            (self._original_artifacts()[1], "proposal_sha256"),
            (self._original_artifacts()[2], "review_request_sha256"),
            (self._original_artifacts()[3], "review_sha256"),
            (self._revised_artifacts()[0], "revision_request_sha256"),
            (self._revised_artifacts()[1], "revision_proposal_sha256"),
            (self._revised_artifacts()[2], "review_request_sha256"),
            (self._revised_artifacts()[3], "review_sha256"),
        )

        for artifact, field in artifacts_and_digest_fields:
            current = getattr(artifact, field)
            forged = "0" * 64 if current != "0" * 64 else "f" * 64
            with self.subTest(artifact=type(artifact).__name__, field=field):
                with self.assertRaisesRegex(ValueError, "digest mismatch"):
                    replace(artifact, **{field: forged})

    def test_acceptance_exists_only_on_final_approved_review_objects(self):
        original = self._original_artifacts()
        revised = self._revised_artifacts()

        self.assertTrue(original[-1].remediation_accepted)
        self.assertTrue(revised[-1].remediation_accepted)

        for artifact in original[:-1] + revised[:-1]:
            if hasattr(artifact, "remediation_accepted"):
                with self.subTest(artifact=type(artifact).__name__):
                    self.assertFalse(artifact.remediation_accepted)

    def test_nested_authoring_item_keeps_remediation_and_retest_required(self):
        item = self._original_artifacts()[0].items[0]

        self.assertTrue(item.remediation_required)
        self.assertTrue(item.future_state_retest_required)

        for field, value in (
            ("remediation_required", False),
            ("future_state_retest_required", False),
            ("remediation_required", 1),
            ("future_state_retest_required", 1),
        ):
            with self.subTest(field=field, value=value):
                with self.assertRaises(ValueError):
                    replace(item, **{field: value})


if __name__ == "__main__":
    unittest.main()
