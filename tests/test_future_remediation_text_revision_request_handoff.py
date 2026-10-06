from __future__ import annotations

import unittest

import test_future_remediation_text_revision_request as revision_tests
import test_future_remediation_text_review as review_tests
from lightup.future_remediation_text_revision_request_handoff import (
    future_remediation_text_revision_request_from_dict,
    future_remediation_text_revision_request_from_json,
    load_and_validate_future_remediation_text_revision_request,
)


class FutureRemediationTextRevisionRequestHandoffTest(unittest.TestCase):
    def setUp(self):
        self.base = revision_tests.FutureRemediationTextRevisionRequestTest(
            "test_revision_required_creates_bounded_non_executable_request"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.review = self.base._review(
            review_tests._review_json(
                decision="revision_required",
                unsupported_claims="fail",
            )
        )
        self.request = self.base._build(self.review)

    def _load(self, persisted=None, *, review=None):
        return load_and_validate_future_remediation_text_revision_request(
            self.request.to_json() if persisted is None else persisted,
            self.review.to_json() if review is None else review,
            self.base.base.review_request.to_json(),
            self.base.base.proposal.to_json(),
            self.base.base.base.request,
            self.base.base.base.bundle,
            self.base.base.base.plan,
            self.base.base.base.report,
            self.base.base.base.preview,
            self.base.base.base.transition_proposal,
            (self.base.base.base.resolution,),
            (self.base.base.base.context,),
            self.base.base.base.state,
        )

    def test_round_trip_requires_exact_live_review_lineage(self):
        parsed = future_remediation_text_revision_request_from_json(
            self.request.to_json()
        )
        validated = self._load()

        self.assertEqual(parsed, self.request)
        self.assertEqual(validated, self.request)
        self.assertTrue(validated.revision_requested)
        self.assertFalse(validated.remediation_accepted)
        self.assertFalse(validated.code_change_authorized)
        self.assertFalse(validated.tool_call_created)
        self.assertFalse(validated.execution_allowed)
        self.assertFalse(validated.target_interaction_allowed)
        self.assertFalse(validated.future_state_retest_allowed)
        self.assertFalse(validated.deployment_authorized)
        self.assertFalse(validated.attack_path_mutation_allowed)

    def test_programmatic_and_json_forms_are_equivalent(self):
        from_dict = future_remediation_text_revision_request_from_dict(
            self.request.as_dict()
        )
        from_json = future_remediation_text_revision_request_from_json(
            self.request.to_json()
        )

        self.assertEqual(from_dict, from_json)
        self.assertEqual(from_dict, self.request)

    def test_schema_digest_and_authority_tampering_fail_closed(self):
        extra = self.request.as_dict()
        extra["unexpected"] = "field"
        with self.assertRaisesRegex(ValueError, "schema mismatch"):
            future_remediation_text_revision_request_from_dict(extra)

        digest = self.request.as_dict()
        digest["revision_request_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            future_remediation_text_revision_request_from_dict(digest)

        for field in (
            "code_change_authorized",
            "tool_call_created",
            "execution_allowed",
            "target_interaction_allowed",
            "future_state_retest_allowed",
            "deployment_authorized",
            "attack_path_mutation_allowed",
        ):
            with self.subTest(field=field):
                widened = self.request.as_dict()
                widened[field] = True
                with self.assertRaisesRegex(ValueError, "authority flag"):
                    future_remediation_text_revision_request_from_dict(widened)

    def test_revision_checks_must_be_unique_known_and_canonically_ordered(self):
        duplicate = self.request.as_dict()
        duplicate["revision_checks"] = [
            "unsupported_claims",
            "unsupported_claims",
        ]
        with self.assertRaisesRegex(ValueError, "must be unique"):
            future_remediation_text_revision_request_from_dict(duplicate)

        unknown = self.request.as_dict()
        unknown["revision_checks"] = ["not_a_real_check"]
        with self.assertRaisesRegex(ValueError, "invalid or out of order"):
            future_remediation_text_revision_request_from_dict(unknown)

        out_of_order = self.request.as_dict()
        out_of_order["revision_checks"] = [
            "future_retest_separation",
            "unsupported_claims",
        ]
        with self.assertRaisesRegex(ValueError, "invalid or out of order"):
            future_remediation_text_revision_request_from_dict(out_of_order)

    def test_duplicate_json_keys_are_rejected_before_decode(self):
        raw = self.request.to_json()
        duplicate = (
            raw[:-1]
            + ',"revision_request_sha256":"'
            + ("0" * 64)
            + '"}'
        )

        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            future_remediation_text_revision_request_from_json(duplicate)

    def test_live_evidence_drift_invalidates_persisted_revision_request(self):
        evidence_id = self.base.base.base.bundle.items[0].evidence[0].evidence_id
        current_sha = self.base.base.base.bundle.items[0].evidence[0].sha256
        replacement = "f" * 64 if current_sha != "f" * 64 else "e" * 64
        with self.base.base.base.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence_id),
            )

        with self.assertRaises(ValueError):
            self._load()

    def test_review_substitution_invalidates_revision_request(self):
        alternate = self.base._review(
            review_tests._review_json(
                decision="revision_required",
                least_privilege="fail",
            )
        )

        with self.assertRaisesRegex(ValueError, "does not match"):
            self._load(review=alternate.to_json())


if __name__ == "__main__":
    unittest.main()
