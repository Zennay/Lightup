from __future__ import annotations

from copy import deepcopy
import unittest

import test_future_remediation_implementation_plan_revision_proposal as proposal_tests
from lightup.future_remediation_implementation_plan_revision_proposal_handoff import (
    future_remediation_implementation_plan_revision_proposal_from_dict,
    future_remediation_implementation_plan_revision_proposal_from_json,
    load_and_validate_future_remediation_implementation_plan_revision_proposal,
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


class FutureRemediationImplementationPlanRevisionProposalHandoffTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = proposal_tests.FutureRemediationImplementationPlanRevisionProposalTest(
            "test_live_revision_request_generates_unaccepted_non_executable_revised_plan"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        gateway, provider = self.base._gateway()
        self.revised_plan = self.base._generate(gateway)
        self.assertEqual(len(provider.requests), 1)

    def _load(
        self,
        persisted=None,
        persisted_revision_request=None,
        persisted_plan=None,
    ):
        return load_and_validate_future_remediation_implementation_plan_revision_proposal(
            self.revised_plan.to_json() if persisted is None else persisted,
            self.base.revision_request.to_json()
            if persisted_revision_request is None
            else persisted_revision_request,
            self.base.review.to_json(),
            self.base.plan_review_request.to_json(),
            self.base.prior_plan.to_json()
            if persisted_plan is None
            else persisted_plan,
            self.base.planning_request.to_json(),
            self.base.remediation_review.to_json(),
            self.base.remediation_review_request.to_json(),
            self.base.proposal.to_json(),
            self.base.root.request,
            self.base.root.bundle,
            self.base.root.plan,
            self.base.root.report,
            self.base.root.preview,
            self.base.root.transition_proposal,
            (self.base.root.resolution,),
            (self.base.root.context,),
            self.base.root.state,
        )

    def test_json_and_dict_round_trip_require_live_revision_lineage(self):
        from_json = (
            future_remediation_implementation_plan_revision_proposal_from_json(
                self.revised_plan.to_json()
            )
        )
        from_dict = (
            future_remediation_implementation_plan_revision_proposal_from_dict(
                self.revised_plan.as_dict()
            )
        )
        validated = self._load()

        self.assertEqual(from_json, self.revised_plan)
        self.assertEqual(from_dict, self.revised_plan)
        self.assertEqual(validated, self.revised_plan)
        self.assertTrue(validated.revised_implementation_plan_created)
        self.assertFalse(validated.implementation_plan_accepted)
        for field in _AUTHORITY_FLAGS:
            self.assertFalse(getattr(validated, field))
        self.assertEqual(validated.future_semantics, "unresolved")
        self.assertEqual(validated.security_verdict, "not_evaluated")

    def test_schema_digest_lifecycle_and_authority_tampering_fail_closed(self):
        extra = self.revised_plan.as_dict()
        extra["unexpected"] = "field"
        with self.assertRaisesRegex(ValueError, "schema mismatch"):
            future_remediation_implementation_plan_revision_proposal_from_dict(
                extra
            )

        missing = self.revised_plan.as_dict()
        missing.pop("prior_plan_sha256")
        with self.assertRaisesRegex(ValueError, "schema mismatch"):
            future_remediation_implementation_plan_revision_proposal_from_dict(
                missing
            )

        digest = self.revised_plan.as_dict()
        digest["revised_plan_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            future_remediation_implementation_plan_revision_proposal_from_dict(
                digest
            )

        accepted = self.revised_plan.as_dict()
        accepted["implementation_plan_accepted"] = True
        with self.assertRaisesRegex(ValueError, "accepted"):
            future_remediation_implementation_plan_revision_proposal_from_dict(
                accepted
            )

        not_created = self.revised_plan.as_dict()
        not_created["revised_implementation_plan_created"] = False
        with self.assertRaisesRegex(ValueError, "created"):
            future_remediation_implementation_plan_revision_proposal_from_dict(
                not_created
            )

        for field in _AUTHORITY_FLAGS:
            with self.subTest(field=field):
                widened = self.revised_plan.as_dict()
                widened[field] = True
                with self.assertRaisesRegex(ValueError, "authority flag"):
                    future_remediation_implementation_plan_revision_proposal_from_dict(
                        widened
                    )

    def test_text_and_provenance_must_remain_canonical_not_normalized(self):
        for field in ("provider_id", "model_id", "summary"):
            with self.subTest(field=field):
                padded = self.revised_plan.as_dict()
                padded[field] = f" {padded[field]}"
                with self.assertRaisesRegex(ValueError, "canonical trimmed"):
                    future_remediation_implementation_plan_revision_proposal_from_dict(
                        padded
                    )

        padded_item = self.revised_plan.as_dict()
        padded_item["plan_items"][0]["intent"] += " "
        with self.assertRaisesRegex(ValueError, "canonical trimmed"):
            future_remediation_implementation_plan_revision_proposal_from_dict(
                padded_item
            )

        padded_assumption = self.revised_plan.as_dict()
        padded_assumption["assumptions"][0] += " "
        with self.assertRaisesRegex(ValueError, "canonical trimmed"):
            future_remediation_implementation_plan_revision_proposal_from_dict(
                padded_assumption
            )

    def test_plan_item_schema_identity_and_change_area_fail_closed(self):
        extra = self.revised_plan.as_dict()
        extra["plan_items"][0]["command"] = "apply"
        with self.assertRaisesRegex(ValueError, "item schema mismatch"):
            future_remediation_implementation_plan_revision_proposal_from_dict(
                extra
            )

        duplicate = self.revised_plan.as_dict()
        duplicate["plan_items"] = (
            duplicate["plan_items"][0],
            dict(duplicate["plan_items"][0]),
        )
        with self.assertRaisesRegex(ValueError, "IDs must be unique"):
            future_remediation_implementation_plan_revision_proposal_from_dict(
                duplicate
            )

        invalid_area = self.revised_plan.as_dict()
        invalid_area["plan_items"][0]["change_area"] = "target_exploitation"
        with self.assertRaisesRegex(ValueError, "change_area is invalid"):
            future_remediation_implementation_plan_revision_proposal_from_dict(
                invalid_area
            )

    def test_duplicate_json_keys_are_rejected(self):
        raw = self.revised_plan.to_json()
        duplicate = (
            raw[:-1]
            + ',"revised_plan_sha256":"'
            + ("0" * 64)
            + '"}'
        )

        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            future_remediation_implementation_plan_revision_proposal_from_json(
                duplicate
            )

    def test_dict_parser_is_input_pure_on_success_and_rejection(self):
        payload = self.revised_plan.as_dict()
        snapshot = deepcopy(payload)

        first = (
            future_remediation_implementation_plan_revision_proposal_from_dict(
                payload
            )
        )
        second = (
            future_remediation_implementation_plan_revision_proposal_from_dict(
                payload
            )
        )
        self.assertEqual(first, self.revised_plan)
        self.assertEqual(second, self.revised_plan)
        self.assertEqual(payload, snapshot)

        rejected = self.revised_plan.as_dict()
        rejected["plan_items"][0]["intent"] += " "
        rejected_snapshot = deepcopy(rejected)
        for _ in range(2):
            with self.assertRaisesRegex(ValueError, "canonical trimmed"):
                future_remediation_implementation_plan_revision_proposal_from_dict(
                    rejected
                )
            self.assertEqual(rejected, rejected_snapshot)

    def test_live_evidence_drift_invalidates_revised_plan_without_model_reexecution(self):
        evidence = self.base.root.bundle.items[0].evidence[0]
        replacement = "f" * 64 if evidence.sha256 != "f" * 64 else "e" * 64
        with self.base.root.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence.evidence_id),
            )

        with self.assertRaises(ValueError):
            self._load()

    def test_revision_request_and_prior_plan_substitution_fail_closed(self):
        revision_request = self.base.revision_request.as_dict()
        revision_request["revision_request_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            self._load(persisted_revision_request=revision_request)

        prior_plan = self.base.prior_plan.as_dict()
        prior_plan["plan_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            self._load(persisted_plan=prior_plan)

    def test_persisted_value_type_is_exactly_json_text_or_object(self):
        with self.assertRaisesRegex(ValueError, "JSON text or object"):
            self._load(persisted=[])


if __name__ == "__main__":
    unittest.main()
