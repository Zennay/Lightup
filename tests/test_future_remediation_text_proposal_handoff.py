from __future__ import annotations

import json
import unittest

import test_future_remediation_text_proposal as proposal_tests
from lightup.future_remediation_text_proposal_handoff import (
    future_remediation_text_proposal_from_dict,
    future_remediation_text_proposal_from_json,
    load_and_validate_future_remediation_text_proposal,
)


class FutureRemediationTextProposalHandoffTest(unittest.TestCase):
    def setUp(self):
        self.base = proposal_tests.FutureRemediationTextProposalTest(
            "test_live_valid_request_generates_bounded_non_executable_proposal"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        gateway, _ = self.base._gateway()
        self.proposal = self.base._generate(gateway)

    def _load(self, persisted):
        return load_and_validate_future_remediation_text_proposal(
            persisted,
            self.base.request,
            self.base.bundle,
            self.base.plan,
            self.base.report,
            self.base.preview,
            self.base.transition_proposal,
            (self.base.resolution,),
            (self.base.context,),
            self.base.state,
        )

    def test_round_trip_requires_exact_live_lineage(self):
        parsed = future_remediation_text_proposal_from_json(
            self.proposal.to_json()
        )
        validated = self._load(self.proposal.to_json())

        self.assertEqual(parsed, self.proposal)
        self.assertEqual(validated, self.proposal)
        self.assertFalse(validated.execution_allowed)
        self.assertFalse(validated.code_change_authorized)
        self.assertFalse(validated.tool_call_created)
        self.assertFalse(validated.target_interaction_allowed)
        self.assertFalse(validated.future_state_retest_allowed)
        self.assertFalse(validated.deployment_authorized)
        self.assertFalse(validated.attack_path_mutation_allowed)

    def test_unknown_missing_and_wrong_primitive_fields_fail_closed(self):
        payload = self.proposal.as_dict()

        extra = dict(payload)
        extra["unexpected"] = "field"
        with self.assertRaisesRegex(ValueError, "schema mismatch"):
            future_remediation_text_proposal_from_dict(extra)

        missing = dict(payload)
        missing.pop("model_id")
        with self.assertRaisesRegex(ValueError, "schema mismatch"):
            future_remediation_text_proposal_from_dict(missing)

        bool_count = dict(payload)
        bool_count["item_count"] = True
        with self.assertRaisesRegex(ValueError, "non-negative integer"):
            future_remediation_text_proposal_from_dict(bool_count)

    def test_content_and_proposal_digest_tampering_is_rejected(self):
        content_tampered = self.proposal.as_dict()
        content_tampered["content"] += " tampered"
        with self.assertRaisesRegex(ValueError, "content digest mismatch"):
            future_remediation_text_proposal_from_dict(content_tampered)

        proposal_tampered = self.proposal.as_dict()
        proposal_tampered["proposal_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "proposal digest mismatch"):
            future_remediation_text_proposal_from_dict(proposal_tampered)

    def test_authority_flags_cannot_be_widened(self):
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
                payload = self.proposal.as_dict()
                payload[field] = True
                with self.assertRaisesRegex(ValueError, "authority flag"):
                    future_remediation_text_proposal_from_dict(payload)

    def test_duplicate_json_keys_are_rejected_before_decode(self):
        raw = self.proposal.to_json()
        duplicate = raw[:-1] + ',"proposal_sha256":"' + ("0" * 64) + '"}'

        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            future_remediation_text_proposal_from_json(duplicate)

    def test_live_evidence_drift_invalidates_persisted_proposal(self):
        evidence_id = self.base.bundle.items[0].evidence[0].evidence_id
        current_sha = self.base.bundle.items[0].evidence[0].sha256
        replacement = "f" * 64 if current_sha != "f" * 64 else "e" * 64
        with self.base.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence_id),
            )

        with self.assertRaises(ValueError):
            self._load(self.proposal.to_json())

    def test_request_or_bundle_lineage_substitution_is_rejected(self):
        payload = json.loads(self.proposal.to_json())

        request_tampered = dict(payload)
        request_tampered["request_sha256"] = "1" * 64
        request_tampered["proposal_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            self._load(request_tampered)

        bundle_tampered = dict(payload)
        bundle_tampered["bundle_sha256"] = "2" * 64
        bundle_tampered["proposal_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            self._load(bundle_tampered)


if __name__ == "__main__":
    unittest.main()
