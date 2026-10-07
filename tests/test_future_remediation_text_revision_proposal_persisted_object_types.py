from __future__ import annotations

import copy
import json
import unittest

import test_future_remediation_text_revision_proposal_handoff as handoff_tests
from lightup.future_remediation_text_revision_proposal_handoff import (
    future_remediation_text_revision_proposal_from_dict,
)


class _StringSubclass(str):
    pass


class _DictSubclass(dict):
    pass


class FutureRemediationTextRevisionProposalPersistedObjectTypesTest(unittest.TestCase):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationTextRevisionProposalHandoffTest(
            "test_round_trip_requires_complete_live_revision_lineage"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.proposal = self.base.proposal
        self.json_payload = json.loads(self.proposal.to_json())
        self.programmatic_payload = self.proposal.as_dict()

    def _assert_rejected_unchanged(self, payload):
        before = copy.deepcopy(payload)
        with self.assertRaises(ValueError):
            future_remediation_text_revision_proposal_from_dict(payload)
        self.assertEqual(payload, before)

    def test_supported_builtin_json_and_programmatic_forms_remain_green(self):
        self.assertEqual(
            future_remediation_text_revision_proposal_from_dict(
                copy.deepcopy(self.json_payload)
            ),
            self.proposal,
        )
        self.assertEqual(
            future_remediation_text_revision_proposal_from_dict(
                copy.deepcopy(self.programmatic_payload)
            ),
            self.proposal,
        )

    def test_top_level_mapping_and_schema_key_subclasses_fail_closed(self):
        self._assert_rejected_unchanged(
            _DictSubclass(copy.deepcopy(self.json_payload))
        )

        payload = copy.deepcopy(self.json_payload)
        value = payload.pop("provider_id")
        payload[_StringSubclass("provider_id")] = value
        self._assert_rejected_unchanged(payload)

    def test_lineage_and_digest_string_subclasses_fail_closed(self):
        for field in (
            "revision_request_sha256",
            "prior_review_sha256",
            "prior_proposal_sha256",
            "prior_content_sha256",
            "content_sha256",
            "revision_proposal_sha256",
        ):
            with self.subTest(field=field):
                payload = copy.deepcopy(self.json_payload)
                payload[field] = _StringSubclass(payload[field])
                self._assert_rejected_unchanged(payload)

    def test_provenance_content_and_fixed_string_subclasses_fail_closed(self):
        for field in (
            "schema_version",
            "provider_id",
            "model_id",
            "content",
            "future_semantics",
            "security_verdict",
        ):
            with self.subTest(field=field):
                payload = copy.deepcopy(self.json_payload)
                payload[field] = _StringSubclass(payload[field])
                self._assert_rejected_unchanged(payload)


if __name__ == "__main__":
    unittest.main()
