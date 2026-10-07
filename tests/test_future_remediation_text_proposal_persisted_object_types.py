from __future__ import annotations

import copy
import json
import unittest

import test_future_remediation_text_proposal_handoff as handoff_tests
from lightup.future_remediation_text_proposal_handoff import (
    future_remediation_text_proposal_from_dict,
)


class _StringSubclass(str):
    pass


class _IntSubclass(int):
    pass


class _DictSubclass(dict):
    pass


class FutureRemediationTextProposalPersistedObjectTypesTest(unittest.TestCase):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationTextProposalHandoffTest(
            "test_round_trip_requires_exact_live_lineage"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.proposal = self.base.proposal
        self.payload = json.loads(self.proposal.to_json())

    def _assert_rejected_unchanged(self, payload):
        before = copy.deepcopy(payload)
        with self.assertRaises(ValueError):
            future_remediation_text_proposal_from_dict(payload)
        self.assertEqual(payload, before)

    def test_canonical_json_decoded_object_remains_green(self):
        parsed = future_remediation_text_proposal_from_dict(
            copy.deepcopy(self.payload)
        )
        self.assertEqual(parsed, self.proposal)

    def test_top_level_mapping_subclass_fails_closed(self):
        self._assert_rejected_unchanged(_DictSubclass(copy.deepcopy(self.payload)))

    def test_top_level_schema_key_subclass_fails_closed(self):
        payload = copy.deepcopy(self.payload)
        value = payload.pop("provider_id")
        payload[_StringSubclass("provider_id")] = value
        self._assert_rejected_unchanged(payload)

    def test_lineage_and_digest_string_subclasses_fail_closed(self):
        for field in (
            "request_sha256",
            "bundle_sha256",
            "content_sha256",
            "proposal_sha256",
        ):
            with self.subTest(field=field):
                payload = copy.deepcopy(self.payload)
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
                payload = copy.deepcopy(self.payload)
                payload[field] = _StringSubclass(payload[field])
                self._assert_rejected_unchanged(payload)

    def test_item_count_integer_subclass_fails_closed(self):
        payload = copy.deepcopy(self.payload)
        payload["item_count"] = _IntSubclass(payload["item_count"])
        self._assert_rejected_unchanged(payload)


if __name__ == "__main__":
    unittest.main()
