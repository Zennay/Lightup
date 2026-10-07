from __future__ import annotations

import copy
import unittest

import test_future_remediation_text_proposal_handoff as handoff_tests
from lightup.future_remediation_text_proposal_handoff import (
    future_remediation_text_proposal_from_dict,
)


class FutureRemediationTextProposalParserPurityTest(unittest.TestCase):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationTextProposalHandoffTest(
            "test_round_trip_requires_exact_live_lineage"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.proposal = self.base.proposal

    @staticmethod
    def _shape(payload: dict) -> tuple:
        return (id(payload), tuple(payload.keys()))

    def _assert_success_is_pure(self, payload: dict):
        before = copy.deepcopy(payload)
        shape = self._shape(payload)

        parsed = future_remediation_text_proposal_from_dict(payload)

        self.assertEqual(parsed, self.proposal)
        self.assertEqual(payload, before)
        self.assertEqual(self._shape(payload), shape)
        return parsed

    def test_success_preserves_caller_content_identity_and_order(self):
        payload = self.proposal.as_dict()

        first = self._assert_success_is_pure(payload)
        second = self._assert_success_is_pure(payload)

        self.assertEqual(first, second)
        self.assertEqual(first.to_json(), second.to_json())

    def test_late_proposal_digest_rejection_is_repeatably_pure(self):
        payload = self.proposal.as_dict()
        payload["proposal_sha256"] = "0" * 64
        before = copy.deepcopy(payload)
        shape = self._shape(payload)

        errors = []
        for _ in range(2):
            with self.assertRaisesRegex(ValueError, "proposal digest mismatch") as caught:
                future_remediation_text_proposal_from_dict(payload)
            errors.append(str(caught.exception))
            self.assertEqual(payload, before)
            self.assertEqual(self._shape(payload), shape)

        self.assertEqual(errors[0], errors[1])

    def test_content_digest_rejection_is_repeatably_pure(self):
        payload = self.proposal.as_dict()
        payload["content"] += " caller-forged"
        before = copy.deepcopy(payload)
        shape = self._shape(payload)

        errors = []
        for _ in range(2):
            with self.assertRaisesRegex(ValueError, "content digest mismatch") as caught:
                future_remediation_text_proposal_from_dict(payload)
            errors.append(str(caught.exception))
            self.assertEqual(payload, before)
            self.assertEqual(self._shape(payload), shape)

        self.assertEqual(errors[0], errors[1])

    def test_authority_rejection_is_repeatably_pure(self):
        payload = self.proposal.as_dict()
        payload["execution_allowed"] = True
        before = copy.deepcopy(payload)
        shape = self._shape(payload)

        errors = []
        for _ in range(2):
            with self.assertRaisesRegex(ValueError, "authority flag") as caught:
                future_remediation_text_proposal_from_dict(payload)
            errors.append(str(caught.exception))
            self.assertEqual(payload, before)
            self.assertEqual(self._shape(payload), shape)

        self.assertEqual(errors[0], errors[1])


if __name__ == "__main__":
    unittest.main()
