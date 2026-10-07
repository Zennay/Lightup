from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import unittest

import test_future_remediation_text_proposal_handoff as handoff_tests
from lightup.future_remediation_text_proposal_handoff import (
    future_remediation_text_proposal_from_dict,
)


def _rehash_content_and_proposal(payload: dict) -> None:
    payload["content_sha256"] = sha256(
        payload["content"].encode("utf-8")
    ).hexdigest()
    digest_payload = deepcopy(payload)
    digest_payload.pop("proposal_sha256")
    payload["proposal_sha256"] = sha256(
        json.dumps(
            digest_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


class FutureRemediationTextProposalContentNormalizationAcceptanceTest(
    unittest.TestCase
):
    def setUp(self):
        self.h = handoff_tests.FutureRemediationTextProposalHandoffTest(
            "test_round_trip_requires_exact_live_lineage"
        )
        self.h.setUp()
        self.addCleanup(self.h.tearDown)

    def test_canonical_producer_proposal_round_trips(self):
        payload = json.loads(self.h.proposal.to_json())
        self.assertEqual(
            future_remediation_text_proposal_from_dict(payload),
            self.h.proposal,
        )
        self.assertEqual(self.h.proposal.content, self.h.proposal.content.strip())

    def test_content_rejects_producer_impossible_outer_whitespace(self):
        original = self.h.proposal.content
        for label, bad_value in (
            ("leading-space", f" {original}"),
            ("trailing-space", f"{original} "),
            ("outer-tab", f"\t{original}\t"),
        ):
            with self.subTest(shape=label):
                payload = json.loads(self.h.proposal.to_json())
                payload["content"] = bad_value
                _rehash_content_and_proposal(payload)

                with self.assertRaisesRegex(
                    ValueError,
                    "content|canonical|normalized|whitespace",
                ):
                    future_remediation_text_proposal_from_dict(payload)


if __name__ == "__main__":
    unittest.main()
