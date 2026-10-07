from __future__ import annotations

import json
import unittest

import test_future_remediation_text_revision_proposal_handoff as handoff_tests
from lightup.future_remediation_text_revision_proposal_handoff import (
    future_remediation_text_revision_proposal_from_dict,
)


class FutureRemediationTextRevisionProposalContentCanonicalityAcceptanceTest(
    unittest.TestCase
):
    def setUp(self):
        self.h = handoff_tests.FutureRemediationTextRevisionProposalHandoffTest(
            "test_round_trip_requires_complete_live_revision_lineage"
        )
        self.h.setUp()
        self.addCleanup(self.h.tearDown)

    def test_canonical_producer_revision_proposal_round_trips(self):
        payload = json.loads(self.h.proposal.to_json())
        self.assertEqual(
            future_remediation_text_revision_proposal_from_dict(payload),
            self.h.proposal,
        )

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

                # Keep both original producer digests. The producer hashes the
                # already-stripped content, while the current persisted handoff
                # strips input before checking those digests. Strict persistence
                # must reject these noncanonical bytes rather than normalize them
                # back under the canonical digests.
                with self.assertRaisesRegex(
                    ValueError,
                    "content|canonical|normalized|whitespace",
                ):
                    future_remediation_text_revision_proposal_from_dict(payload)


if __name__ == "__main__":
    unittest.main()
