from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import unittest

import test_future_remediation_text_revision_proposal_handoff as handoff_tests
from lightup.future_remediation_text_revision_proposal_handoff import (
    future_remediation_text_revision_proposal_from_dict,
)


def _rehash(payload: dict) -> None:
    digest_payload = deepcopy(payload)
    digest_payload.pop("revision_proposal_sha256")
    payload["revision_proposal_sha256"] = sha256(
        json.dumps(
            digest_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


class FutureRemediationTextRevisionProposalModelIdentityAcceptanceTest(
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

    def test_model_id_rejects_producer_impossible_outer_whitespace(self):
        original = self.h.proposal.model_id
        for label, bad_value in (
            ("leading-space", f" {original}"),
            ("trailing-space", f"{original} "),
            ("outer-tab", f"\t{original}\t"),
        ):
            with self.subTest(shape=label):
                payload = json.loads(self.h.proposal.to_json())
                payload["model_id"] = bad_value
                _rehash(payload)

                with self.assertRaisesRegex(
                    ValueError,
                    "model_id|model|canonical|normalized|whitespace",
                ):
                    future_remediation_text_revision_proposal_from_dict(payload)


if __name__ == "__main__":
    unittest.main()
