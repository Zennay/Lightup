from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import unittest

import test_future_remediation_text_proposal as proposal_tests


class FutureRemediationTextProposalDirectIntegrityTest(unittest.TestCase):
    def setUp(self):
        self.base = proposal_tests.FutureRemediationTextProposalTest(
            "test_live_valid_request_generates_bounded_non_executable_proposal"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        gateway, _ = self.base._gateway()
        self.proposal = self.base._generate(gateway)

    def test_valid_direct_proposal_preserves_canonical_metadata(self):
        self.assertGreater(self.proposal.item_count, 0)
        self.assertTrue(self.proposal.provider_id)
        self.assertTrue(self.proposal.model_id)
        self.assertTrue(self.proposal.content)
        self.assertEqual(len(self.proposal.content_sha256), 64)
        self.assertEqual(len(self.proposal.proposal_sha256), 64)

    def test_direct_construction_rejects_schema_forgery(self):
        with self.assertRaisesRegex(ValueError, "schema version mismatch"):
            replace(
                self.proposal,
                schema_version="st5.remediation_text_proposal.v0",
            )

    def test_direct_construction_rejects_noncanonical_digests(self):
        for field in (
            "request_sha256",
            "bundle_sha256",
            "content_sha256",
            "proposal_sha256",
        ):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "canonical lowercase SHA-256"):
                    replace(self.proposal, **{field: "ABC"})

    def test_direct_construction_rejects_item_count_confusion(self):
        for value in (0, -1, True):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "positive integer"):
                    replace(self.proposal, item_count=value)

    def test_direct_construction_rejects_empty_provider_model_or_content(self):
        for field in ("provider_id", "model_id", "content"):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "non-empty string"):
                    replace(self.proposal, **{field: "   "})

    def test_direct_construction_rejects_nul_and_oversized_content(self):
        nul_content = "safe" + "\x00" + "text"
        nul_sha = sha256(nul_content.encode("utf-8")).hexdigest()
        with self.assertRaisesRegex(ValueError, "contains NUL"):
            replace(
                self.proposal,
                content=nul_content,
                content_sha256=nul_sha,
            )

        oversized = "x" * 16001
        oversized_sha = sha256(oversized.encode("utf-8")).hexdigest()
        with self.assertRaisesRegex(ValueError, "bounded output size"):
            replace(
                self.proposal,
                content=oversized,
                content_sha256=oversized_sha,
            )

    def test_direct_construction_recomputes_content_digest(self):
        with self.assertRaisesRegex(ValueError, "content digest mismatch"):
            replace(self.proposal, content=self.proposal.content + " changed")

    def test_direct_construction_recomputes_full_proposal_digest(self):
        with self.assertRaisesRegex(ValueError, "proposal digest mismatch"):
            replace(self.proposal, proposal_sha256="0" * 64)

        changed = self.proposal.content + " changed"
        changed_sha = sha256(changed.encode("utf-8")).hexdigest()
        with self.assertRaisesRegex(ValueError, "proposal digest mismatch"):
            replace(
                self.proposal,
                content=changed,
                content_sha256=changed_sha,
            )

    def test_direct_construction_detects_lineage_change_with_stale_digest(self):
        replacement = "f" * 64
        if replacement == self.proposal.request_sha256:
            replacement = "e" * 64
        with self.assertRaisesRegex(ValueError, "proposal digest mismatch"):
            replace(self.proposal, request_sha256=replacement)


if __name__ == "__main__":
    unittest.main()
