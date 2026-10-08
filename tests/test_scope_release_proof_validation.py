"""Adversarial metadata tests. The validator is NOT a CI attestation verifier."""
import copy
import unittest

from scope_release_proof_validation import validate_proof_record


SOURCE = "a" * 40
TEST = "b" * 40
GOOD = {
    "source_sha": SOURCE,
    "test_sha": TEST,
    "canonical_run_url": "https://github.com/Zennay/Lightup/actions/runs/123456",
    "conclusion": "success",
    "runner_kind": "self-hosted",
    "python_version": "3.11",
    "observed_at": "2026-10-08T00:00:00Z",
    "gate_ids": ["tenant_lineage"],
}


class ProofMetadataTests(unittest.TestCase):
    def check(self, value):
        return validate_proof_record(value, expected_source_sha=SOURCE, expected_test_sha=TEST)

    def test_canonical_record_is_structurally_valid_not_attested(self):
        self.assertTrue(self.check(GOOD))

    def test_stale_head_and_test_sha_rejected(self):
        for field, value in (("source_sha", "c" * 40), ("test_sha", "c" * 40)):
            with self.subTest(field=field):
                bad = dict(GOOD, **{field: value})
                self.assertFalse(self.check(bad))

    def test_noncanonical_runner_or_ci_conclusion_rejected(self):
        for field, values in {
            "conclusion": ["queued", "cancelled", "skipped", "failure", "stale_head", True, None],
            "runner_kind": ["hosted", "ubuntu-latest", "SELF-HOSTED", None],
            "python_version": ["3.10", "3.11.0", "", None],
            "canonical_run_url": ["https://evil.test/123", "https://github.com/Zennay/Lightup/actions/runs/0", ""],
        }.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    self.assertFalse(self.check(dict(GOOD, **{field: value})))

    def test_missing_extra_and_polymorphic_metadata_rejected(self):
        missing = dict(GOOD)
        del missing["gate_ids"]
        self.assertFalse(self.check(missing))
        self.assertFalse(self.check(dict(GOOD, approved=True)))
        self.assertFalse(self.check([]))
        self.assertFalse(self.check(dict(GOOD, gate_ids=["tenant_lineage", "tenant_lineage"])))
        self.assertFalse(self.check(dict(GOOD, observed_at="yesterday")))
        self.assertFalse(self.check(dict(GOOD, gate_ids=[1])))
        self.assertFalse(self.check(dict(GOOD, source_sha=True)))

    def test_never_mutates_caller_record(self):
        candidate = copy.deepcopy(GOOD)
        before = copy.deepcopy(candidate)
        self.check(candidate)
        self.assertEqual(candidate, before)


if __name__ == "__main__":
    unittest.main()
