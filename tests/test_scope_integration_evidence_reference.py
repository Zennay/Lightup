"""Offline evidence-gate reference; never used for runtime authorization.

No production modules, sockets or targets are imported or accessed.
"""
import unittest
import re


REQUIRED = frozenset({
    "production_owner", "base_sha", "head_sha",
    "hosted_py311", "hosted_py314", "canonical_vps",
    "issuer_provenance", "dispatch_revocation",
    "purpose_isolation", "independent_approval",
})


def evidence_ready(record):
    """Reference release-evidence predicate, NOT a permission decision."""
    if type(record) is not dict or set(record) != REQUIRED:
        return False
    if any(type(record[key]) is not str or not record[key].strip()
           for key in ("production_owner", "base_sha", "head_sha")):
        return False
    if any(re.fullmatch(r"[0-9a-f]{40}", record[key]) is None
           for key in ("base_sha", "head_sha")):
        return False
    if record["base_sha"] == record["head_sha"]:
        return False
    if any(type(record[key]) is not bool or record[key] is not True
           for key in REQUIRED - {"production_owner", "base_sha", "head_sha"}):
        return False
    # No interpretation of a CI result as an actual authorization grant.
    return True


class EvidenceGateReferenceTests(unittest.TestCase):
    def setUp(self):
        self.valid = {
            "production_owner": "reviewed-owner",
            "base_sha": "a" * 40,
            "head_sha": "b" * 40,
            **{key: True for key in REQUIRED - {"production_owner", "base_sha", "head_sha"}},
        }

    def test_complete_review_record_only_is_ready_for_release_review(self):
        self.assertTrue(evidence_ready(self.valid))

    def test_every_missing_review_dimension_denies(self):
        for key in REQUIRED:
            with self.subTest(key=key):
                candidate = dict(self.valid)
                del candidate[key]
                self.assertFalse(evidence_ready(candidate))

    def test_every_failing_review_dimension_denies(self):
        for key in REQUIRED - {"production_owner", "base_sha", "head_sha"}:
            with self.subTest(key=key):
                candidate = dict(self.valid)
                candidate[key] = False
                self.assertFalse(evidence_ready(candidate))

    def test_truthy_strings_and_numeric_values_do_not_replace_proof(self):
        for value in ("success", "true", 1, [], object()):
            with self.subTest(value=type(value).__name__):
                candidate = dict(self.valid)
                candidate["canonical_vps"] = value
                self.assertFalse(evidence_ready(candidate))

    def test_unrecognized_keys_and_unsupported_record_types_deny(self):
        candidate = dict(self.valid)
        candidate["target_active"] = True
        self.assertFalse(evidence_ready(candidate))
        self.assertFalse(evidence_ready(list(self.valid.items())))

    def test_noncanonical_commit_identity_denies(self):
        for bad in ("short", "g" * 40, "A" * 40, "a" * 39, "a" * 41, " " + "a" * 40, None, 123):
            with self.subTest(value=repr(bad)):
                candidate = dict(self.valid)
                candidate["base_sha"] = bad
                self.assertFalse(evidence_ready(candidate))

    def test_same_base_and_head_denies(self):
        candidate = dict(self.valid)
        candidate["head_sha"] = candidate["base_sha"]
        self.assertFalse(evidence_ready(candidate))

    def test_inputs_not_mutated(self):
        before = dict(self.valid)
        evidence_ready(self.valid)
        self.assertEqual(before, self.valid)


if __name__ == "__main__":
    unittest.main()
