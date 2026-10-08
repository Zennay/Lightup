"""Offline reference contract: evidence ordering must not alter logical remediation identity.

This is a pure model. It does not claim production behavior or authorize targets.
"""
import hashlib
import json
import unittest


def reference_digest(tenant, finding, evidence_ids):
    """Canonicalize an unordered evidence *set* without losing tenant/finding binding."""
    if any(type(v) is not str or not v or len(v) > 128 for v in (tenant, finding)):
        raise ValueError("invalid identity")
    if type(evidence_ids) not in (tuple, list) or not evidence_ids or len(evidence_ids) > 64:
        raise ValueError("invalid evidence collection")
    if any(type(x) is not str or not x or len(x) > 128 for x in evidence_ids):
        raise ValueError("invalid evidence reference")
    if len(set(evidence_ids)) != len(evidence_ids):
        raise ValueError("duplicate evidence reference")
    payload = json.dumps(
        {"tenant": tenant, "finding": finding, "evidence": sorted(evidence_ids)},
        sort_keys=True, ensure_ascii=True, separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


class EvidenceReferenceOrderReferenceTests(unittest.TestCase):
    def test_reorder_does_not_change_digest(self):
        self.assertEqual(reference_digest("t1", "f1", ["b", "a"]),
                         reference_digest("t1", "f1", ["a", "b"]))

    def test_tenant_is_bound(self):
        self.assertNotEqual(reference_digest("t1", "f1", ["a"]),
                            reference_digest("t2", "f1", ["a"]))

    def test_finding_is_bound(self):
        self.assertNotEqual(reference_digest("t1", "f1", ["a"]),
                            reference_digest("t1", "f2", ["a"]))

    def test_evidence_membership_is_bound(self):
        self.assertNotEqual(reference_digest("t1", "f1", ["a"]),
                            reference_digest("t1", "f1", ["b"]))

    def test_duplicates_fail_closed(self):
        with self.assertRaises(ValueError):
            reference_digest("t1", "f1", ["a", "a"])

    def test_invalid_container_fails_closed(self):
        for invalid in ("abc", {"a"}, (), None):
            with self.subTest(invalid=repr(invalid)), self.assertRaises(ValueError):
                reference_digest("t1", "f1", invalid)

    def test_invalid_reference_fails_closed(self):
        for invalid in (1, True, "", "x" * 129):
            with self.subTest(invalid=repr(invalid)), self.assertRaises(ValueError):
                reference_digest("t1", "f1", [invalid])

    def test_invalid_identity_fails_closed(self):
        for invalid in (True, 1, "", "x" * 129):
            with self.subTest(invalid=repr(invalid)), self.assertRaises(ValueError):
                reference_digest(invalid, "f1", ["a"])

    def test_collection_limit_fails_closed(self):
        with self.assertRaises(ValueError):
            reference_digest("t1", "f1", [str(i) for i in range(65)])

    def test_tuple_and_list_are_equivalent(self):
        self.assertEqual(reference_digest("t1", "f1", ("b", "a")),
                         reference_digest("t1", "f1", ["a", "b"]))

    def test_reference_case_remains_distinct(self):
        self.assertNotEqual(reference_digest("t1", "f1", ["EV"]),
                            reference_digest("t1", "f1", ["ev"]))

    def test_unicode_normalization_not_silent(self):
        self.assertNotEqual(reference_digest("t1", "f1", ["é"]),
                            reference_digest("t1", "f1", ["e\u0301"]))

    def test_delimiter_injection_is_unambiguous(self):
        self.assertNotEqual(reference_digest("tenant", "finding", ["a,b"]),
                            reference_digest("tenant", "finding", ["a", "b"]))

    def test_collection_at_limit_is_accepted(self):
        ids = [f"e{i:02d}" for i in range(64)]
        self.assertEqual(reference_digest("t", "f", ids),
                         reference_digest("t", "f", list(reversed(ids))))

    def test_reference_whitespace_is_not_silently_stripped(self):
        self.assertNotEqual(reference_digest("t", "f", ["ev"]),
                            reference_digest("t", "f", [" ev "]))

    def test_identity_field_boundaries_are_unambiguous(self):
        self.assertNotEqual(reference_digest("a:b", "c", ["d"]),
                            reference_digest("a", "b:c", ["d"]))

    def test_membership_extension_changes_digest(self):
        self.assertNotEqual(reference_digest("t", "f", ["a"]),
                            reference_digest("t", "f", ["a", "b"]))

    def test_surrogate_and_control_references_are_not_silently_aliased(self):
        self.assertNotEqual(reference_digest("t", "f", ["e\\n"]),
                            reference_digest("t", "f", ["e\n"]))

    def test_does_not_mutate_inputs(self):
        ids = ["z", "a"]
        reference_digest("t1", "f1", ids)
        self.assertEqual(ids, ["z", "a"])


if __name__ == "__main__":
    unittest.main()
