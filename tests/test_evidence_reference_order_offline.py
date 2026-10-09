"""Offline reference contract: evidence ordering must not alter logical remediation identity.

This is a pure model. It does not claim production behavior or authorize targets.
"""
import hashlib
import hmac
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
    # Unpaired surrogate code points cannot represent valid UTF-8 identifiers.
    if any(0xD800 <= ord(ch) <= 0xDFFF for value in (tenant, finding, *evidence_ids) for ch in value):
        raise ValueError("invalid surrogate in reference identity")
    payload = json.dumps(
        {"schema": "lightup.evidence-set.v1", "tenant": tenant, "finding": finding, "evidence": sorted(evidence_ids)},
        sort_keys=True, ensure_ascii=True, separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()




def verify_reference_digest(tenant, finding, evidence_ids, claimed_digest):
    """Fail closed on malformed receipts; offline reference, not production attestation."""
    if type(claimed_digest) is not str or len(claimed_digest) != 64:
        return False
    if any(char not in "0123456789abcdef" for char in claimed_digest):
        return False
    try:
        actual = reference_digest(tenant, finding, evidence_ids)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, claimed_digest)

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

    def test_identity_upper_bound_is_accepted(self):
        self.assertEqual(
            reference_digest("t" * 128, "f" * 128, ["e" * 128]),
            reference_digest("t" * 128, "f" * 128, ("e" * 128,)),
        )

    def test_finding_identity_invalid_independently(self):
        for invalid in (None, False, 0, "", "f" * 129):
            with self.subTest(invalid=repr(invalid)), self.assertRaises(ValueError):
                reference_digest("tenant", invalid, ["e"])

    def test_evidence_identity_escape_is_distinct(self):
        self.assertNotEqual(
            reference_digest("t", "f", ['"e"']),
            reference_digest("t", "f", ["e"]),
        )

    def test_repeated_digest_is_deterministic(self):
        first = reference_digest("tenant", "finding", ["β", "α"])
        for _ in range(10):
            self.assertEqual(first, reference_digest("tenant", "finding", ["α", "β"]))

    def test_digest_uses_versioned_domain_separation(self):
        expected_payload = json.dumps(
            {"schema": "lightup.evidence-set.v1", "tenant": "t", "finding": "f",
             "evidence": ["a", "b"]},
            sort_keys=True, ensure_ascii=True, separators=(",", ":"),
        ).encode("ascii")
        self.assertEqual(reference_digest("t", "f", ["b", "a"]),
                         hashlib.sha256(expected_payload).hexdigest())

    def test_versioned_digest_differs_from_unversioned_legacy_payload(self):
        legacy = json.dumps(
            {"tenant": "t", "finding": "f", "evidence": ["a"]},
            sort_keys=True, ensure_ascii=True, separators=(",", ":"),
        ).encode("ascii")
        self.assertNotEqual(reference_digest("t", "f", ["a"]),
                            hashlib.sha256(legacy).hexdigest())

    def test_unpaired_surrogates_fail_closed(self):
        for malformed in (chr(0xD800), chr(0xDFFF)):
            with self.subTest(malformed=ascii(malformed)):
                for position in ("tenant", "finding", "evidence"):
                    with self.subTest(position=position), self.assertRaises(ValueError):
                        parts = {"tenant": "t", "finding": "f", "evidence_ids": ["e"]}
                        parts["evidence_ids" if position == "evidence" else position] = (
                            [malformed] if position == "evidence" else malformed
                        )
                        reference_digest(**parts)

    def test_valid_supplementary_unicode_identity(self):
        self.assertEqual(reference_digest("t", "f", ["🔒"]),
                         reference_digest("t", "f", ("🔒",)))

    def test_distinct_canonical_json_values_cannot_share_digest(self):
        samples = [("t", "f", ["a"]), ("t", "f", ["a", "b"]),
                   ("t", "f2", ["a"]), ("t2", "f", ["a"]),
                   ("t", "f", ["A"]), ("t", "f", ["a "])]
        self.assertEqual(len({reference_digest(*case) for case in samples}),
                         len(samples))

    def test_all_permutations_share_exact_digest(self):
        from itertools import permutations

        references = ("alpha", "beta", "gamma", "delta")
        digests = {
            reference_digest("tenant", "finding", list(order))
            for order in permutations(references)
        }
        self.assertEqual(len(digests), 1)

    def test_exact_evidence_reference_character_length_boundary(self):
        accepted = "é" * 128
        self.assertEqual(
            reference_digest("t", "f", [accepted]),
            reference_digest("t", "f", (accepted,)),
        )
        with self.assertRaises(ValueError):
            reference_digest("t", "f", ["é" * 129])

    def test_receipt_verifier_accepts_matching_digest(self):
        claim = reference_digest("t", "f", ["b", "a"])
        self.assertTrue(verify_reference_digest("t", "f", ["a", "b"], claim))

    def test_receipt_verifier_rejects_tampered_claim(self):
        claim = reference_digest("t", "f", ["a"])
        tampered = ("0" if claim[0] != "0" else "1") + claim[1:]
        self.assertFalse(verify_reference_digest("t", "f", ["a"], tampered))

    def test_receipt_verifier_rejects_malformed_claim(self):
        claim = reference_digest("t", "f", ["a"])
        for malformed in (None, 1, True, b"0" * 64, claim.upper(), "0" * 63, "g" * 64):
            with self.subTest(claim=repr(malformed)):
                self.assertFalse(verify_reference_digest("t", "f", ["a"], malformed))

    def test_receipt_verifier_rejects_changed_context(self):
        claim = reference_digest("t", "f", ["a"])
        for tenant, finding, refs in (("t2", "f", ["a"]), ("t", "f2", ["a"]),
                                      ("t", "f", ["b"]), ("t", "f", ["a", "b"])):
            with self.subTest(tenant=tenant, finding=finding, refs=refs):
                self.assertFalse(verify_reference_digest(tenant, finding, refs, claim))

    def test_receipt_verifier_rejects_invalid_inputs(self):
        claim = reference_digest("t", "f", ["a"])
        self.assertFalse(verify_reference_digest("t", "f", ["a", "a"], claim))
        self.assertFalse(verify_reference_digest("t", "f", [chr(0xD800)], claim))

    def test_does_not_mutate_inputs(self):
        ids = ["z", "a"]
        reference_digest("t1", "f1", ids)
        self.assertEqual(ids, ["z", "a"])


if __name__ == "__main__":
    unittest.main()
