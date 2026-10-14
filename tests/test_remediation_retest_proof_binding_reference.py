"""Offline reference invariants for binding remediation retest proof to a finding.

This is a reference contract, NOT a production verification or authorization gate.
No filesystem, network, assessment, or target execution occurs.
"""
import hashlib
import json
import re
import unittest


def digest(payload):
    if type(payload) is not dict:
        return None
    try:
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError):
        return None
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)


def verified_retest(finding, proof):
    """Only exact, immutable-link-shaped retest evidence can support closure."""
    if type(finding) is not dict or type(proof) is not dict:
        return False
    if set(finding) != {"tenant_id", "finding_id", "revision", "evidence_sha256"}:
        return False
    required = {"tenant_id", "finding_id", "revision", "prior_evidence_sha256",
                "retest_evidence_sha256", "result", "method", "verified"}
    if set(proof) != required:
        return False
    for obj in (finding, proof):
        if type(obj["tenant_id"]) is not str or _ID.fullmatch(obj["tenant_id"]) is None:
            return False
        if type(obj["finding_id"]) is not str or _ID.fullmatch(obj["finding_id"]) is None:
            return False
        if type(obj["revision"]) is not int or obj["revision"] < 1:
            return False
    if any(proof[k] != finding[k] for k in ("tenant_id", "finding_id", "revision")):
        return False
    for value in (finding["evidence_sha256"], proof["prior_evidence_sha256"], proof["retest_evidence_sha256"]):
        if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            return False
    if proof["prior_evidence_sha256"] != finding["evidence_sha256"]:
        return False
    if proof["retest_evidence_sha256"] == proof["prior_evidence_sha256"]:
        return False
    return (proof["result"] == "passed" and type(proof["result"]) is str
            and proof["verified"] is True and type(proof["method"]) is str
            and proof["method"] in ("offline_lab", "authorized_retest"))


class RetestProofBindingReference(unittest.TestCase):
    def setUp(self):
        self.finding = {"tenant_id": "tenant-a", "finding_id": "f-1", "revision": 2,
                        "evidence_sha256": "a" * 64}
        self.proof = {"tenant_id": "tenant-a", "finding_id": "f-1", "revision": 2,
                      "prior_evidence_sha256": "a" * 64,
                      "retest_evidence_sha256": "b" * 64,
                      "result": "passed", "method": "offline_lab", "verified": True}

    def test_exact_positive_reference(self):
        self.assertTrue(verified_retest(self.finding, self.proof))

    def test_canonical_selector_boundaries_accepted(self):
        for identifier in ("a", "A_0.-:z", "x" * 128):
            with self.subTest(identifier=identifier):
                finding = {**self.finding, "tenant_id": identifier, "finding_id": identifier}
                proof = {**self.proof, "tenant_id": identifier, "finding_id": identifier}
                self.assertTrue(verified_retest(finding, proof))

    def test_selector_trailing_newline_rejected(self):
        for value in ("tenant-a\\n", "tenant-a\\r", "tenant-a\\r\\n"):
            with self.subTest(value=value):
                self.assertFalse(verified_retest({**self.finding, "tenant_id": value},
                                                 {**self.proof, "tenant_id": value}))

    def test_cross_tenant_denied(self):
        self.assertFalse(verified_retest(self.finding, {**self.proof, "tenant_id": "tenant-b"}))

    def test_wrong_finding_denied(self):
        self.assertFalse(verified_retest(self.finding, {**self.proof, "finding_id": "f-2"}))

    def test_stale_revision_denied(self):
        self.assertFalse(verified_retest(self.finding, {**self.proof, "revision": 1}))

    def test_bool_revision_denied(self):
        self.assertFalse(verified_retest(self.finding, {**self.proof, "revision": True}))

    def test_wrong_prior_evidence_denied(self):
        self.assertFalse(verified_retest(self.finding, {**self.proof, "prior_evidence_sha256": "c" * 64}))

    def test_reused_evidence_denied(self):
        self.assertFalse(verified_retest(self.finding, {**self.proof, "retest_evidence_sha256": "a" * 64}))

    def test_unverified_denied(self):
        self.assertFalse(verified_retest(self.finding, {**self.proof, "verified": 1}))

    def test_unrecognized_method_denied(self):
        self.assertFalse(verified_retest(self.finding, {**self.proof, "method": "unknown"}))

    def test_extra_fields_denied(self):
        self.assertFalse(verified_retest(self.finding, {**self.proof, "override": True}))

    def test_uppercase_digest_denied(self):
        self.assertFalse(verified_retest(self.finding, {**self.proof, "retest_evidence_sha256": "B" * 64}))

    def test_failed_retest_denied(self):
        self.assertFalse(verified_retest(self.finding, {**self.proof, "result": "failed"}))

    def test_subclass_containers_denied(self):
        class Fake(dict):
            pass
        self.assertFalse(verified_retest(self.finding, Fake(self.proof)))

    def test_unsafe_tenant_identifiers_denied(self):
        for identifier in (" tenant-a", "tenant-a ", "tenant\\na", "ténant", "../tenant", "", "x" * 129):
            with self.subTest(identifier=identifier):
                self.assertFalse(verified_retest({**self.finding, "tenant_id": identifier},
                                                 {**self.proof, "tenant_id": identifier}))

    def test_unsafe_finding_identifiers_denied(self):
        for identifier in (" f-1", "f-1\\r", "f/1", "f\\u20281", "", "x" * 129):
            with self.subTest(identifier=identifier):
                self.assertFalse(verified_retest({**self.finding, "finding_id": identifier},
                                                 {**self.proof, "finding_id": identifier}))

    def test_noncanonical_finding_revision_denied(self):
        for revision in (0, -1, 1.0, "2", None):
            with self.subTest(revision=revision):
                self.assertFalse(verified_retest({**self.finding, "revision": revision},
                                                 {**self.proof, "revision": revision}))

    def test_missing_or_wrong_typed_digests_denied(self):
        for bad in (None, b"b" * 64, "z" * 64, "b" * 63):
            with self.subTest(bad=bad):
                self.assertFalse(verified_retest(self.finding,
                                                 {**self.proof, "retest_evidence_sha256": bad}))

    def test_missing_fields_denied(self):
        for key in self.proof:
            with self.subTest(key=key):
                self.assertFalse(verified_retest(self.finding, {k: v for k, v in self.proof.items() if k != key}))

    def test_all_finding_binding_fields_fail_closed(self):
        mutations = {
            "tenant_id": "tenant-b",
            "finding_id": "f-2",
            "revision": 3,
            "evidence_sha256": "c" * 64,
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                self.assertFalse(verified_retest({**self.finding, field: replacement}, self.proof))

    def test_finding_missing_or_extra_fields_denied(self):
        for field in self.finding:
            with self.subTest(missing=field):
                self.assertFalse(verified_retest(
                    {key: value for key, value in self.finding.items() if key != field}, self.proof))
        self.assertFalse(verified_retest({**self.finding, "status": "resolved"}, self.proof))

    def test_finding_outer_subclass_denied(self):
        class FindingProxy(dict):
            pass
        self.assertFalse(verified_retest(FindingProxy(self.finding), self.proof))

    def test_verified_and_method_exact_types(self):
        class TrustedLooking(str):
            pass
        for patch in ({"result": TrustedLooking("passed")},
                      {"method": TrustedLooking("offline_lab")},
                      {"verified": "true"}, {"verified": False}):
            with self.subTest(patch=patch):
                self.assertFalse(verified_retest(self.finding, {**self.proof, **patch}))

    def test_inputs_remain_unchanged(self):
        before = (digest(self.finding), digest(self.proof))
        verified_retest(self.finding, self.proof)
        self.assertEqual(before, (digest(self.finding), digest(self.proof)))


if __name__ == "__main__":
    unittest.main()
