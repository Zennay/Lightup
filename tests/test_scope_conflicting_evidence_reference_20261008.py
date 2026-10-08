"""Offline-only reference for contradictory authorization evidence (not runtime proof)."""
import unittest


def reference_admit(evidence):
    """Illustrative conjunctive reference, never connected to execution."""
    if type(evidence) is not dict:
        return False
    required = ("request_id", "approval_request_id", "tenant_id", "approval_tenant_id",
                "asset_id", "approval_asset_id", "capability", "approval_capability",
                "revision", "approval_revision", "approved", "revoked")
    if any(key not in evidence for key in required):
        return False
    for key in required[:10]:
        if type(evidence[key]) is not str or not evidence[key] or evidence[key].strip() != evidence[key]:
            return False
    if type(evidence["approved"]) is not bool or type(evidence["revoked"]) is not bool:
        return False
    if not evidence["approved"] or evidence["revoked"]:
        return False
    return all(evidence[a] == evidence[b] for a, b in (
        ("request_id", "approval_request_id"),
        ("tenant_id", "approval_tenant_id"),
        ("asset_id", "approval_asset_id"),
        ("capability", "approval_capability"),
        ("revision", "approval_revision"),
    ))


class ConflictingEvidenceReferenceTests(unittest.TestCase):
    def setUp(self):
        self.valid = dict(request_id="r1", approval_request_id="r1",
                          tenant_id="t1", approval_tenant_id="t1",
                          asset_id="a1", approval_asset_id="a1",
                          capability="web-baseline", approval_capability="web-baseline",
                          revision="v1", approval_revision="v1",
                          approved=True, revoked=False)

    def test_consistent_reference_only(self):
        self.assertTrue(reference_admit(self.valid))

    def test_missing_evidence_denies(self):
        for key in self.valid:
            with self.subTest(key=key):
                altered = dict(self.valid)
                del altered[key]
                self.assertFalse(reference_admit(altered))

    def test_conflicts_deny_independently(self):
        for key in ("approval_request_id", "approval_tenant_id",
                    "approval_asset_id", "approval_capability", "approval_revision"):
            with self.subTest(key=key):
                altered = dict(self.valid, **{key: "different"})
                self.assertFalse(reference_admit(altered))

    def test_no_partial_agreement_or_majority_vote(self):
        altered = dict(self.valid, approval_tenant_id="foreign", approval_revision="v2")
        self.assertFalse(reference_admit(altered))

    def test_revocation_dominates_historical_approval(self):
        self.assertFalse(reference_admit(dict(self.valid, revoked=True)))

    def test_approval_must_be_exact_boolean(self):
        for value in (1, "true", [], None):
            with self.subTest(value=value):
                self.assertFalse(reference_admit(dict(self.valid, approved=value)))

    def test_revocation_must_be_exact_boolean(self):
        for value in (0, "false", None):
            with self.subTest(value=value):
                self.assertFalse(reference_admit(dict(self.valid, revoked=value)))

    def test_identifier_type_confusion_denies(self):
        class FriendlyStr(str):
            pass
        for value in (FriendlyStr("t1"), 1, None, " t1", ""):
            with self.subTest(value=value):
                self.assertFalse(reference_admit(dict(self.valid, tenant_id=value)))

    def test_malformed_container_denies(self):
        for value in (None, [], "approved", True):
            with self.subTest(value=value):
                self.assertFalse(reference_admit(value))


if __name__ == "__main__":
    unittest.main()
