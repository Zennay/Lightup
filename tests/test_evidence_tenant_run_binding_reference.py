"""Offline reference contract for tenant/run/finding evidence binding.

This models a consumer-side admission boundary; NOT production enforcement.
No external I/O, grants, scanners or target operations.
"""
import dataclasses
import unittest


@dataclasses.dataclass(frozen=True)
class EvidenceReceipt:
    evidence_id: str
    tenant_id: str
    run_id: str
    finding_id: str
    digest: str
    revoked: bool = False


def admit_reference(receipt, *, tenant_id, run_id, finding_id, digest):
    """Return a conditional identity match, never authorization or provenance."""
    if type(receipt) is not EvidenceReceipt:
        return False
    for value in (receipt.evidence_id, receipt.tenant_id, receipt.run_id,
                  receipt.finding_id, receipt.digest, tenant_id, run_id,
                  finding_id, digest):
        if type(value) is not str or not value or len(value) > 256:
            return False
    if type(receipt.revoked) is not bool or receipt.revoked:
        return False
    return (receipt.tenant_id == tenant_id
            and receipt.run_id == run_id
            and receipt.finding_id == finding_id
            and receipt.digest == digest)


class EvidenceTenantRunBindingReferenceTests(unittest.TestCase):
    def setUp(self):
        self.receipt = EvidenceReceipt("ev-1", "tenant-A", "run-A",
                                       "finding-A", "sha256:example")

    def check(self, receipt=None, **overrides):
        context = dict(tenant_id="tenant-A", run_id="run-A",
                       finding_id="finding-A", digest="sha256:example")
        context.update(overrides)
        return admit_reference(self.receipt if receipt is None else receipt,
                               **context)

    def test_matching_reference_is_only_conditionally_eligible(self):
        self.assertTrue(self.check())

    def test_cross_tenant_reference_rejected(self):
        self.assertFalse(self.check(tenant_id="tenant-B"))

    def test_cross_run_reference_rejected(self):
        self.assertFalse(self.check(run_id="run-B"))

    def test_cross_finding_reference_rejected(self):
        self.assertFalse(self.check(finding_id="finding-B"))

    def test_digest_mismatch_rejected(self):
        self.assertFalse(self.check(digest="sha256:changed"))

    def test_revoked_receipt_rejected(self):
        self.assertFalse(self.check(dataclasses.replace(self.receipt, revoked=True)))

    def test_truthy_revocation_alias_rejected(self):
        self.assertFalse(self.check(dataclasses.replace(self.receipt, revoked=0)))

    def test_non_string_context_rejected(self):
        for value in (None, 1, True, b"tenant-A", "", "x" * 257):
            with self.subTest(value=value):
                self.assertFalse(self.check(tenant_id=value))

    def test_subclass_and_duck_receipts_rejected(self):
        class SubReceipt(EvidenceReceipt):
            pass
        self.assertFalse(self.check(SubReceipt(**dataclasses.asdict(self.receipt))))
        self.assertFalse(self.check(dataclasses.asdict(self.receipt)))

    def test_all_receipt_identity_fields_reject_malformed_values(self):
        for field in ("evidence_id", "tenant_id", "run_id", "finding_id", "digest"):
            for value in (None, False, 12, b"bytes", "", "x" * 257):
                with self.subTest(field=field, value=value):
                    candidate = dataclasses.replace(self.receipt, **{field: value})
                    self.assertFalse(self.check(candidate))

    def test_exact_length_edge_is_accepted_as_shape_only(self):
        receipt = dataclasses.replace(self.receipt, evidence_id="x" * 256)
        self.assertTrue(self.check(receipt))
        self.assertFalse(self.check(dataclasses.replace(receipt, evidence_id="x" * 257)))

    def test_all_consumer_selectors_reject_type_confusion(self):
        for field in ("tenant_id", "run_id", "finding_id", "digest"):
            for value in (None, True, 0, b"bytes", "", "x" * 257):
                with self.subTest(field=field, value=value):
                    self.assertFalse(self.check(**{field: value}))

    def test_exact_matching_no_casefold_whitespace_or_normalization(self):
        for field in ("tenant_id", "run_id", "finding_id", "digest"):
            canonical = getattr(self.receipt, field)
            for alias in (canonical.upper(), canonical + " ", " " + canonical):
                if alias != canonical:
                    with self.subTest(field=field, alias=alias):
                        self.assertFalse(self.check(**{field: alias}))

    def test_rebinding_receipt_to_other_tenant_does_not_validate_origin(self):
        """A coherent forged receipt illustrates that equality is not provenance."""
        forged = dataclasses.replace(self.receipt, tenant_id="tenant-B")
        self.assertTrue(self.check(forged, tenant_id="tenant-B"))

    def test_original_receipt_unchanged(self):
        before = dataclasses.asdict(self.receipt)
        self.assertFalse(self.check(run_id="other"))
        self.assertEqual(dataclasses.asdict(self.receipt), before)


if __name__ == "__main__":
    unittest.main()
