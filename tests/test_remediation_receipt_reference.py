"""Zero-I/O regression cases for the offline remediation receipt contract."""
import unittest
from lightup.remediation_receipt_reference import validate_remediation_receipt

H1 = "a" * 64
H2 = "b" * 64
H3 = "c" * 64


def receipt(**changes):
    value = dict(finding_id="finding-1", evidence_sha256=H1,
                 remediation_sha256=H2, retest_status="pending",
                 retest_evidence_sha256=None)
    value.update(changes)
    return value


class RemediationReceiptTests(unittest.TestCase):
    def test_pending_receipt_is_inert(self):
        self.assertEqual(validate_remediation_receipt(receipt())["retest_status"], "pending")

    def test_passed_requires_independent_evidence(self):
        self.assertEqual(validate_remediation_receipt(
            receipt(retest_status="passed", retest_evidence_sha256=H3)
        )["retest_evidence_sha256"], H3)

    def test_failed_requires_independent_evidence(self):
        self.assertEqual(validate_remediation_receipt(
            receipt(retest_status="failed", retest_evidence_sha256=H3)
        )["retest_status"], "failed")

    def test_completed_without_evidence_denied(self):
        for status in ("passed", "failed"):
            with self.subTest(status=status), self.assertRaises(ValueError):
                validate_remediation_receipt(receipt(retest_status=status))

    def test_pending_with_fabricated_retest_evidence_denied(self):
        for status in ("pending", "not_tested"):
            with self.subTest(status=status), self.assertRaises(ValueError):
                validate_remediation_receipt(receipt(retest_status=status, retest_evidence_sha256=H3))

    def test_original_evidence_reuse_denied(self):
        with self.assertRaises(ValueError):
            validate_remediation_receipt(receipt(retest_status="passed", retest_evidence_sha256=H1))

    def test_untrusted_shapes_denied(self):
        for value in (None, [], {}, "receipt", 1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_remediation_receipt(value)

    def test_unknown_fields_and_missing_fields_denied(self):
        for value in (receipt(extra=True), {k:v for k,v in receipt().items() if k != "finding_id"}):
            with self.assertRaises(ValueError):
                validate_remediation_receipt(value)

    def test_hashes_reject_noncanonical_types_and_case(self):
        for value in (H1.upper(), "sha256:" + H1, H1 + "0", 7, None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_remediation_receipt(receipt(evidence_sha256=value))

    def test_control_characters_in_finding_identity_denied(self):
        for value in ("a\\nb", "a\\x00b", "a\\x7fb", " a", "a "):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_remediation_receipt(receipt(finding_id=value))

    def test_status_subclass_denied(self):
        class Status(str):
            pass
        with self.assertRaises(ValueError):
            validate_remediation_receipt(receipt(retest_status=Status("pending")))

    def test_input_unchanged_and_snapshot_independent(self):
        original = receipt()
        snapshot = validate_remediation_receipt(original)
        snapshot["finding_id"] = "different"
        self.assertEqual(original["finding_id"], "finding-1")


if __name__ == "__main__":
    unittest.main()
