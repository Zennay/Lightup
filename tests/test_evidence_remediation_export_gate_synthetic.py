import unittest
from evidence_remediation_export_gate_synthetic import eligible


class ExportGateTests(unittest.TestCase):
    def setUp(self):
        self.ok = {"tenant": "a", "review": "r", "finding": "f",
                   "remediation": "m", "digest": "a" * 64,
                   "redacted": True, "approved": True}

    def check(self, record):
        return eligible(record, tenant="a", review="r")

    def test_reference_positive(self):
        self.assertTrue(self.check(self.ok))

    def test_cross_tenant(self):
        self.assertFalse(self.check(dict(self.ok, tenant="b")))

    def test_wrong_review(self):
        self.assertFalse(self.check(dict(self.ok, review="stale")))

    def test_unknown_raw_field(self):
        self.assertFalse(self.check(dict(self.ok, raw_secret="never export")))

    def test_no_review(self):
        self.assertFalse(self.check(dict(self.ok, approved=False)))

    def test_no_redaction(self):
        self.assertFalse(self.check(dict(self.ok, redacted=False)))

    def test_truthy_flags(self):
        for field in ("approved", "redacted"):
            self.assertFalse(self.check(dict(self.ok, **{field: 1})))

    def test_digest_format(self):
        for digest in ("A" * 64, "a" * 63, "g" * 64):
            self.assertFalse(self.check(dict(self.ok, digest=digest)))

    def test_missing_identity(self):
        record = dict(self.ok)
        del record["finding"]
        self.assertFalse(self.check(record))

    def test_input_unchanged_after_denial(self):
        record = dict(self.ok, tenant="b")
        before = dict(record)
        self.assertFalse(self.check(record))
        self.assertEqual(record, before)


if __name__ == "__main__":
    unittest.main()
