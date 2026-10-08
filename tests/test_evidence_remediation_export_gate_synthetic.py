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


    def test_blank_or_padded_identities(self):
        for field in ("tenant", "review", "finding", "remediation"):
            for value in ("", " ", " value", "value "):
                with self.subTest(field=field, value=value):
                    self.assertFalse(self.check(dict(self.ok, **{field: value})))

    def test_string_subclass_rejected(self):
        class UntrustedText(str):
            pass
        for field in ("tenant", "review", "finding", "remediation", "digest"):
            with self.subTest(field=field):
                self.assertFalse(self.check(dict(self.ok, **{field: UntrustedText(self.ok[field])})))

    def test_invalid_trusted_context(self):
        for tenant, review in ((True, "r"), ("a", False), (" ", "r"), ("a", "")):
            with self.subTest(tenant=tenant, review=review):
                self.assertFalse(eligible(self.ok, tenant=tenant, review=review))

    def test_wrong_record_type(self):
        class UntrustedDict(dict):
            pass
        self.assertFalse(self.check(UntrustedDict(self.ok)))
        self.assertFalse(self.check(None))

if __name__ == "__main__":
    unittest.main()
