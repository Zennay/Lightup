"""Offline IPv4 legacy-alias reference. Not a production authorization gate."""
import ipaddress
import unittest

def canonical_ipv4_literal(value):
    if type(value) is not str or len(value) > 15:
        return None
    parts = value.split(".")
    if len(parts) != 4:
        return None
    if any(not p or not p.isascii() or not p.isdecimal() or (len(p)>1 and p[0]=="0") for p in parts):
        return None
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        return None
    return value if str(address) == value else None

class IPv4AliasReference(unittest.TestCase):
    def test_canonical_literal_identity_only(self):
        self.assertEqual(canonical_ipv4_literal("192.0.2.12"), "192.0.2.12")
    def test_numeric_aliases_denied(self):
        for s in ("3221225996", "0xC000020C", "0300.0000.0002.0014"):
            with self.subTest(s=s): self.assertIsNone(canonical_ipv4_literal(s))
    def test_shortened_forms_denied(self):
        for s in ("192.0.524", "192.2", "192"):
            with self.subTest(s=s): self.assertIsNone(canonical_ipv4_literal(s))
    def test_padded_forms_denied(self):
        for s in ("192.000.2.12", "192.0.2.012", "0192.0.2.12"):
            with self.subTest(s=s): self.assertIsNone(canonical_ipv4_literal(s))
    def test_whitespace_and_trailing_dot_denied(self):
        for s in (" 192.0.2.12", "192.0.2.12 ", "192.0.2.12.", "+192.0.2.12"):
            with self.subTest(s=s): self.assertIsNone(canonical_ipv4_literal(s))
    def test_unicode_lookalikes_denied(self):
        for s in ("１９２.０.２.１２", "١٩٢.٠.٢.١٢", "192．0．2．12"):
            with self.subTest(s=s): self.assertIsNone(canonical_ipv4_literal(s))
    def test_embedded_uri_port_cidr_denied(self):
        for s in ("192.0.2.12:443", "http://192.0.2.12/", "192.0.2.12/32"):
            with self.subTest(s=s): self.assertIsNone(canonical_ipv4_literal(s))
    def test_wrong_types_denied(self):
        for v in (None, 3221225996, True, b"192.0.2.12"):
            with self.subTest(v=v): self.assertIsNone(canonical_ipv4_literal(v))
    def test_oversized_denied(self):
        self.assertIsNone(canonical_ipv4_literal("1"*100000))

if __name__ == "__main__":
    unittest.main()
