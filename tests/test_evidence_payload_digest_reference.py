"""Offline evidence payload digest reference; no production authority."""
import hashlib
import unittest


def verify_payload(expected_sha256: object, payload: object, *, max_bytes: int = 1024 * 1024) -> bool:
    """Strict bytes/hash identity check, not an authorization decision."""
    if type(max_bytes) is not int or max_bytes <= 0:
        return False
    if type(payload) is not bytes or len(payload) > max_bytes:
        return False
    if type(expected_sha256) is not str or len(expected_sha256) != 64:
        return False
    if any(ch not in "0123456789abcdef" for ch in expected_sha256):
        return False
    return hashlib.sha256(payload).hexdigest() == expected_sha256


class EvidenceContentHashReferenceTests(unittest.TestCase):
    def setUp(self):
        self.payload = b"evidence\x00artifact\r\n"
        self.digest = hashlib.sha256(self.payload).hexdigest()

    def test_exact_payload_passes(self):
        self.assertTrue(verify_payload(self.digest, self.payload))

    def test_empty_payload_can_be_valid(self):
        payload = b""
        self.assertTrue(verify_payload(hashlib.sha256(payload).hexdigest(), payload))

    def test_binary_control_bytes_present(self):
        self.assertIn(0, self.payload)
        self.assertTrue(self.payload.endswith(bytes((13, 10))))

    def test_text_normalization_must_not_match(self):
        normalized = self.payload.replace(bytes((13, 10)), bytes((10,)))
        self.assertFalse(verify_payload(self.digest, normalized))

    def test_mutated_bytes_denied(self):
        self.assertFalse(verify_payload(self.digest, self.payload + b"!"))

    def test_truncated_bytes_denied(self):
        self.assertFalse(verify_payload(self.digest, self.payload[:-1]))

    def test_uppercase_digest_denied(self):
        self.assertFalse(verify_payload(self.digest.upper(), self.payload))

    def test_short_digest_denied(self):
        self.assertFalse(verify_payload(self.digest[:-1], self.payload))

    def test_non_hex_digest_denied(self):
        self.assertFalse(verify_payload("g" * 64, self.payload))

    def test_payload_string_denied(self):
        self.assertFalse(verify_payload(self.digest, self.payload.decode("latin1")))

    def test_bytearray_denied(self):
        self.assertFalse(verify_payload(self.digest, bytearray(self.payload)))

    def test_wrong_digest_type_denied(self):
        self.assertFalse(verify_payload(bytes.fromhex(self.digest), self.payload))

    def test_oversize_payload_denied(self):
        self.assertFalse(verify_payload(self.digest, self.payload, max_bytes=len(self.payload) - 1))

    def test_exact_bound_allowed(self):
        self.assertTrue(verify_payload(self.digest, self.payload, max_bytes=len(self.payload)))

    def test_invalid_budgets_denied(self):
        for budget in (True, False, 0, -1, 1.0, "10", None):
            with self.subTest(budget=budget):
                self.assertFalse(verify_payload(self.digest, self.payload, max_bytes=budget))

    def test_input_unchanged(self):
        original = self.payload
        verify_payload(self.digest, self.payload)
        self.assertEqual(self.payload, original)


if __name__ == "__main__":
    unittest.main()
