"""Offline reference: failures in external authorization proof verification deny.
This is NOT the production gate and never authorizes target execution.
"""
import unittest
import unicodedata
from dataclasses import dataclass


@dataclass(frozen=True)
class Proof:
    tenant: str
    request: str
    issuer: str
    grant: str


def eligible(proof, verifier):
    """A trusted caller-provided verifier is illustrative, not issuer provenance."""
    if type(proof) is not Proof:
        return False
    if any(\n        type(value) is not str\n        or not value\n        or len(value) > 256\n        or value != value.strip()\n        or any(unicodedata.category(ch) in {"Cc", "Cf", "Zl", "Zp"} for ch in value)\n        for value in (proof.tenant, proof.request, proof.issuer, proof.grant)\n    ):
        return False
    try:
        result = verifier(proof)
    except Exception:
        return False
    return type(result) is bool and result is True


class VerifierFailureReferenceTests(unittest.TestCase):
    def setUp(self):
        self.proof = Proof("tenant-a", "request-a", "issuer-a", "grant-a")

    def test_true_boolean_is_only_conditional_reference_accept(self):
        self.assertTrue(eligible(self.proof, lambda _: True))

    def test_false_and_none_deny(self):
        for value in (False, None):
            with self.subTest(value=value):
                self.assertFalse(eligible(self.proof, lambda _: value))

    def test_truthy_non_booleans_deny(self):
        for value in (1, "yes", [True], {"valid": True}):
            with self.subTest(value=repr(value)):
                self.assertFalse(eligible(self.proof, lambda _: value))

    def test_verifier_runtime_failure_denies(self):
        for error in (RuntimeError, ValueError, TimeoutError, ConnectionError):
            with self.subTest(error=error):
                def broken(_):
                    raise error("proof lookup unavailable")
                self.assertFalse(eligible(self.proof, broken))

    def test_verifier_interrupted_result_denies(self):
        def broken(_):
            raise StopIteration
        self.assertFalse(eligible(self.proof, broken))

    def test_malformed_envelope_denies_without_calling_verifier(self):
        called = []
        def check(_):
            called.append(True)
            return True
        self.assertFalse(eligible({"tenant": "tenant-a"}, check))
        self.assertFalse(eligible(Proof(" tenant-a", "r", "i", "g"), check))
        self.assertFalse(eligible(Proof("", "r", "i", "g"), check))
        self.assertEqual(called, [])

    def test_control_characters_and_oversized_identifiers_deny_before_verification(self):
        called = []
        def check(_):
            called.append(True)
            return True
        for bad in ("tenant\nother", "tenant\tother", "tenant\x00other",
                    "tenant\x7fother", "x" * 257):
            with self.subTest(bad=repr(bad)):
                self.assertFalse(eligible(Proof(bad, "request", "issuer", "grant"), check))
        self.assertEqual(called, [])

    def test_unicode_format_and_line_separator_deny_without_verification(self):
        calls = []
        def check(_):
            calls.append(True)
            return True
        for bad in ("tenant\\u200bother", "tenant\\u2028other", "tenant\\u2029other",
                    "tenant\\u2060other"):
            with self.subTest(bad=repr(bad)):
                self.assertFalse(eligible(Proof(bad, "request", "issuer", "grant"), check))
        self.assertEqual(calls, [])

    def test_identifier_length_boundary(self):
        self.assertTrue(eligible(Proof("x" * 256, "request", "issuer", "grant"),
                                 lambda _: True))

    def test_wrong_type_fields_deny_without_verifier(self):
        calls = []
        def check(_):
            calls.append(True)
            return True
        for bad in (None, 12, True, b"tenant", ["tenant"]):
            with self.subTest(bad=repr(bad)):
                self.assertFalse(eligible(Proof(bad, "request", "issuer", "grant"), check))
        self.assertEqual(calls, [])

    def test_verifier_called_once_on_positive_result(self):
        calls = []
        def check(value):
            calls.append(value)
            return True
        self.assertTrue(eligible(self.proof, check))
        self.assertEqual(calls, [self.proof])

    def test_verifier_failure_has_no_implicit_fallback_or_retry(self):
        calls = []
        def check(value):
            calls.append(value)
            raise ConnectionError("authorization issuer offline")
        self.assertFalse(eligible(self.proof, check))
        self.assertEqual(calls, [self.proof])

    def test_missing_or_noncallable_verifier_denies(self):
        for bad in (None, False, True, "trusted", {}):
            with self.subTest(bad=repr(bad)):
                self.assertFalse(eligible(self.proof, bad))

    def test_forged_subclass_denies(self):
        class Forged(Proof):
            pass
        self.assertFalse(eligible(Forged("t", "r", "i", "g"), lambda _: True))

    def test_reference_does_not_mutate_proof(self):
        before = self.proof
        self.assertFalse(eligible(self.proof, lambda _: 1))
        self.assertEqual(self.proof, before)


if __name__ == "__main__":
    unittest.main()
