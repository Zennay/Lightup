"""Offline audience-binding reference contract; not production authorization proof."""
import unittest

MAX_AUDIENCE_BYTES = 128


def reference_audience_match(grant_audience, trusted_dispatcher_audience):
    """Strict illustrative predicate only. All remaining gates are external."""
    def valid(value):
        return (
            type(value) is str
            and 0 < len(value.encode("utf-8")) <= MAX_AUDIENCE_BYTES
            and all(0x21 <= ord(ch) <= 0x7E for ch in value)
        )
    return valid(grant_audience) and valid(trusted_dispatcher_audience) and (
        grant_audience == trusted_dispatcher_audience
    )


class AudienceBindingReferenceTests(unittest.TestCase):
    def test_exact_match_is_only_conditional(self):
        self.assertTrue(reference_audience_match("lab.http-baseline.v1", "lab.http-baseline.v1"))

    def test_different_adapter_denied(self):
        self.assertFalse(reference_audience_match("lab.http-baseline.v1", "lab.tls-baseline.v1"))

    def test_case_and_padding_denied(self):
        for altered in ("LAB.HTTP-BASELINE.V1", "lab.http-baseline.v1 ", " lab.http-baseline.v1"):
            with self.subTest(altered=altered):
                self.assertFalse(reference_audience_match("lab.http-baseline.v1", altered))

    def test_suffix_and_prefix_denied(self):
        for altered in ("lab.http-baseline.v1/child", "lab.http-baseline"):
            with self.subTest(altered=altered):
                self.assertFalse(reference_audience_match("lab.http-baseline.v1", altered))

    def test_missing_and_untyped_values_denied(self):
        for invalid in (None, "", 0, 1, True, [], {}, b"lab.http-baseline.v1"):
            with self.subTest(invalid=repr(invalid)):
                self.assertFalse(reference_audience_match(invalid, "lab.http-baseline.v1"))
                self.assertFalse(reference_audience_match("lab.http-baseline.v1", invalid))

    def test_control_unicode_and_encoded_alias_denied(self):
        for altered in ("lab.http\nbaseline.v1", "lab.http-baseline.v1\u200b", "lab.http%2dbaseline.v1"):
            with self.subTest(altered=repr(altered)):
                self.assertFalse(reference_audience_match("lab.http-baseline.v1", altered))

    def test_oversized_inputs_denied(self):
        oversized = "a" * (MAX_AUDIENCE_BYTES + 1)
        self.assertFalse(reference_audience_match(oversized, oversized))
        self.assertFalse(reference_audience_match(oversized, "lab.http-baseline.v1"))

    def test_inputs_not_mutated(self):
        grant = "lab.http-baseline.v1"
        dispatcher = "lab.http-baseline.v1"
        reference_audience_match(grant, dispatcher)
        self.assertEqual((grant, dispatcher), ("lab.http-baseline.v1", "lab.http-baseline.v1"))


if __name__ == "__main__":
    unittest.main()
