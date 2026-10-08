import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from lightup.activation import ActivationMode, ActivationPolicy


class ActivationReferenceContractTests(unittest.TestCase):
    def test_authorized_mode_accepts_canonical_reference(self):
        policy = ActivationPolicy(
            mode=ActivationMode.AUTHORIZED,
            activation_reference="AUTH-498",
        )
        policy.validate()

    def test_authorized_mode_rejects_blank_reference(self):
        for value in ("", " ", "\t", "\n", "   \t  "):
            with self.subTest(value=repr(value)):
                with self.assertRaises(ValueError):
                    ActivationPolicy(
                        mode=ActivationMode.AUTHORIZED,
                        activation_reference=value,
                    ).validate()

    def test_authorized_mode_rejects_non_string_reference(self):
        for value in (1, True, ["AUTH-498"], {"reference": "AUTH-498"}, object()):
            with self.subTest(type=type(value).__name__):
                with self.assertRaises(ValueError):
                    ActivationPolicy(
                        mode=ActivationMode.AUTHORIZED,
                        activation_reference=value,
                    ).validate()

    def test_authorized_mode_rejects_string_subclasses(self):
        class RedirectingReference(str):
            def __new__(cls):
                return super().__new__(cls, "VISIBLE-PUBLIC-REFERENCE")

            def strip(self, *args, **kwargs):
                return "AUTH-498"

        with self.assertRaises(ValueError):
            ActivationPolicy(
                mode=ActivationMode.AUTHORIZED,
                activation_reference=RedirectingReference(),
            ).validate()


if __name__ == "__main__":
    unittest.main()
