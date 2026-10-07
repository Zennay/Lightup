from __future__ import annotations

import unittest

from lightup.discovery import ProspectProfile


class _IdentityText(str):
    pass


class UnauthorizedDiscoveryProfileIdentityTextBoundaryTest(unittest.TestCase):
    def test_canonical_identity_text_is_preserved(self):
        profile = ProspectProfile("prospect-1", "Example Org")

        self.assertEqual(profile.prospect_id, "prospect-1")
        self.assertEqual(profile.organization_name, "Example Org")

    def test_prospect_id_rejects_non_exact_text(self):
        for value in (None, 1, object(), _IdentityText("prospect-1")):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    ValueError,
                    "prospect_id must be exact non-empty text",
                ):
                    ProspectProfile(value, "Example Org")

    def test_prospect_id_rejects_blank_text_without_normalization(self):
        for value in ("", " ", "\t\n"):
            with self.subTest(value=repr(value)):
                with self.assertRaisesRegex(
                    ValueError,
                    "prospect_id must be exact non-empty text",
                ):
                    ProspectProfile(value, "Example Org")

    def test_organization_name_rejects_non_exact_text(self):
        for value in (None, 1, object(), _IdentityText("Example Org")):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    ValueError,
                    "organization_name must be exact non-empty text",
                ):
                    ProspectProfile("prospect-1", value)

    def test_organization_name_rejects_blank_text_without_normalization(self):
        for value in ("", " ", "\t\n"):
            with self.subTest(value=repr(value)):
                with self.assertRaisesRegex(
                    ValueError,
                    "organization_name must be exact non-empty text",
                ):
                    ProspectProfile("prospect-1", value)


if __name__ == "__main__":
    unittest.main()
