"""Pure offline reference for provenance *shape*, not a trusted consent issuer.

This deliberately does not modify ScopePolicy or produce execution permits.
A passing result never authorizes real target interaction.
"""
from __future__ import annotations

import unittest
import unicodedata
from dataclasses import dataclass
from unittest.mock import Mock

from lightup.models import Authorization


def _well_formed_identity(value: object) -> bool:
    if type(value) is not str or not value or value != value.strip():
        return False
    if any(unicodedata.category(ch) in {"Cc", "Cf", "Cs"} for ch in value):
        return False
    return any(not ch.isspace() for ch in value)


def reference_provenance_shape(authorization: object) -> bool:
    """Fail closed on malformed provenance without invoking policy/target I/O."""
    if type(authorization) is not Authorization:
        return False
    return (
        _well_formed_identity(authorization.owner)
        and _well_formed_identity(authorization.reference)
    )


class ReferenceProvenanceShapeTests(unittest.TestCase):
    def test_rejects_blank_and_invisible_fields(self):
        invalid = ("", "   ", "\t", "\u200b", "\u200e", "\u202e",
                   "\ufeff", "\ud800", "\n", "id\rvalue", "id\x00value")
        for field in ("owner", "reference"):
            for value in invalid:
                with self.subTest(field=field, value=repr(value)):
                    kwargs = {"owner": "owner-1", "reference": "consent-1"}
                    kwargs[field] = value
                    self.assertFalse(reference_provenance_shape(Authorization(**kwargs)))

    def test_rejects_nonstring_objects_without_coercion(self):
        class Poison:
            def __str__(self):
                raise AssertionError("unexpected coercion")
            def __bool__(self):
                raise AssertionError("unexpected truth check")
        for field in ("owner", "reference"):
            kwargs = {"owner": "owner-1", "reference": "consent-1"}
            kwargs[field] = Poison()
            self.assertFalse(reference_provenance_shape(Authorization(**kwargs)))

    def test_valid_text_does_not_imply_trusted_consent(self):
        self.assertTrue(reference_provenance_shape(
            Authorization(owner="owner-1", reference="consent-1")
        ))

    def test_rejects_none_and_forged_object(self):
        self.assertFalse(reference_provenance_shape(None))
        self.assertFalse(reference_provenance_shape(
            {"owner": "owner-1", "reference": "consent-1"}
        ))

    def test_no_external_policy_or_handler_calls(self):
        handler = Mock()
        policy = Mock()
        grant = Authorization(owner="\u200b", reference="consent-1")
        self.assertFalse(reference_provenance_shape(grant))
        policy.assert_not_called()
        handler.assert_not_called()


if __name__ == "__main__":
    unittest.main()
