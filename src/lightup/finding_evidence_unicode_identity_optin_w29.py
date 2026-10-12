"""Additional opt-in Unicode identity gate for historical finding evidence refs.

Stacks ONLY on W27's uninstalled shape/size decoder. Not a replacement for
DomainStore, authorization, tenant selectors, provenance or finding retest.
"""
from __future__ import annotations

import unicodedata

from .finding_evidence_json_checked_optin_w27 import decode_finding_evidence_checked

_ERROR = "invalid persisted finding evidence integrity"


def _ambiguous_reference(reference: str) -> bool:
    has_visible_base = False
    for character in reference:
        category = unicodedata.category(character)
        # Control/format/private/unassigned/surrogate code points can hide or
        # redirect an identifier even though the JSON array itself is valid.
        if category.startswith("C"):
            return True
        # A non-ASCII space or a paragraph/line separator is ambiguous in an ID.
        if category.startswith("Z") and character != " ":
            return True
        # Marks after a base are ordinary accents or emoji variation selectors;
        # a mark before any base has no stable visual anchor in an identifier.
        if category.startswith("M") and not has_visible_base:
            return True
        if not character.isspace() and not category.startswith("M"):
            has_visible_base = True
    return False


def decode_finding_evidence_unicode_identity_checked(raw: object) -> tuple[str, ...]:
    """Reject ambiguous reference presentation before returning a full batch.

    W27 exact-type/length/JSON guards run first. NFKC comparison is *only*
    used for within-row collisions; returned references retain original bytes,
    order and spelling. Does not check historical IDs across other rows.
    """
    references = decode_finding_evidence_checked(raw)
    seen_normalized: set[str] = set()
    for reference in references:
        if _ambiguous_reference(reference):
            raise ValueError(_ERROR)
        normalized = unicodedata.normalize("NFKC", reference)
        if normalized in seen_normalized:
            raise ValueError(_ERROR)
        seen_normalized.add(normalized)
    return references
