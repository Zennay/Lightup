"""Fail-closed, original-source-preserving gate for uncertain HAR note copies.

This is a PRIVATE local source-minimisation feature, not a source
authenticator, privacy PASS, active tool, or permission to disclose.
The operator retains the original file outside this derived workroom.
"""
from __future__ import annotations

from private_json_mask import _Reader, MAX_FRAGMENT

HOLD_MARKER = "[WITHHELD_PRIVATE_HAR_UNREVIEWED]"
MAX_SOURCE = 512 * 1024


def hold_unadmitted_har(source: str) -> str:
    """Withhold a whole embedded/oversized/ambiguous HAR-like source.

    A structured HAR can lose its enclosing request/response paths if its
    root JSON is too large or malformed. Pattern-scanning nested fragments
    would then preserve sensitive URLs or opaque header values. This gate
    instead refuses to copy such an original into the PRIVATE derivative.
    """
    if type(source) is not str or not source:
        return source
    stripped = source.strip()
    # Standalone oversized JSON is not eligible for per-structure masking.
    # We cannot promise to recognise every HAR form through the cap.
    if stripped.startswith(("{", "[")) and len(stripped) > MAX_FRAGMENT:
        return HOLD_MARKER
    har_hint = ('"log"' in source and '"entries"' in source
                or '"request"' in source and '"postData"' in source
                or '"entries"' in source and
                ('"request"' in source or '"response"' in source))
    if not har_hint:
        return source
    if len(source) > MAX_SOURCE or not stripped.startswith(("{", "[")):
        return HOLD_MARKER
    try:
        reader = _Reader(stripped, 0)
        consumed, _spans = reader.read()
        if not stripped[consumed:].strip():
            return source
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        pass
    return HOLD_MARKER
