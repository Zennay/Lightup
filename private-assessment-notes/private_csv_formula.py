"""Local PRIVATE HUMAN CSV note admission; fail closed on formula-like Unicode.

Complements, never weakens, existing source-roster and ordinary CSV rules.
A spreadsheet display may normalize Unicode compatibility characters,
strip format marks, or interpret bidi controls differently from a browser.
This helper does NOT make any CSV safe for publication or authentication.
"""
from __future__ import annotations

import unicodedata

_PREFIX_FORMULA = ("=", "+", "-", "@")
_BIDI_CONTROLS = frozenset(chr(n) for n in (
    *range(0x202A, 0x202F), *range(0x2066, 0x206A),
    0x061C,
))


def unsafe_private_csv_note(value: str, maximum: int) -> bool:
    """Reject local HUMAN note text unsafe in CSV or Unicode presentation.

    Only a narrow, source-private acceptance gate. Reject leading format /
    direction-control characters rather than silently normalizing original
    HUMAN content or claiming the resulting CSV is safe to disclose.
    """
    if type(value) is not str or len(value) > maximum:
        return True
    for char in value:
        codepoint = ord(char)
        if (codepoint == 127 or codepoint < 32 and char != "\t"
                or char in _BIDI_CONTROLS or char in "\u2028\u2029"):
            return True
    # Leading zero-width/format/combining marks can camouflage a later
    # formula operator. Do not silently remove them from the original note.
    trimmed = value.lstrip()
    if trimmed and unicodedata.category(trimmed[0]) in ("Cf", "Mn", "Me"):
        return True
    # NFKC exposes fullwidth and compatibility forms such as U+FF1D.
    # Recheck whitespace because NFKC can introduce ordinary spaces.
    canonical = unicodedata.normalize("NFKC", trimmed).lstrip()
    return canonical.startswith(_PREFIX_FORMULA)
