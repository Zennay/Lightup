"""Bounded, inert masking of percent-encoded URL credential parameter names.

Only owner-private source derivatives. This is not general URL sanitisation,
authentication, PII detection, consent, or safe-to-share certification.
"""
from __future__ import annotations

import re
import unicodedata
from urllib.parse import unquote_plus

# Literal URL schemes only. No network, DNS, browser, or subprocess.
_URL_START = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:https?|wss?|ftps?|sftp|ssh|"
    r"postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss)://"
)
_PARAM = re.compile(
    r"(?P<separator>[?&#;])(?P<name>[^?&#;=\s\"'<>()\[\]{}\\]{1,256})="
    r"(?P<value>[^&#;\s\"'<>()\[\]{}]{0,4096})"
)
_BAD_PERCENT = re.compile(r"%(?![a-fA-F0-9]{2})")
_STOP = set(" \t\r\n\"'<>()[\\]{}")
MAX_URLS = 96
MAX_URL_LENGTH = 8192


def mask_url_query_names(source: str, secret_name) -> str:
    """Hide values after recognized query/fragment names.

    Up to three bounded decode passes apply to parameter names only, so
    nested-percent-encoded credential names are still withheld. Original
    encoded names and punctuation are preserved; values are never decoded.
    Ambiguous or overlong input remains PRIVATE/HOLD; no general guarantee.
    """
    if type(source) is not str or not source:
        return source
    replacements: list[tuple[int, int]] = []
    count = 0
    for hit in _URL_START.finditer(source):
        count += 1
        if count > MAX_URLS:
            break
        start = hit.start()
        end = hit.end()
        while end < len(source) and end - start < MAX_URL_LENGTH:
            if source[end] in _STOP:
                break
            end += 1
        if end < len(source) and end - start == MAX_URL_LENGTH:
            # Do not claim a complete parameter scan of an oversized URL.
            continue
        url = source[start:end]
        question, fragment = url.find("?"), url.find("#")
        if question < 0 and fragment < 0:
            continue
        first_param = min(n for n in (question, fragment) if n >= 0)
        for match in _PARAM.finditer(url, first_param):
            name = match.group("name")
            if _BAD_PERCENT.search(name):
                continue
            try:
                decoded = unquote_plus(name, encoding="utf-8", errors="strict")
            except UnicodeError:
                continue
            # Decode only the parameter name, at most two more times. Values
            # remain untouched and the original encoded name is preserved.
            for _ in range(2):
                if not re.search(r"(?i)%[0-9a-f]{2}", decoded) or _BAD_PERCENT.search(decoded):
                    break
                try:
                    nested = unquote_plus(decoded, encoding="utf-8", errors="strict")
                except UnicodeError:
                    break
                if nested == decoded:
                    break
                decoded = nested
            # Compare a canonical key only; preserve its original spelling in
            # the source copy while withholding the associated value. NFKC
            # catches compatibility characters, and removing format controls
            # prevents zero-width/bidi characters from hiding known names.
            canonical = unicodedata.normalize("NFKC", decoded)
            canonical = "".join(character for character in canonical
                                if unicodedata.category(character) != "Cf")
            if secret_name.fullmatch(canonical):
                a, b = match.span("value")
                replacements.append((start + a, start + b))
    result = source
    for a, b in reversed(replacements):
        result = result[:a] + "[REDACTED_URL_VALUE]" + result[b:]
    return result
