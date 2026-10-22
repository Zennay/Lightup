"""Bounded, inert cURL form payload masking for PRIVATE original notes.

Recognises only known credential field names within a quoted cURL argument.
Not a general shell, form or URI parser: unknown shapes still require human
review, and NO derived output is cleared for publication or execution.
"""
from __future__ import annotations

import re
import unicodedata

_CURL_ARGUMENT = re.compile(
    r"""(?ix)(?<![A-Za-z0-9_-])
    (?P<flag>--data(?:-raw|-binary|-urlencode)?|--form(?:-string)?|-[dF])
    (?P<separator>[ \t]*=[ \t]*|[ \t]+|(?=['"]))
    (?P<quote>["'])
    (?P<payload>(?:\\.|(?! (?P=quote) )[^\\\r\n]){0,8192})
    (?P=quote)""",
    re.VERBOSE,
)
# curl also accepts a single unquoted name=value or name@file argument.
# The quote-aware path above handles multi-field values; this branch only
# admits one bounded shell word and never joins across whitespace/operators.
_CURL_UNQUOTED = re.compile(
    r"""(?ix)(?<![A-Za-z0-9_-])
    (?P<flag>--data(?:-raw|-binary|-urlencode)?|--form(?:-string)?|-[dF])
    (?P<separator>[ \t]*=[ \t]*|[ \t]+)
    (?P<payload>(?!["'])(?:[^\s\r\n"'`<>|;&]){1,4096})""",
    re.VERBOSE,
)

_CREDENTIAL_FIELD = re.compile(
    r"""(?ix)^(?:password|passwd|pwd|api[_-]?key|secret|
    client[_-]?secret|private[_-]?key|(?:access|refresh|auth|id)[_-]?token|
    session(?:[_-]?(?:id|token|key))?|csrf(?:[_-]?token)?|
    xsrf(?:[_-]?token)?|jwt|signature|sig|sid|jsessionid|phpsessid|
    x-amz-security-token|aws[_-]?secret[_-]?access[_-]?key)$"""
)
_FIELD_DELIMITER = re.compile(r"([&;])")
_PERCENT_ASCII_FIELD_CHAR = re.compile(r"(?i)%([0-9a-f]{2})")
_PRIVATE_MARKER = "[REDACTED_FORM_VALUE]"
# Protect a named field delimiter only while the original generic redactor
# runs; otherwise its broad key=value matcher can consume the next &field.
# It is always stripped before any PRIVATE note is returned or written.
FIELD_BOUNDARY_GUARD = "_LIGHTUP_PRIVATE_CURL_FIELD_BOUNDARY_"


def _field_key(name: str) -> str:
    """Canonicalise only a field name for credential matching.

    Decode at most three bounded layers of percent-encoded ASCII letters,
    digits, underscore or hyphen. NFKC folds compatibility spellings, and
    Unicode format controls are ignored for matching. The original key is
    retained in output; the value is withheld. Never decode payload values
    or use a URI, shell or network parser here.
    """
    def decode_ascii_name_char(match: re.Match[str]) -> str:
        character = chr(int(match.group(1), 16))
        if character.isascii() and (character.isalnum() or character in "_-"):
            return character
        return match.group(0)

    canonical = name
    # Bound nested name-only percent decoding. Expose an encoded percent only
    # when another two-hex escape follows; values and original key spelling
    # are never decoded or rewritten.
    for _ in range(3):
        exposed = re.sub(r"(?i)%25(?=[0-9a-f]{2})", "%", canonical)
        decoded = _PERCENT_ASCII_FIELD_CHAR.sub(decode_ascii_name_char, exposed)
        if decoded == canonical:
            break
        canonical = decoded
    canonical = unicodedata.normalize("NFKC", canonical)
    return "".join(character for character in canonical
                   if unicodedata.category(character) != "Cf")


def _mask_field(fragment: str, *, urlencoded: bool) -> str:
    """Withhold value or curl's named file source for a known field."""
    equals = fragment.find("=")
    at_sign = fragment.find("@")
    if equals < 0 and at_sign < 0:
        return fragment
    if equals >= 0 and (at_sign < 0 or equals < at_sign):
        split_at = equals
    else:
        split_at = at_sign
    raw_name = fragment[:split_at]
    name = raw_name.strip()
    if not _CREDENTIAL_FIELD.fullmatch(_field_key(name)):
        return fragment
    # The @source form of --data-urlencode and --form is also private.
    # Retain the original delimiter/key as a cue for HUMAN review.
    separator = fragment[split_at]
    return (fragment[:split_at] + FIELD_BOUNDARY_GUARD
            + fragment[split_at:split_at + 1] + _PRIVATE_MARKER)


def _mask_payload(match: re.Match[str]) -> str:
    payload = match.group("payload")
    # Nested JSON and other non-form bodies are handled separately by
    # original masks. Do not guess field separators inside structured data.
    if payload.lstrip().startswith(("{", "[")):
        return match.group(0)
    segments = _FIELD_DELIMITER.split(payload)
    for index in range(0, len(segments), 2):
        segments[index] = _mask_field(
            segments[index], urlencoded=match.group("flag").lower() ==
            "--data-urlencode")
    return (match.group("flag") + match.group("separator")
            + match.group("quote") + "".join(segments) + match.group("quote"))


def _mask_unquoted(match: re.Match[str]) -> str:
    payload = match.group("payload")
    masked = _mask_field(payload, urlencoded=match.group("flag").lower() == "--data-urlencode")
    return match.group("flag") + match.group("separator") + masked


def mask_curl_form_payloads(text: str) -> str:
    """Mask known credential name=value / name@file form fragments.

    Multiple query-style fields in one bounded quoted argument are handled.
    Arbitrary shell syntax, encodings and nested structures are not.
    """
    quoted = _CURL_ARGUMENT.sub(_mask_payload, text)
    return _CURL_UNQUOTED.sub(_mask_unquoted, quoted)
