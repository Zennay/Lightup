"""Bounded, inert cURL form payload masking for PRIVATE original notes.

Recognises only known credential field names within a quoted cURL argument.
Not a general shell, form or URI parser: unknown shapes still require human
review, and NO derived output is cleared for publication or execution.
"""
from __future__ import annotations

import re

_CURL_ARGUMENT = re.compile(
    r"""(?ix)(?<![A-Za-z0-9_-])
    (?P<flag>--data(?:-raw|-binary|-urlencode)?|--form(?:-string)?|-[dF])
    (?P<separator>[ \t]*=[ \t]*|[ \t]+|(?=['"]))
    (?P<quote>["'])
    (?P<payload>(?:\\.|(?! (?P=quote) )[^\\\r\n]){0,8192})
    (?P=quote)""",
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
_PERCENT_UNDERSCORE = re.compile(r"(?i)%5f")
_PERCENT_HYPHEN = re.compile(r"(?i)%2d")
_PRIVATE_MARKER = "[REDACTED_FORM_VALUE]"


def _field_key(name: str) -> str:
    # Decode only separators in a field name; do not decode a payload or
    # interpret arbitrary percent escapes and do not perform network access.
    name = _PERCENT_UNDERSCORE.sub("_", name)
    return _PERCENT_HYPHEN.sub("-", name)


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
    return fragment[:split_at + 1] + _PRIVATE_MARKER


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


def mask_curl_form_payloads(text: str) -> str:
    """Mask known credential name=value / name@file form fragments.

    Multiple query-style fields in one bounded quoted argument are handled.
    Arbitrary shell syntax, encodings and nested structures are not.
    """
    return _CURL_ARGUMENT.sub(_mask_payload, text)
