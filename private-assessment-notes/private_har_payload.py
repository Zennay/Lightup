"""Bounded offline HAR postData form-content admission; never privacy clearance.

Used only after the outer HAR/JSON object has been fully parsed and its
mimeType and text fields are both exact strings. No requests or filesystem
access; unknown encodings/fields are left to HUMAN review.
"""
from __future__ import annotations

import re
from urllib.parse import unquote_plus

MAX_BODY = 16 * 1024
MAX_FIELDS = 128
_FORM_TYPES = frozenset(("application/x-www-form-urlencoded",))
_MULTIPART_TYPE = "multipart/form-data"
_PART_DISPOSITION = re.compile(
    r"(?im)^[ \t]*content-disposition:[ \t]*form-data[^\r\n]{0,512}")
_PART_NAME = re.compile(
    r"""(?ix)(?:^|;)[ \t]*name[ \t]*=[ \t]*
    (?:"([^"\r\n]{1,256})"|'([^'\r\n]{1,256})'|([^;\s\r\n]{1,256}))"""
)
_JSON_TYPES = frozenset(("application/json", "application/ld+json",
                         "application/problem+json"))


def mime_family(raw: str) -> str | None:
    if type(raw) is not str or len(raw) > 128:
        return None
    content_type = raw.split(";", 1)[0].strip().lower()
    if content_type in _FORM_TYPES:
        return "form"
    if content_type == _MULTIPART_TYPE:
        return "multipart"
    if content_type in _JSON_TYPES or content_type.endswith("+json") and (
            content_type.startswith("application/")):
        return "json"
    return None


def contains_named_form_secret(payload: str, secret_name) -> bool:
    """Check named parameters only, with strict bounded key decoding.

    A true return means a known field *name* appeared: caller must withhold
    the complete original field-bearing text string, not the decoded copy.
    """
    if type(payload) is not str or len(payload) > MAX_BODY:
        return False
    fields = re.split(r"[&;]", payload)
    if len(fields) > MAX_FIELDS:
        return False
    for field in fields:
        name, equals, _ = field.partition("=")
        if not equals or not name or len(name) > 256:
            continue
        try:
            decoded_name = unquote_plus(name, encoding="utf-8", errors="strict")
        except UnicodeError:
            continue
        if secret_name.fullmatch(decoded_name) is not None:
            return True
    return False



def contains_named_multipart_secret(payload: str, secret_name) -> bool:
    """Recognize bounded literal multipart form-data part header names.

    Does not attempt to parse boundary contents, encoded part files,
    nested multipart messages or nonstandard folding. Marker is a
    reviewer cue only, never evidence of sanitized secrets.
    """
    if type(payload) is not str or len(payload) > MAX_BODY:
        return False
    seen = 0
    for disposition in _PART_DISPOSITION.finditer(payload):
        seen += 1
        if seen > MAX_FIELDS:
            return False
        field = _PART_NAME.search(disposition.group(0))
        if not field:
            continue
        key = next((value for value in field.groups() if value is not None),
                   "")
        if secret_name.fullmatch(key) is not None:
            return True
    return False
