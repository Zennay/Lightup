"""Bounded, unambiguous HTML form parsing before authentication or mutations."""

from __future__ import annotations

import re
from urllib.parse import parse_qs

MAX_FORM_BYTES = 64 * 1024
MAX_FORM_FIELDS = 64


class FormError(ValueError):
    def __init__(self, status: str = "400 Bad Request"):
        super().__init__("invalid form request")
        self.status = status


def read_form(environ) -> dict[str, str]:
    # Never pass negative, missing or attacker-sized lengths to the stream.
    # WSGI servers decode transfer framing; this shell accepts fixed lengths.
    if environ.get("HTTP_TRANSFER_ENCODING"):
        raise FormError()
    length_text = environ.get("CONTENT_LENGTH", "")
    if not isinstance(length_text, str) or not re.fullmatch(r"[0-9]{1,10}", length_text):
        raise FormError()
    length = int(length_text)
    if length > MAX_FORM_BYTES:
        raise FormError("413 Payload Too Large")
    content_type = environ.get("CONTENT_TYPE", "").split(";", 1)[0].strip().lower()
    if content_type != "application/x-www-form-urlencoded":
        raise FormError("415 Unsupported Media Type")
    raw = environ["wsgi.input"].read(length) if length else b""
    if len(raw) != length:
        raise FormError()
    try:
        encoded = raw.decode("utf-8", errors="strict")
        if re.search(r"%(?![0-9A-Fa-f]{2})", encoded):
            raise ValueError("invalid percent escape")
        fields = parse_qs(encoded, keep_blank_values=True, strict_parsing=True,
                          encoding="utf-8", errors="strict",
                          max_num_fields=MAX_FORM_FIELDS)
    except (UnicodeError, ValueError):
        raise FormError() from None
    # Repeated security-sensitive fields must not acquire first/last-value
    # semantics that differ between the application and a proxy.
    if any(not key or len(values) != 1 for key, values in fields.items()):
        raise FormError()
    return {key: values[0] for key, values in fields.items()}
