"""Conservative offline lexical gate for synthetic HTTP/1.1 fixtures (issue #1161).

IMPORTANT: A passing result cannot authenticate installed Nginx/Gunicorn
parsing, exclude desynchronization or authorize a target. This function
handles caller-owned bytes in memory only; it performs no HTTP I/O.
"""
from __future__ import annotations

MAX_FIXTURE_BYTES = 16 * 1024
MAX_SYNTHETIC_BODY = 8 * 1024
MAX_HEADER_FIELDS = 24

# A deliberately *narrow* allowlist, NOT an RFC-complete HTTP parser.
HEADER_TOKEN = frozenset(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-")
DIGIT = frozenset(b"0123456789")
FORBIDDEN_HOP_FIELDS = frozenset({
    b"transfer-encoding", b"te", b"trailer", b"connection",
    b"proxy-connection", b"upgrade",
})
ALLOWED_REQUEST_LINES = frozenset({
    b"GET /health HTTP/1.1",
    b"POST /clients HTTP/1.1",
})


def accepts_synthetic_http1_fixture(payload: object) -> bool:
    """Reject ambiguous or out-of-fixture HTTP/1.1 bytes before use in a lab.

    Designed ONLY as a local test-fixture gate. Never use its True result as
    permission to send a request, start an assessment, or activate a grant.
    """
    if type(payload) is not bytes:
        return False
    if not 0 < len(payload) <= MAX_FIXTURE_BYTES:
        return False
    marker = payload.find(b"\r\n\r\n")
    if marker < 0:
        return False
    header_section, body = payload[:marker], payload[marker + 4:]
    lines = header_section.split(b"\r\n")
    if not lines or lines[0] not in ALLOWED_REQUEST_LINES:
        return False
    if not 1 <= len(lines) - 1 <= MAX_HEADER_FIELDS:
        return False
    if any(b"\r" in line or b"\n" in line for line in lines):
        return False

    fields: dict[bytes, bytes] = {}
    for field in lines[1:]:
        if b":" not in field:
            return False
        name, raw_value = field.split(b":", 1)
        if not name or any(ch not in HEADER_TOKEN for ch in name):
            return False
        lower_name = name.lower()
        # Duplicated fields are not normalized, even when both values agree.
        if lower_name in fields or lower_name in FORBIDDEN_HOP_FIELDS:
            return False
        # Exact, single-SP fixture syntax; reject obs-fold and hidden controls.
        if not raw_value.startswith(b" ") or raw_value.startswith(b"  "):
            return False
        value = raw_value[1:]
        if (not value or value[0] == 32 or value[-1] == 32
                or any(c < 32 or c > 126 for c in value)):
            return False
        fields[lower_name] = value

    # Do not allow arbitrary hosts or routes even for a syntactically clean
    # in-memory fixture. Actual target grants remain an independent boundary.
    if fields.get(b"host") != b"localhost":
        return False

    is_post = lines[0] == b"POST /clients HTTP/1.1"
    if not is_post:
        return b"content-length" not in fields and b"content-type" not in fields and body == b""

    if fields.get(b"content-type") != b"application/x-www-form-urlencoded":
        return False
    length = fields.get(b"content-length")
    if length is None or not length:
        return False
    if (length != b"0" and
            (length[0] not in b"123456789" or any(ch not in DIGIT for ch in length))):
        return False
    # Bound before any int conversion and compare byte-for-byte, rather than
    # accepting a prefix of a truncated or concatenated request.
    if len(length) > 4:
        return False
    declared = int(length)
    if declared > MAX_SYNTHETIC_BODY or declared != len(body):
        return False
    return True
