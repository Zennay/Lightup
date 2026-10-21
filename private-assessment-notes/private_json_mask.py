"""Inert, bounded JSON/HAR credential field redaction for PRIVATE notes.

Preserves original JSON layout, ordering, and all non-sensitive tokens.
Only known string-valued credential fields are replaced. Never authenticates,
anonymizes, approves, sends, executes or guarantees complete sanitization.
"""
from __future__ import annotations

import json
import re
from json.decoder import scanstring
from private_har_payload import (
    MAX_BODY, contains_named_form_secret, contains_named_multipart_secret,
    mime_family,
)

MAX_FRAGMENT = 128 * 1024
MAX_ATTEMPTS = 96
MAX_NODES = 4096
MAX_DEPTH = 24

# These are known *literal* credential field names, not a privacy classifier.
_SECRET_FIELD = re.compile(
    r"""(?ix)^(?:authorization|proxy-authorization|cookie|set-cookie|
    x-api-key|x-auth-token|x-access-token|x-amz-security-token|
    x-goog-api-key|x-csrf-token|x-xsrf-token|
    api[_-]?key|password|passwd|pwd|secret|client[_-]?secret|
    private[_-]?key|access[_-]?token|refresh[_-]?token|
    auth[_-]?token|id[_-]?token|bearer[_-]?token|jwt|
    session(?:[_-]?(?:id|token|key))?|sid|csrf(?:[_-]?token)?|
    xsrf(?:[_-]?token)?|signature|sig|jsessionid|phpsessid|
    aws[_-]?secret[_-]?access[_-]?key)$"""
)
_HEADER_FIELD = re.compile(
    r"""(?ix)^(?:authorization|proxy-authorization|cookie|set-cookie|
    x-api-key|x-auth-token|x-access-token|x-amz-security-token|
    x-goog-api-key|x-csrf-token|x-xsrf-token)$"""
)
_CREDENTIAL_MARKER = "[REDACTED_JSON_VALUE]"
_HEADER_MARKER = "[REDACTED_HAR_HEADER_VALUE]"
_PARAM_MARKER = "[REDACTED_HAR_PARAM_VALUE]"
_HAR_FORM_MARKER = "[REDACTED_HAR_FORM_TEXT]"
_HAR_JSON_MARKER = "[REDACTED_HAR_EMBEDDED_JSON]"
_HAR_MULTIPART_MARKER = "[REDACTED_HAR_MULTIPART_TEXT]"
# In a well-formed HAR entry, request and response body text is not needed
# for a privacy-minimal human index. Withhold regardless of declared MIME,
# encoding or recognised field names; never claim comprehensive anonymisation.
_HAR_REQUEST_BODY_MARKER = "[REDACTED_HAR_REQUEST_BODY]"
_HAR_RESPONSE_BODY_MARKER = "[REDACTED_HAR_RESPONSE_BODY]"
_HAR_WEBSOCKET_MARKER = "[REDACTED_HAR_WEBSOCKET_FRAME]"
_HAR_COOKIE_MARKER = "[REDACTED_HAR_COOKIE_VALUE]"
_HAR_QUERY_MARKER = "[REDACTED_HAR_QUERY_VALUE]"
_HAR_FORM_PARAM_MARKER = "[REDACTED_HAR_FORM_PARAM_VALUE]"
_HAR_URL_MARKER = "[REDACTED_HAR_REQUEST_URL]"
_HAR_REDIRECT_MARKER = "[REDACTED_HAR_REDIRECT_URL]"
_HAR_ANY_HEADER_MARKER = "[REDACTED_HAR_ANY_HEADER_VALUE]"
_HAR_FILE_MARKER = "[REDACTED_HAR_FILE_REFERENCE]"
_DECODER = json.JSONDecoder(parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))


class _Reader:
    def __init__(self, source: str, position: int, *, allow_embedded: bool = True):
        self.source = source
        self.pos = position
        self.nodes = 0
        self.allow_embedded = allow_embedded
        self.spans: list[tuple[int, int, str]] = []

    def _ws(self) -> None:
        s = self.source
        while self.pos < len(s) and s[self.pos] in " \t\r\n":
            self.pos += 1

    def _char(self, token: str) -> None:
        self._ws()
        if self.pos >= len(self.source) or self.source[self.pos] != token:
            raise ValueError("invalid JSON punctuation")
        self.pos += 1

    def _string(self) -> tuple[str, int, int]:
        self._ws()
        if self.pos >= len(self.source) or self.source[self.pos] != '"':
            raise ValueError("not a JSON string")
        first = self.pos
        # The C-accelerated scanner takes positional-only arguments on CPython.
        # Passing strict= as a keyword raises TypeError before any HAR masking.
        decoded, end = scanstring(self.source, first + 1, True)
        self.pos = end
        return decoded, first, end

    def _node(self, depth: int, path: tuple[str, ...] = ()) -> tuple[str, str | None, int, int]:
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            raise ValueError("bounded JSON depth/nodes exceeded")
        self.nodes += 1
        self._ws()
        start = self.pos
        if self.pos >= len(self.source) or self.pos - self.start > MAX_FRAGMENT:
            raise ValueError("bounded JSON fragment exceeded")
        ch = self.source[self.pos]
        if ch == '"':
            value, a, b = self._string()
            return ("string", value, a, b)
        if ch == "{":
            self.pos += 1
            seen: set[str] = set()
            members: dict[str, tuple[str, str | None, int, int]] = {}
            self._ws()
            if self.pos < len(self.source) and self.source[self.pos] == "}":
                self.pos += 1
                return ("object", None, start, self.pos)
            while True:
                key, _, _ = self._string()
                if key in seen:
                    # Do not guess which duplicate name/value should win.
                    raise ValueError("duplicate JSON member")
                seen.add(key)
                self._char(":")
                node = self._node(depth + 1, path + (key,))
                members[key] = node
                # Structural HAR entry paths only. Leave the source archive
                # untouched and preserve its surrounding metadata. In this
                # PRIVATE derivative, omit complete opaque body strings even
                # when they are not shaped like a known credential.
                if node[0] == "string":
                    # A request URL can include opaque identifiers in any
                    # path/query, not only parameters named token/password.
                    # Withhold the entire URL in the derived local review.
                    if path[-1:] == ("request",) and key == "url":
                        self.spans.append((node[2], node[3], _HAR_URL_MARKER))
                    elif path[-1:] == ("response",) and key == "redirectURL":
                        self.spans.append((node[2], node[3], _HAR_REDIRECT_MARKER))
                    elif (path[-3:] == ("request", "postData", "params")
                          and key == "fileName"):
                        # Form-upload local paths can identify a reviewer,
                        # organisation or private evidence source.
                        self.spans.append((node[2], node[3], _HAR_FILE_MARKER))
                if key == "text" and node[0] == "string":
                    if path[-2:] == ("request", "postData"):
                        self.spans.append((node[2], node[3], _HAR_REQUEST_BODY_MARKER))
                    elif path[-2:] == ("response", "content"):
                        self.spans.append((node[2], node[3], _HAR_RESPONSE_BODY_MARKER))
                # DevTools HAR extensions may include captured WebSocket
                # frame strings in a _webSocketMessages array. Keep frame
                # metadata but never copy its message bytes into this PRIVATE
                # derivative; frames can include session or user content.
                if (key in ("data", "payload") and node[0] == "string"
                        and path[-1:] == ("_webSocketMessages",)):
                    self.spans.append((node[2], node[3], _HAR_WEBSOCKET_MARKER))
                if _SECRET_FIELD.fullmatch(key) and node[0] == "string":
                    self.spans.append((node[2], node[3], _CREDENTIAL_MARKER))
                self._ws()
                if self.pos >= len(self.source):
                    raise ValueError("truncated JSON object")
                if self.source[self.pos] == "}":
                    self.pos += 1
                    break
                self._char(",")
            # HAR cookie/query/form arrays and HTTP headers are represented as
            # small JSON objects; member order and intervening fields vary.
            # Use decoded JSON key/value identity, NOT text adjacency.
            name_node = members.get("name")
            value_node = members.get("value")
            if (name_node and value_node and name_node[0] == "string"
                    and value_node[0] == "string"
                    and isinstance(name_node[1], str)):
                # HAR cookies carry credentials even when exporters use an
                # arbitrary application-specific cookie name. Never display
                # any of their original string values in a derived PRIVATE
                # note. Preserve the cookie name for original HUMAN triage.
                if path[-2:] in (("request", "headers"),
                                 ("response", "headers")):
                    # Unknown headers can carry unrecognised session and
                    # customer data. Preserve name only for HUMAN triage.
                    marker = _HAR_ANY_HEADER_MARKER
                elif path[-2:] in (("request", "cookies"),
                                   ("response", "cookies")):
                    marker = _HAR_COOKIE_MARKER
                elif path[-2:] == ("request", "queryString"):
                    # Even unknown names can hold private searches or IDs.
                    marker = _HAR_QUERY_MARKER
                elif path[-3:] == ("request", "postData", "params"):
                    # postData.params often duplicates the opaque request
                    # body; minimise EVERY string parameter value locally.
                    marker = _HAR_FORM_PARAM_MARKER
                elif _SECRET_FIELD.fullmatch(name_node[1]):
                    marker = (_HEADER_MARKER
                              if _HEADER_FIELD.fullmatch(name_node[1])
                              else _PARAM_MARKER)
                else:
                    marker = None
                if marker is not None:
                    self.spans.append((value_node[2], value_node[3], marker))
            # HAR postData.text can contain an entire *serialized* request
            # body. The existing name/value pairs do NOT inspect this field.
            # Recognize only explicit original postData mimeType + text with
            # bounded, nonrecursive and strictly parsed parameter names.
            mime = members.get("mimeType")
            body = members.get("text")
            if (self.allow_embedded
                    and path[-2:] != ("request", "postData")
                    and mime and body
                    and mime[0] == "string" and body[0] == "string"
                    and type(mime[1]) is str and type(body[1]) is str
                    and len(body[1]) <= MAX_BODY):
                family = mime_family(mime[1])
                if (family == "form"
                        and contains_named_form_secret(body[1], _SECRET_FIELD)):
                    # Withhold the WHOLE source-serialized text field: this
                    # avoids leaking its other query/body members and preserves
                    # the parent original JSON object layout.
                    self.spans.append((body[2], body[3], _HAR_FORM_MARKER))
                elif (family == "multipart"
                      and contains_named_multipart_secret(body[1],
                                                          _SECRET_FIELD)):
                    self.spans.append((body[2], body[3], _HAR_MULTIPART_MARKER))
                elif family == "json":
                    try:
                        nested = _Reader(body[1], 0, allow_embedded=False)
                        consumed, nested_spans = nested.read()
                        if (nested_spans and not body[1][consumed:].strip()):
                            self.spans.append(
                                (body[2], body[3], _HAR_JSON_MARKER))
                    except (ValueError, UnicodeError, RecursionError,
                            OverflowError):
                        # An undecodable or ambiguous nested body never
                        # becomes a security/privacy clearance.
                        pass
            return ("object", None, start, self.pos)
        if ch == "[":
            self.pos += 1
            self._ws()
            if self.pos < len(self.source) and self.source[self.pos] == "]":
                self.pos += 1
                return ("array", None, start, self.pos)
            while True:
                self._node(depth + 1, path)
                self._ws()
                if self.pos >= len(self.source):
                    raise ValueError("truncated JSON array")
                if self.source[self.pos] == "]":
                    self.pos += 1
                    break
                self._char(",")
            return ("array", None, start, self.pos)
        value, end = _DECODER.raw_decode(self.source, self.pos)
        if type(value) not in (type(None), bool, int, float):
            raise ValueError("unexpected JSON scalar")
        self.pos = end
        return ("scalar", None, start, end)

    def read(self) -> tuple[int, list[tuple[int, int, str]]]:
        self.start = self.pos
        self._node(0)
        if self.pos - self.start > MAX_FRAGMENT:
            raise ValueError("JSON fragment too large")
        # One span per value even if both its own key and its name/value
        # relationship appear credential-like. The HAR meaning takes priority.
        chosen = {}
        for first, last, marker in self.spans:
            if (first, last) not in chosen or marker != _CREDENTIAL_MARKER:
                chosen[(first, last)] = marker
        return self.pos, [(a, b, value) for (a, b), value in chosen.items()]


def mask_json_fields(source: str) -> str:
    """Mask JSON secret string values, including nonadjacent HAR name/value.

    Embedded valid JSON object/array islands are admitted individually.
    Invalid, duplicate-key, overlong or over-deep islands are left untouched
    here (other original masks still run). Outputs ALWAYS PRIVATE/HOLD.
    """
    if not isinstance(source, str) or not source:
        return source
    masked: list[str] = []
    position = 0
    scan = 0
    attempts = 0
    while scan < len(source):
        if source[scan] not in "{[":
            scan += 1
            continue
        attempts += 1
        if attempts > MAX_ATTEMPTS:
            break
        try:
            end, spans = _Reader(source, scan).read()
            if not spans:
                scan = end
                continue
            masked.append(source[position:scan])
            offset = scan
            for first, last, marker in sorted(spans):
                if first < offset:
                    raise ValueError("overlapping JSON string spans")
                masked.append(source[offset:first])
                masked.append(json.dumps(marker))
                offset = last
            masked.append(source[offset:end])
            position = end
            scan = end
        except (ValueError, UnicodeError, RecursionError, OverflowError):
            scan += 1
    if not masked:
        return source
    masked.append(source[position:])
    return "".join(masked)
