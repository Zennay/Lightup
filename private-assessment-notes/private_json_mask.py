"""Inert, bounded JSON/HAR credential field redaction for PRIVATE notes.

Preserves original JSON layout, ordering, and all non-sensitive tokens.
Only known string-valued credential fields are replaced. Never authenticates,
anonymizes, approves, sends, executes or guarantees complete sanitization.
"""
from __future__ import annotations

import json
import re
from json.decoder import scanstring

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
_DECODER = json.JSONDecoder(parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))


class _Reader:
    def __init__(self, source: str, position: int):
        self.source = source
        self.pos = position
        self.nodes = 0
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
        decoded, end = scanstring(self.source, first + 1, strict=True)
        self.pos = end
        return decoded, first, end

    def _node(self, depth: int) -> tuple[str, str | None, int, int]:
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
                node = self._node(depth + 1)
                members[key] = node
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
                    and isinstance(name_node[1], str)
                    and _SECRET_FIELD.fullmatch(name_node[1])):
                marker = (_HEADER_MARKER if _HEADER_FIELD.fullmatch(name_node[1])
                          else _PARAM_MARKER)
                self.spans.append((value_node[2], value_node[3], marker))
            return ("object", None, start, self.pos)
        if ch == "[":
            self.pos += 1
            self._ws()
            if self.pos < len(self.source) and self.source[self.pos] == "]":
                self.pos += 1
                return ("array", None, start, self.pos)
            while True:
                self._node(depth + 1)
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
