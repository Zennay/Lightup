from __future__ import annotations

import re

_PATTERNS: tuple[tuple[re.Pattern[str], object], ...] = (
    (
        re.compile(r"(?im)^([ \t]*(?:set-cookie|cookie):[ \t]*)[^\r\n]*$"),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"(?im)^([ \t]*(?:proxy-)?authorization:[ \t]*"
            r"[A-Za-z][A-Za-z0-9._~+\-]*[ \t]+)[^\r\n]*$"
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"(?i)\b(https?://)[^\s/@]+@"),
        r"\1[REDACTED]@",
    ),
    (
        re.compile(
            r"(?i)\b(authorization:\s*(?:bearer|basic)\s+)[A-Za-z0-9._~+\-/]+=*"
        ),
        r"\1[REDACTED]",
    ),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_ACCESS_KEY]"),
    (
        re.compile(
            r'''(?i)(["'])((?:(?:access|refresh|id|auth)[_-]?token|client[_-]?secret|aws[_-]?(?:secret[_-]?access[_-]?key|access[_-]?key[_-]?id|session[_-]?token)|api[_-]?key|token|secret|password))\1(\s*:\s*)(["'])((?:\\.|(?!\4)[^\\\r\n])*)\4'''
        ),
        lambda m: (
            f"{m.group(1)}{m.group(2)}{m.group(1)}{m.group(3)}"
            f"{m.group(4)}[REDACTED]{m.group(4)}"
        ),
    ),
    (
        re.compile(
            r'''(?i)\b((?:access|refresh|id|auth)[_-]?token|client[_-]?secret|aws[_-]?(?:secret[_-]?access[_-]?key|access[_-]?key[_-]?id|session[_-]?token))\b\s*[:=]\s*(["']?)[^\s,&"']+\2'''
        ),
        lambda m: f"{m.group(1)}=[REDACTED]",
    ),
    (
        re.compile(
            r'''(?i)\b(api[_-]?key|token|secret|password)\b\s*[:=]\s*(["']?)[^\s,&"']+\2'''
        ),
        lambda m: f"{m.group(1)}=[REDACTED]",
    ),
)


def redact_text(value: str) -> str:
    redacted = value
    for pattern, replacement in _PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted
