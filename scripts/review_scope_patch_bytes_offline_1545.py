#!/usr/bin/env python3
"""Strict fictional Git patch bytes review — never grants authorization.

Opt-in, stdin-only, zero network/Git/handler/target access. A syntactically
valid patch is REVIEW_ONLY, not approval. Any ambiguity is atomic HOLD.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import sys
import unicodedata

SCHEMA = "lightup.scope.synthetic_patch_bytes.v1"
MAX_STDIN = 196608
MAX_PATCH = 32768
MAX_TOTAL_PATCH = 131072
MAX_PATCHES = 16
MAX_HUNKS = 64
MAX_HUNK_LINES = 8192
HOLD = 2
REVIEW_ONLY = 3
IDENT = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,31}\Z", re.ASCII)
SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
HUNK = re.compile(r"@@ -([0-9]+)(?:,([0-9]+))? \+([0-9]+)(?:,([0-9]+))? @@(?: [^\n]*)?\Z", re.ASCII)
FLAGS = {
    "authorized": False,
    "client_consent_verified": False,
    "operator_consent_verified": False,
    "grant_allowed": False,
    "scan_allowed": False,
    "dispatch_allowed": False,
    "merge_allowed": False,
    "deploy_allowed": False,
    "release_allowed": False,
}


class Hold(ValueError):
    """Never include user supplied text in HOLD receipts."""


def _object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise Hold("duplicate key")
        result[key] = value
    return result


def _constant(_text: str) -> None:
    raise Hold("nonfinite")


def _exact_patch_text(raw: bytes) -> str:
    try:
        value = raw.decode("utf-8", errors="strict")
    except UnicodeError:
        raise Hold("invalid UTF-8") from None
    if not value or "\ufffd" in value or "\r" in value or "\0" in value:
        raise Hold("lossy or ambiguous patch")
    if unicodedata.normalize("NFC", value) != value:
        raise Hold("non-canonical Unicode patch text")
    # Some invisible characters are categorised as letters or symbols rather
    # than format/controls: Hangul fillers and the visually blank Braille cell.
    blank_glyphs = {"\u115f", "\u1160", "\u3164", "\uffa0", "\u2800"}
    for char in value:
        if char in "\n\t":
            continue
        category = unicodedata.category(char)
        if (category in {"Cc", "Cf", "Cs", "Zl", "Zp", "Mn", "Me"}
                or (category == "Zs" and char != " ")
                or char in blank_glyphs):
            raise Hold("invisible or ambiguous patch character")
    return value


def _int_group(match: re.Match[str], group: int, default: int) -> int:
    text = match.group(group)
    result = default if text is None else int(text)
    if result > MAX_HUNK_LINES:
        raise Hold("oversized hunk")
    return result


def check_patch(raw: bytes) -> bool:
    """Validate a single headerless unified patch, never scan any target."""
    if type(raw) is not bytes or len(raw) > MAX_PATCH:
        return False
    try:
        body = _exact_patch_text(raw)
        if body.endswith("\n"):
            return False  # producer strips the final newline; no identity alias
        lines = body.split("\n")
        if any(len(line.encode("utf-8")) > 8192 for line in lines):
            return False
        index = 0
        previous_old_end = -1
        previous_new_end = -1
        hunks = 0
        while index < len(lines):
            match = HUNK.fullmatch(lines[index])
            if match is None:
                return False
            hunks += 1
            if hunks > MAX_HUNKS:
                return False
            old_start = int(match.group(1))
            new_start = int(match.group(3))
            old_count = _int_group(match, 2, 1)
            new_count = _int_group(match, 4, 1)
            if old_start > 100000000 or new_start > 100000000:
                return False
            if (old_count and old_start == 0) or (new_count and new_start == 0):
                return False
            if old_start <= previous_old_end or new_start <= previous_new_end:
                return False
            previous_old_end = old_start + old_count - 1
            previous_new_end = new_start + new_count - 1
            if previous_old_end > 100000000 or previous_new_end > 100000000:
                return False
            index += 1
            old_seen = new_seen = 0
            changed = False
            last_content = False
            used_no_newline = False
            while index < len(lines) and not lines[index].startswith("@@ "):
                line = lines[index]
                if line == r"\ No newline at end of file":
                    if not last_content or used_no_newline:
                        return False
                    used_no_newline = True
                    last_content = False
                else:
                    if not line or line[0] not in " +-":
                        return False
                    if line[0] in "+-":
                        changed = True
                    if line[0] in " -":
                        old_seen += 1
                    if line[0] in " +":
                        new_seen += 1
                    last_content = True
                    used_no_newline = False
                if old_seen > old_count or new_seen > new_count:
                    return False
                index += 1
            if old_seen != old_count or new_seen != new_count or not changed:
                return False
        return hunks > 0
    except (ValueError, UnicodeError, OverflowError, RecursionError):
        return False


def check_document(document: object) -> bool:
    if type(document) is not dict or set(document) != {"schema", "patches"}:
        return False
    schema = document["schema"]
    if type(schema) is not str or schema != SCHEMA:
        return False
    patches = document["patches"]
    if type(patches) is not list or not 1 <= len(patches) <= MAX_PATCHES:
        return False
    total = 0
    names: set[str] = set()
    for patch in patches:
        if type(patch) is not dict or set(patch) != {"path_id", "patch_b64", "sha256"}:
            return False
        name, encoded, digest = patch["path_id"], patch["patch_b64"], patch["sha256"]
        if type(name) is not str or IDENT.fullmatch(name) is None or name in names:
            return False
        names.add(name)
        if type(encoded) is not str or len(encoded) > (MAX_PATCH * 4 // 3 + 8) or not encoded.isascii():
            return False
        if type(digest) is not str or SHA256.fullmatch(digest) is None:
            return False
        try:
            raw = base64.b64decode(encoded, validate=True)
            if base64.b64encode(raw).decode("ascii") != encoded:
                return False
        except (ValueError, binascii.Error):
            return False
        total += len(raw)
        if total > MAX_TOTAL_PATCH:
            return False
        if hashlib.sha256(raw).hexdigest() != digest or not check_patch(raw):
            return False
    return True


def evaluate(data: bytes) -> int:
    if type(data) is not bytes or not 1 <= len(data) <= MAX_STDIN:
        return HOLD
    try:
        document = json.loads(
            data.decode("ascii", errors="strict"),
            object_pairs_hook=_object_pairs,
            parse_constant=_constant,
        )
        canonical = json.dumps(
            document, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        return REVIEW_ONLY if canonical == data and check_document(document) else HOLD
    except (UnicodeError, ValueError, TypeError, OverflowError, RecursionError):
        return HOLD


def receipt(code: int) -> str:
    return json.dumps({
        "schema": SCHEMA,
        "status": "REVIEW_ONLY" if code == REVIEW_ONLY else "HOLD",
        "basis": "untrusted_synthetic_patch_bytes_only",
        **FLAGS,
    }, sort_keys=True, separators=(",", ":")) + "\n"


def main() -> int:
    try:
        code = HOLD if len(sys.argv) != 1 else evaluate(sys.stdin.buffer.read(MAX_STDIN + 1))
    except (OSError, UnicodeError, ValueError):
        code = HOLD
    output = receipt(code)
    try:
        if sys.stdout.write(output) != len(output):
            return HOLD
        sys.stdout.flush()
    except (OSError, UnicodeError, ValueError):
        return HOLD
    return code


if __name__ == "__main__":
    raise SystemExit(main())
