"""Opt-in *synthetic only* stdin Git path-stream preflight for #1541.

This standalone, no-authority review reads one bounded canonical JSON record
from stdin. No Git subprocess, assets, credentials, scan, grant, handler,
repository authenticity or deployment is involved. It is not production-wired.
Success is REVIEW_ONLY / exit 3, never an authorization or exit zero.
"""
from __future__ import annotations

import base64
import binascii
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scope_git_path_identity_oracle_1541 import parse_git_path_outputs

_MAX_JSON_BYTES = 786432
_MAX_GIT_OUTPUT = 262144
_SCHEMA = "lightup.scope_git_paths_synthetic.v1"
_REQUIRED = frozenset({"schema", "synthetic_only", "status_b64", "numstat_b64"})
_FALSE_FIELDS = (
    "authorized", "consent_verified", "permit_issued", "dispatch_allowed",
    "execution_allowed", "merge_allowed", "release_allowed",
)


def _receipt(status: str) -> bytes:
    data = {name: False for name in _FALSE_FIELDS}
    data.update(status=status, synthetic_only=True)
    return (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


_HOLD = _receipt("HOLD")
_REVIEW = _receipt("REVIEW_ONLY")


def _no_duplicate_keys(pairs):
    document = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("noncanonical")
        document[key] = value
    return document


def _reject_nonfinite(value):
    raise ValueError("noncanonical")


def _decode_github_stream(encoded: object) -> bytes:
    if type(encoded) is not str or not encoded or len(encoded) > 4 * ((_MAX_GIT_OUTPUT + 2) // 3):
        raise ValueError("noncanonical")
    raw = base64.b64decode(encoded, validate=True)
    if (not raw or len(raw) > _MAX_GIT_OUTPUT or
            base64.b64encode(raw).decode("ascii") != encoded):
        raise ValueError("noncanonical")
    return raw


def _review(raw: bytes) -> bool:
    if type(raw) is not bytes or not raw or len(raw) > _MAX_JSON_BYTES:
        return False
    try:
        document = json.loads(raw.decode("utf-8", "strict"),
                              object_pairs_hook=_no_duplicate_keys,
                              parse_constant=_reject_nonfinite)
        if type(document) is not dict or set(document) != _REQUIRED:
            return False
        if (document["schema"] != _SCHEMA or type(document["schema"]) is not str or
                document["synthetic_only"] is not True):
            return False
        canonical = json.dumps(document, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=True, allow_nan=False).encode("ascii")
        if canonical != raw:
            return False
        status = _decode_github_stream(document["status_b64"])
        numstat = _decode_github_stream(document["numstat_b64"])
        parse_git_path_outputs(status, numstat)
        return True
    except Exception:
        # Privacy-minimal HOLD. In particular do not print any malformed
        # base64, filename, JSON field, traceback or other provided content.
        return False


def main() -> int:
    try:
        if len(sys.argv) != 1:
            result = False
        else:
            raw = sys.stdin.buffer.read(_MAX_JSON_BYTES + 1)
            result = _review(raw)
    except Exception:
        result = False
    try:
        sys.stdout.buffer.write(_REVIEW if result else _HOLD)
        sys.stdout.buffer.flush()
    except OSError:
        return 2
    return 3 if result else 2


if __name__ == "__main__":
    raise SystemExit(main())
