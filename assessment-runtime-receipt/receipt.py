"""Offline receipt for already-exported, untrusted lab comparison JSON.

A receipt proves only byte identity, never source authenticity or permission.
"""
import hashlib
import json
from pathlib import Path

MAX_BYTES = 262144
FALSE_FLAGS = ("authorized", "consent_verified", "dispatch_allowed", "release_allowed")

def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result

def inspect(path):
    receipt = {"status": "HOLD", "source_authenticated": False,
               **{flag: False for flag in FALSE_FLAGS}}
    try:
        source = Path(path)
        if source.is_symlink() or not source.is_file():
            return receipt
        with source.open("rb") as handle:
            data = handle.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            return receipt
        obj = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_pairs,
                         parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite")))
        if type(obj) is not dict or obj.get("status") not in ("HOLD", "REVIEW_ONLY"):
            return receipt
        if any(obj.get(flag) is not False for flag in FALSE_FLAGS):
            return receipt
        receipt.update(status=obj["status"],
                       source_sha256=hashlib.sha256(data).hexdigest(),
                       byte_count=len(data))
    except (OSError, ValueError, UnicodeError, TypeError, RecursionError):
        pass
    return receipt

if __name__ == "__main__":
    import sys
    print(json.dumps(inspect(sys.argv[1] if len(sys.argv) == 2 else ""), sort_keys=True))
    raise SystemExit(3)
