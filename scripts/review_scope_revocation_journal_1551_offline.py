"""Offline pinned, detached fictional revocation journal review. NEVER consent/authority.

Raw journal SHA-256 must be externally retained. A matching local file is only
an untrusted consistency observation, not proof of complete/live revocations.
"""
from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import sys

PATH = Path(__file__).resolve().with_name("review_scope_document_binding_1551_offline.py")
SPEC = importlib.util.spec_from_file_location("scope1551_binding", PATH)
binding = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(binding)
timeline = binding.timeline
claim = timeline.claim
MAX_JOURNAL_BYTES = 32 * 1024


def _hold() -> dict[str, object]:
    return {"schema_version": 1, "status": "HOLD",
            "reason": "UNTRUSTED_OR_REVOKED_JOURNAL", **claim.AUTHORITY_FLAGS}


def _valid_journal(snapshot: bytes, journal: bytes, expected_sha256: str) -> bool:
    if (type(journal) is not bytes or not 0 < len(journal) <= MAX_JOURNAL_BYTES
        or type(expected_sha256) is not str
        or not claim.DIGEST.fullmatch(expected_sha256)
        or expected_sha256 == "0" * 64 or b"\\" in journal):
        return False
    if not hmac.compare_digest(hashlib.sha256(journal).hexdigest(), expected_sha256):
        return False
    try:
        recorded = json.loads(journal.decode("utf-8", "strict"),
                              object_pairs_hook=claim._pairs,
                              parse_constant=claim._constant)
        snapshots = json.loads(snapshot.decode("utf-8", "strict"),
                               object_pairs_hook=claim._pairs,
                               parse_constant=claim._constant)
    except (UnicodeError, ValueError, RecursionError, OverflowError, TypeError):
        return False
    if (type(recorded) is not dict
        or set(recorded) != {"schema_version", "proposal_sha", "scope_sha256",
                             "through_at", "principals", "covered_sequence", "events"}
        or type(recorded["schema_version"]) is not int
        or recorded["schema_version"] != 1):
        return False
    # timeline.review must already have validated snapshots and all nested fields.
    latest = snapshots["entries"][-1]["packet"]
    principals = {record["role"]: record["principal"] for record in latest["consents"]}
    if (recorded["proposal_sha"] != latest["proposal_sha"]
        or recorded["scope_sha256"] != latest["scope_sha256"]
        or recorded["through_at"] != latest["review_at"]
        or type(recorded["principals"]) is not dict
        or set(recorded["principals"]) != {"client", "operator"}
        or recorded["principals"] != principals):
        return False
    covered = recorded["covered_sequence"]
    if (type(covered) is not int or not 1 <= covered <= 65535
        or covered < max(record["event_seq"] for record in latest["consents"])):
        return False
    # Any event, including malformed, out-of-window or unknown actors, HOLD.
    # This prevents an event from being silently ignored based on its metadata.
    return type(recorded["events"]) is list and recorded["events"] == []


def review(snapshot: bytes, document: bytes, journal: bytes,
           journal_sha256: str) -> dict[str, object]:
    try:
        baseline = timeline.review(snapshot, scope_document_bytes=document)
        if baseline["status"] != "REVIEW_ONLY":
            return _hold()
        if not _valid_journal(snapshot, journal, journal_sha256):
            return _hold()
    except (ValueError, OSError, TypeError, KeyError, MemoryError,
            OverflowError, RecursionError):
        return _hold()
    return {"schema_version": 1, "status": "REVIEW_ONLY",
            "reason": "UNAUTHENTICATED_JOURNAL_CONSISTENCY_ONLY",
            **claim.AUTHORITY_FLAGS}


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    outcome = _hold()
    if (type(argv) is list and len(argv) == 6
        and all(type(part) is str for part in argv)
        and argv[0] == "--scope-document"
        and argv[2] == "--revocation-journal"
        and argv[4] == "--expected-journal-sha256"):
        try:
            scope_document = binding._read_regular_document(argv[1])
            journal_document = binding._read_regular_document(argv[3])
            timeline_input = binding._read_stdin()
            outcome = review(timeline_input, scope_document, journal_document, argv[5])
        except (ValueError, OSError, TypeError, MemoryError, OverflowError):
            outcome = _hold()
    try:
        output = json.dumps(outcome, sort_keys=True, separators=(",", ":")) + "\n"
        written = sys.stdout.write(output)
        sys.stdout.flush()
        if type(written) is not int or written != len(output):
            return 2
    except (OSError, ValueError, UnicodeError):
        return 2
    return 3 if outcome["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
