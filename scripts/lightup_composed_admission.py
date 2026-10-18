"""Read original held/completed comparator ZIP without altering source metrics.

A source-bound original Review Desk result is a private human review document,
not source authentication, remediation evidence, client consent or permission.
"""
from __future__ import annotations

from hashlib import sha256
from io import BytesIO
from zipfile import ZipFile, BadZipFile

from archive import Hold, decode_json


EXPECTED = frozenset({
    "index.html", "START-HERE.txt", "review.html",
    "review-desk.html", "review-desk.json", "human-worklist.csv",
    "manifest.json",
})


def admit_original_review(data: bytes, *, baseline_sha: str,
                          candidate_sha: str, comparator_exit: int,
                          cohort: bool) -> tuple[bytes, str]:
    """Return *unmodified original* desk JSON and its claimed review state.

    Reject malformed review ZIPs before reusing the original status and
    fingerprints, including a valid original HOLD for measured regressions.
    """
    if type(data) is not bytes or not 0 < len(data) <= 8_388_608:
        raise Hold("invalid original review bytes")
    if comparator_exit not in (2, 3):
        raise Hold("original comparator rejected source")
    try:
        with ZipFile(BytesIO(data)) as original:
            names = original.namelist()
            if len(names) != 7 or len(set(names)) != 7 or set(names) != EXPECTED:
                raise Hold("invalid original report composition")
            if any(original.getinfo(name).file_size > 2_000_000
                   for name in names):
                raise Hold("excessive original report member")
            manifest = decode_json(original.read("manifest.json"))
            desk_bytes = original.read("review-desk.json")
            desk = decode_json(desk_bytes)
    except (BadZipFile, OSError, KeyError, ValueError, TypeError, RuntimeError) as error:
        raise Hold("corrupt original read-only review ZIP") from error
    if type(manifest) is not dict or type(desk) is not dict:
        raise Hold("original report not canonical")
    state = "REVIEW_ONLY" if comparator_exit == 2 else "HOLD"
    if (manifest.get("format") != "lightup.private_lab_review_pack.v1"
            or manifest.get("source_fingerprint_kind") != "original_input_file_bytes"
            or manifest.get("baseline_sha256") != baseline_sha
            or manifest.get("candidate_sha256") != candidate_sha
            or manifest.get("status") != state
            or manifest.get("comparison_type") != ("cohort" if cohort else "single_case")
            or manifest.get("review_desk_json_sha256") != sha256(desk_bytes).hexdigest()
            or desk.get("status") != state
            or not isinstance(desk.get("comparisons" if cohort else "changes"), list)
            or len(desk_bytes) > 262_144):
        raise Hold("original report/byte source disagreement")
    for flag in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
        if manifest.get(flag) is not False or desk.get(flag) is not False:
            raise Hold("original report cannot imply authorization")
    return desk_bytes, state
