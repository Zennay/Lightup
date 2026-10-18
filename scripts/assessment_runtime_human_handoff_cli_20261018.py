"""Export a minimized offline human follow-up from an existing source-bound review.

Only accepted ten-member private review packets can be summarized.
The shared ZIP contains neither original scenario IDs nor source-byte hashes.
It cannot prove authenticity, authorize an assessment or release anything.
"""
from __future__ import annotations

import argparse
from collections import Counter
from hashlib import sha256
from io import BytesIO
import json
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED

from assessment_runtime_attach_triage_cli_20261018 import _read_raw_archive
from assessment_runtime_review_handoff_cli_20261018 import _write_exclusive
from assessment_runtime_verify_pack_cli_20261018 import inspect_bytes, _json

LIMIT = 400_000
STAGES = ("todo", "investigating", "waiting", "planned", "reviewed")


def _recipient_brief(raw: bytes):
    # Same bounded original snapshot throughout admission and conversion.
    status = inspect_bytes(raw)
    with ZipFile(BytesIO(raw), "r") as source:
        old = _json(source.read("manifest.json"))
        if old["format"] != "lightup.private_lab_review_pack.v2":
            raise ValueError("an original source-bound human review is required")
        saved = _json(source.read("saved-human-review.json"))
        summary = source.read("human-summary.html")
        worklist = source.read("human-worklist.csv")
    counts = Counter(row["human_stage"] for row in saved["cases"])
    # Purely aggregated human planning counters, never release/approval.
    manifest = json.dumps({
        "format": "lightup.ordinal_human_followup.v1",
        "comparison_status": status,
        "case_count": len(saved["cases"]),
        "human_stages": {name: counts[name] for name in STAGES},
        "human_summary_sha256": sha256(summary).hexdigest(),
        "human_worklist_sha256": sha256(worklist).hexdigest(),
        "source_authenticated": False,
        "authorized": False,
        "consent_verified": False,
        "dispatch_allowed": False,
        "release_allowed": False,
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    instructions = (
        "LIGHTUP · MINIMIZED HUMAN FOLLOW-UP / NOT AUTHORIZED\n"
        "Open human-summary.html for original human planning stages and dates.\n"
        "Open human-worklist.csv for the source-regression follow-up checklist.\n"
        "Neither scenario IDs, original raw comparison JSON nor source fingerprints\n"
        "are included. Dates, aggregate counts and metrics may still be sensitive.\n"
        "Human planning is never assessment consent, scope, security or release GO.\n"
    ).encode("utf-8")
    buffer = BytesIO()
    with ZipFile(buffer, "w") as archive:
        for name, payload in (
            ("READ-ME.txt", instructions), ("human-summary.html", summary),
            ("human-worklist.csv", worklist), ("manifest.json", manifest),
        ):
            member = ZipInfo(name, date_time=(2026, 10, 18, 0, 0, 0))
            member.compress_type = ZIP_DEFLATED
            member.external_attr = 0o600 << 16
            archive.writestr(member, payload)
    result = buffer.getvalue()
    if len(result) > LIMIT:
        raise ValueError("human follow-up over limit")
    return result, status


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", help="Intact ten-member private source-bound review ZIP")
    parser.add_argument("--output", required=True, help="New private minimized follow-up ZIP")
    args = parser.parse_args(argv)
    try:
        raw, _ = _read_raw_archive(args.source)
        payload, status = _recipient_brief(raw)
        _write_exclusive(args.output, payload)
    except (OSError, ValueError, TypeError, KeyError, OverflowError,
            UnicodeError, RecursionError, AttributeError, RuntimeError,
            EOFError, NotImplementedError, BadZipFile, LargeZipFile):
        print("PRIVATE_HUMAN_HANDOFF_HOLD")
        return 3
    print("PRIVATE_HUMAN_HANDOFF_WRITTEN — " + status +
          "; UNSIGNED; NOT AUTHORIZED")
    return 2 if status == "REVIEW_ONLY" else 3


if __name__ == "__main__":
    raise SystemExit(main())
