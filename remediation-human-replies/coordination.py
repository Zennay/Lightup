#!/usr/bin/env python3
"""Private source-bound HUMAN return coordination into a native encrypted reply.

Reopens an original selected source-redacted .luhq plus 2..8 existing .luhr
files with the unchanged original admission. Generates a new editable HUMAN
response that can be saved as the existing native encrypted .luhr format.
It does NOT attest independent people, consensus, original findings or consent.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import sys

import reply

WARNING = (
    "INCUBATE M3/M7 DRAFT/HOLD. This privately displayed side-by-side "
    "HUMAN response history is unverified self-declared text from encrypted "
    "files, NOT independently authenticated people, consensus, evidence, "
    "security remediation, retesting, actual consent, scanner/grant approval "
    "or a source of real client identity. Coordinated HUMAN reply is a new "
    "manual statement, never a verified fix."
)

def require(condition: bool, message: str) -> None:
    reply.require(condition, message)

def compile_workroom(handoff: Path, received: list[Path],
                     destination: Path, continuation: Path | None = None) -> None:
    require(handoff.is_absolute() and
            2 <= len(received) <= 8 and len(set(received)) == len(received)
            and all(x.is_absolute() for x in received) and
            handoff not in received, "Select 2–8 distinct original encrypted HUMAN reply files")
    require(destination.is_absolute()
            and destination.parent == destination.parent.resolve(strict=True)
            and not destination.exists() and not destination.is_symlink()
            and handoff != destination and handoff.parent != destination
            and all(x != destination and x.parent != destination for x in received),
            "Coordinated HUMAN workroom needs separate new absolute PRIVATE directory")
    if continuation is not None:
        require(continuation.is_absolute() and
                continuation not in [handoff, *received] and
                continuation != destination and continuation.parent != destination,
                "Continuing HUMAN decision must use a distinct original encrypted .luhr")
    for path in [handoff, *received, *([continuation] if continuation else [])]:
        require(destination not in path.parents and path not in destination.parents,
                "Original encrypted HUMAN input/output locations must not overlap")

    original, source_key, source_bytes = reply.source(handoff)
    require(1 <= len(original["items"]) <= 256,
            "Bound private coordination to 256 actual selected HUMAN request groups")

    joined = [[] for _ in original["items"]]
    saved_sources: list[tuple[Path, bytes]] = []
    seen = set()
    for file_ordinal, response_path in enumerate(received, 1):
        # Strict original source + chosen item ordinal/reason admission and
        # separate interactive AES-GCM password for every existing reply.
        responses, ciphertext = reply.admitted_reply(response_path, original, source_key)
        signature = hashlib.sha256(ciphertext).digest()
        require(signature not in seen,
                "Duplicate exact encrypted HUMAN reply is not another file/reviewer")
        seen.add(signature)
        saved_sources.append((response_path, ciphertext))
        for i, item in enumerate(responses):
            joined[i].append({
                "file_slot": file_ordinal,
                "status": item["status"],
                "answer": item["answer"],
                "question": item["question"],
            })

    # New coordination starts with ZERO inherited respondent statements.
    # Resuming can load only an explicitly selected, independently decrypted,
    # exact-original-bound previously saved coordinator .luhr from the user.
    previous = None
    saved_continuation = None
    if continuation is not None:
        previous, exact = reply.admitted_reply(continuation, original, source_key)
        # Do not allow a previous responder file to masquerade as a separately
        # authored previous coordinator state.
        require(hashlib.sha256(exact).digest() not in seen,
                "Previous coordinator .luhr may not be one of the earlier reply files")
        saved_continuation = (continuation, exact)
    page = reply.editable_page(original, source_key, previous=previous,
                               comparisons=joined)
    require(len(page) <= 2_800_000,
            "Selected original private HUMAN response comparison exceeds browser bound")
    all_previous = [*saved_sources, *([saved_continuation] if saved_continuation else [])]
    require(reply.encrypted_cockpit.private_envelope(handoff) == source_bytes
            and all(reply.schedule_vault.private_vault(p) == original_bytes
                    for p, original_bytes in all_previous),
            "Original PRIVATE HUMAN sources changed during coordinated workroom preparation")

    receipt = reply.schedule.canonical({
        "kind": "lightup.private_human_selected_reply_coordination.v1",
        "version": 1,
        "disposition": "PRIVATE_HUMAN_ONLY_DRAFT_HOLD",
        "authority_granted": False,
        "consent_verified": False,
        "source_authenticated": False,
        "remediation_verified": False,
        "unique_reviewers_verified": False,
        "original_selected_human_tasks": len(original["items"]),
        "submitted_encrypted_reply_file_slots": len(received),
        "coordinator_statements_autofilled": False,
        "prior_coordinator_encrypted_state_explicitly_reopened": continuation is not None,
        "warning": WARNING,
    })
    reply.exclusive_output(destination,
                           [handoff, *received, *([continuation] if continuation else [])], {
        "index.html": page,
        "anonymous-counts.json": receipt,
        "README.txt": (
            WARNING + "\nThe local index.html contains decrypted, previously "
            "self-declared HUMAN answer and request text and is PRIVATE. "
            "Original source hashes/case identifiers absent from the redacted "
            "handoff remain unknown, not authenticated. Earlier replies are "
            "DISPLAY ONLY. New coordination starts with blank HUMAN response; "
            "when --continuation was explicitly selected the previously saved "
            "encrypted own HUMAN answer is decrypted and loaded for editing. "
            "Always deliberately save a NEW encrypted .luhr in the browser. "
            "This .luhr intentionally excludes prior "
            "respondents' answers/owner notes/identifying metadata, and can "
            "be admitted by original native reply.py open/resume and "
            "reconcile.py without any schema change.\n"
        ).encode("utf-8"),
    })
    print("REVIEW_ONLY: PRIVATE HUMAN coordinator:", destination / "index.html")
    print("Original admitted reply file slots:", len(received))
    print("Earlier reviewer statements never automatically become the coordinator decision.")
    print("Explicit prior own encrypted response resumed:", continuation is not None)
    print("No verified reviewer identity, independent consent, scan or grant.")

def main() -> int:
    cmd = argparse.ArgumentParser(description=__doc__)
    cmd.add_argument("--handoff", type=Path, required=True,
                     help="Same originally selected encrypted source-redacted HUMAN .luhq")
    cmd.add_argument("--reply", type=Path, action="append", required=True,
                     help="Different prior encrypted HUMAN .luhr; select 2–8")
    cmd.add_argument("--continuation", type=Path,
                     help="Optional DIFFERENT previously encrypted HUMAN coordinator .luhr "
                          "to resume; native full original-bound admission and password")
    cmd.add_argument("--output-dir", type=Path, required=True,
                     help="Fresh owner-private absolute HUMAN coordination folder")
    args = cmd.parse_args()
    try:
        compile_workroom(args.handoff, args.reply, args.output_dir,
                         continuation=args.continuation)
        return 2
    except (reply.single_review.review.Hold, OSError, ValueError,
            TypeError, KeyError, ImportError, RuntimeError,
            UnicodeError, OverflowError) as exc:
        print("HOLD: PRIVATE source-bound HUMAN coordination: " + str(exc),
              file=sys.stderr)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
