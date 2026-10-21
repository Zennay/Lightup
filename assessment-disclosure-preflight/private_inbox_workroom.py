"""One-command source-free PRIVATE inbox + original HUMAN action workroom.

Strictly local. Publishes the exact board and its matching human template in
one exclusive owner-private operation. No scans, grants, authorization, or
source evidence verification.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys

import private_inbox_actions as actions
import private_inbox_board as board
import private_intake as inbox
import private_reopen as original
from human_review import Hold


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create the complete source-free PRIVATE HUMAN inbox workroom")
    parser.add_argument("--private-parent", required=True,
                        help="existing owner-only 0700 parent of received PRIVATE rooms")
    parser.add_argument("--room", action="append", required=True,
                        help="exact received room name, repeat 1–12 times in intended slot order")
    parser.add_argument("--private-output-dir",
                        help="create mode: separate existing owner-only 0700 output directory")
    parser.add_argument("--saved-workroom-dir",
                        help="read-only reopen mode: existing owner-only 0700 saved workroom")
    parser.add_argument("--full-reopen", action="store_true",
                        help="explicit trusted TTY native HUMAN re-admission of every room; use the same setting as creation")
    args = parser.parse_args()
    parent_fd = None
    try:
        reopen_mode = args.saved_workroom_dir is not None
        if reopen_mode == (args.private_output_dir is not None):
            raise ValueError("choose exactly one of --private-output-dir (create) or --saved-workroom-dir (read-only reopen)")
        output_dir = args.saved_workroom_dir if reopen_mode else args.private_output_dir
        if not 1 <= len(args.room) <= board.MAX_ROOMS or len(set(args.room)) != len(args.room):
            raise ValueError("1–12 distinct original PRIVATE rooms required")
        parent_fd, parent_path = inbox.user_private_parent(args.private_parent)
        board.require_output_outside_source_tree(parent_path, output_dir)
        rows = [board.read_one(parent_fd, parent_path, name, slot)
                for slot, name in enumerate(args.room, 1)]
        if args.full_reopen:
            if not sys.stdin.isatty() or not sys.stdout.isatty():
                raise ValueError("full native HUMAN reopening requires a trusted interactive terminal")
            print("PRIVATE native HUMAN reopening for", len(rows), "explicitly selected rooms.")
            print("This is not source authentication, consent, a security verdict or release.")
            if input("Type exactly REOPEN to continue: ").strip() != "REOPEN":
                raise ValueError("HUMAN did not confirm original reopening")
            for name in args.room:
                original.reopen(parent_path, name)
            after = [board.read_one(parent_fd, parent_path, name, slot, full_reopened=True)
                     for slot, name in enumerate(args.room, 1)]
            expected = [{**row, "source_reopening": "ORIGINAL_NATIVE_REVIEW_ONLY"}
                        for row in rows]
            if after != expected:
                raise ValueError("original PRIVATE bytes or human choices changed during reopening")
            rows = after

        # The same exact JSON bytes bind the HUMAN template and finalizer.
        manifest = board.manifest_bytes(rows, args.full_reopen)
        digest = hashlib.sha256(manifest).hexdigest()
        artifacts = [
            (board.HTML, board.render(rows).encode("utf-8")),
            (board.CSV, board.source_free_csv(rows).encode("utf-8")),
            (board.JSON, manifest),
            (actions.TEMPLATE, actions.csv_template(digest, rows).encode("utf-8")),
        ]
        if reopen_mode:
            # Reconstruct every expected byte from the currently re-admitted
            # original rooms. A saved workroom is accepted only as a complete,
            # owner-private, exact four-file match; it is never rewritten.
            # Use the same strict owner-owned 0700 directory, full inventory,
            # regular unlinked 0600 file and exact-byte custody boundary as
            # standalone HUMAN template, finalized-plan and revision reopen.
            actions.reopen_private_artifacts(args.saved_workroom_dir, artifacts)
            print("REVIEW_ONLY: saved PRIVATE HUMAN workroom reopened read-only; all four output files match.")
            print("Original rooms and saved outputs were not changed; no authority or release was created.")
            return 2

        # One exclusive private publication: no board without its matching
        # native HUMAN worksheet, and no overwrite of any existing artifact.
        actions.publish_private_artifacts(args.private_output_dir, artifacts)
    except (OSError, TypeError, ValueError, UnicodeError, MemoryError, Hold):
        print("HOLD: complete PRIVATE HUMAN workroom not published or reopened; no authority",
              file=sys.stderr)
        return 3
    finally:
        if parent_fd is not None:
            os.close(parent_fd)
    print("REVIEW_ONLY: complete PRIVATE workroom published (HTML/CSV/JSON + matching HUMAN template)")
    print("Template binds exact board JSON bytes; use private_inbox_actions.py finalize after manual HUMAN editing")
    print("No scan, grant, authenticated consent, security approval or release")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
