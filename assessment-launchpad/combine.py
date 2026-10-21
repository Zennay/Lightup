#!/usr/bin/env python3
"""Compose original private Launchpad batches into one human-only lab proposal.

Never imports assessment execution, starts a provider, contacts a target, or
turns an unsigned packet into authority. Only an original-policy-admitted
owner-private packet can be an input.
"""
from __future__ import annotations

import argparse
import os
import sys

from build import Hold, admit, build
from compare import _load

_MAX_PACKETS = 12


def combine(source_dirs: list[str], output_dir: str) -> tuple[int, int]:
    if not 2 <= len(source_dirs) <= _MAX_PACKETS:
        raise Hold("choose 2–12 existing private launch packets")

    sources: list[dict] = []
    all_endpoints: list[str] = []
    for directory in source_dirs:
        # _load uses original reopen() for exact whole-packet hash coverage,
        # owner-only 0700/0600 admission, original LabScenario scope admission
        # and any source-bound Studio checks. Original inputs are untouched.
        original = _load(directory)
        if original["studio"]:
            # A Studio scenario is a byte-exact specific IP membership claim.
            # Combining two different scenario drafts would manufacture a new
            # scenario/ground-truth relationship not present in either source.
            raise Hold("Studio-bound packets cannot be combined")
        sources.append(original)
        all_endpoints.extend(original["endpoints"])

    # Do not silently discard duplicate URLs or infer aliases are equivalent.
    # The original source owner also limits an entire lab scenario to 16 URLs.
    if len(all_endpoints) != len(set(all_endpoints)):
        raise Hold("duplicate endpoint across private packet proposals")
    selected = admit(all_endpoints)

    # Reopen every original immediately before publication: if an input was
    # altered after its first read, refuse rather than silently adopt drift.
    for directory, original in zip(source_dirs, sources):
        again = _load(directory)
        if (again["studio"] or again["manifest_sha256"] != original["manifest_sha256"]
                or again["endpoints"] != original["endpoints"]):
            raise Hold("a selected private source changed during composition")

    # Record original unsigned source receipts only INSIDE the new owner-private
    # original packet START-HERE.txt. Its hash is already bound by build.py's
    # private-plan.json and checked by reopen.py. No names, paths or endpoints
    # leave the private output; there is no claimed producer authentication.
    handoff = (
        "\nHUMAN COMPOSITION / UNSIGNED SOURCE REFERENCES\n"
        "The source order is a human-selected proposal, not verified chronology.\n"
        "No original source was edited or authenticated; never infer consent.\n"
        + "".join(
            f"Source slot {i:02d}: original manifest SHA-256 {source['manifest_sha256']}\n"
            for i, source in enumerate(sources, 1)
        )
        + "The combined packet must be independently re-opened and reviewed.\n"
    )
    build(
        selected, output_dir, human_handoff_note=handoff,
        source_segments=tuple(
            (len(source["endpoints"]), source["manifest_sha256"])
            for source in sources
        ),
    )
    return len(sources), len(selected)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Combine existing owner-private original lab proposals; REVIEW_ONLY, never scan."
    )
    parser.add_argument("--packet", action="append", required=True,
                        help="original owner-private packet directory; repeat 2–12 times")
    parser.add_argument("--output-dir", required=True, help="NEW owner-private output directory")
    args = parser.parse_args(argv)
    try:
        count, urls = combine(args.packet, args.output_dir)
        print(f"PRIVATE_LAB_COMPOSITION_PREPARED — REVIEW_ONLY DRAFT/HOLD; "
              f"source_packets={count} proposed_endpoints={urls}; NO AUTHORITY")
        return 2
    except (Hold, OSError, ValueError, KeyError, TypeError, UnicodeError,
            OverflowError, RecursionError):
        print("PRIVATE_LAB_COMPOSITION_HOLD — source, membership or destination refused",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
