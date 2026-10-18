#!/usr/bin/env python3
"""Offline local terminal navigator for source-bound archive and human follow-up.

All operations only handle filenames entered individually by the human.
No directory enumeration, shell dispatch, network, target or grant invocation.
"""
from __future__ import annotations

from types import SimpleNamespace
import sys
from zipfile import BadZipFile

import archive
import archive_studio
import agenda
import followup
import packet
import packet_inspect


ACTIONS = (
    ("1", "Create multi-artifact private archive"),
    ("2", "Recheck original source bytes"),
    ("3", "Open printable private or anonymous inventory"),
    ("4", "Export anonymous source category counts"),
    ("5", "Compare two private archive snapshots"),
    ("6", "Create source-bound human follow-up form"),
    ("7", "Publish follow-up desk from locally edited form"),
    ("8", "Package existing archive and human worklist for private local coordination"),
    ("9", "Build a private interactive Archive Studio browser workspace"),
    ("10", "Create source-bound human follow-up agenda and planned-date overview"),
    ("11", "Inspect a local coordination ZIP without extracting or trusting it"),
    ("q", "Exit without changing files"),
)


def ask(message: str) -> str:
    value = input(message + "\n> ").strip()
    if len(value) > 4096 or not value:
        raise archive.Hold("invalid operator selection")
    return value


def optional(message: str, fallback: str) -> str:
    value = input(message + f" [{fallback}]\n> ").strip()
    if len(value) > 32:
        raise archive.Hold("invalid operator selection")
    return value or fallback


def yes_no(message: str) -> bool:
    answer = optional(message + " (y/n)", "n").lower()
    if answer not in ("y", "n"):
        raise archive.Hold("invalid operator answer")
    return answer == "y"


def paths() -> list[str]:
    print("Enter each exact local file path separately. A blank line finishes selection.")
    result = []
    while len(result) <= 64:
        entry = input(f"Source {len(result)+1} (blank to finish): ").strip()
        if not entry:
            break
        if len(entry) > 4096:
            raise archive.Hold("input path too long")
        result.append(entry)
    if not 2 <= len(result) <= 64:
        raise archive.Hold("expected 2–64 explicitly selected source files")
    return result


def operation(choice: str) -> int:
    if choice == "1":
        source_files = paths()
        target = ask("New private manifest JSON path (must not exist)")
        return archive.capture(SimpleNamespace(sources=source_files, output=target))
    if choice == "2":
        manifest = ask("Existing owner-private manifest JSON path")
        source_files = paths()
        return archive.verify(SimpleNamespace(manifest=manifest, sources=source_files))
    if choice == "3":
        manifest = ask("Existing owner-private manifest JSON path")
        anonymous = yes_no("Hide original private byte fingerprints and item slots")
        output = ask("New local HTML dashboard path (must not exist)")
        return archive.view(SimpleNamespace(manifest=manifest, output=output,
                                            aggregate_only=anonymous))
    if choice == "4":
        manifest = ask("Existing owner-private manifest JSON path")
        output = ask("New anonymous category JSON path (must not exist)")
        return archive.share(SimpleNamespace(manifest=manifest, output=output))
    if choice == "5":
        before = ask("Older owner-private manifest JSON path")
        after = ask("Newer owner-private manifest JSON path")
        format_choice = optional("Output format: html or json", "html").lower()
        if format_choice not in ("html", "json"):
            raise archive.Hold("invalid format")
        anonymous = yes_no("Remove private SHA-256 byte fingerprints")
        output = ask("New source delta output path (must not exist)")
        return archive.diff(SimpleNamespace(previous=before, current=after,
                                            output=output, aggregate_only=anonymous,
                                            format=format_choice))
    if choice == "6":
        manifest = ask("Exact original owner-private manifest JSON path")
        output = ask("New editable owner-private follow-up form JSON path")
        return followup.draft(SimpleNamespace(manifest=manifest, output=output))
    if choice == "7":
        manifest = ask("Exact original owner-private manifest JSON path")
        choices = ask("Locally edited human follow-up JSON form path")
        format_choice = optional("Output format: html or json", "html").lower()
        if format_choice not in ("html", "json"):
            raise archive.Hold("invalid format")
        anonymous = yes_no("Remove individual human role and date assignments")
        output = ask("New human worklist output path (must not exist)")
        return followup.render(SimpleNamespace(manifest=manifest, choices=choices,
                                               output=output, aggregate_only=anonymous,
                                               format=format_choice))
    if choice == "8":
        manifest = ask("Existing owner-private archive manifest JSON path")
        with_choices = yes_no("Include source-bound human follow-up stages")
        followup_file = ask("Original edited human follow-up form JSON path") if with_choices else None
        agenda_date = (ask("Human agenda planning reference date YYYY-MM-DD")
                       if with_choices and yes_no("Include source-bound human agenda in ZIP") else None)
        anonymous = yes_no("Create aggregate-only packet without source fingerprints/roles/dates")
        include_studio = False if anonymous else yes_no("Include private interactive browser studio in ZIP")
        previous = (ask("Previous original private archive manifest path")
                    if include_studio and yes_no("Compare Studio to a previous private archive") else None)
        output = ask("New private coordination ZIP path (must not exist)")
        return packet.package(SimpleNamespace(manifest=manifest, choices=followup_file,
                                              output=output, aggregate_only=anonymous,
                                              include_studio=include_studio, previous=previous,
                                              agenda_date=agenda_date))
    if choice == "9":
        manifest = ask("Existing owner-private archive manifest JSON path")
        previous = (ask("Previously saved original private archive manifest JSON")
                    if yes_no("Compare against an earlier private archive") else None)
        output = ask("New interactive private Archive Studio HTML path (must not exist)")
        return archive_studio.build(manifest, output, previous)
    if choice == "10":
        manifest = ask("Original private archive manifest JSON path")
        choices = ask("Exact matching edited human follow-up JSON path")
        as_of = ask("Human agenda reference date YYYY-MM-DD")
        output_format = optional("Agenda format: html, md or json", "html").lower()
        if output_format not in ("html", "md", "json"):
            raise archive.Hold("unsupported human agenda format")
        anonymous = yes_no("Export category counts only with no source slot details")
        output = ask("New local human agenda output path (must not exist)")
        return agenda.action(SimpleNamespace(manifest=manifest, choices=choices,
                            as_of=as_of, format=output_format,
                            aggregate_only=anonymous, output=output))
    if choice == "11":
        name = ask("Existing local LightUp coordination ZIP path")
        private_summary = yes_no("Publish a new private source-neutral inspection receipt")
        output = ask("New private inspection JSON filename") if private_summary else None
        return packet_inspect.inspect(SimpleNamespace(packet=name, output=output))
    raise archive.Hold("invalid operation")


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if argv in (["--help"], ["-h"]):
        print("LightUp offline assessment archive operator console.")
        print("Usage: python3 assessment-archive/console.py")
        print("Requires interactive standard input. No network, scans, grants or file writes without explicit local paths.")
        return 0
    if argv:
        print("ASSESSMENT_ARCHIVE_HOLD — console accepts no command arguments")
        return 3
    print("LightUp · Local Lab Archive & Human Follow-up")
    print("INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. Not a permission or clearance.")
    while True:
        print("\nChoose an explicit private local action:")
        for number, label in ACTIONS:
            print(f" {number}. {label}")
        try:
            choice = input("> ").strip().lower()
            if choice == "q":
                print("OFFLINE_CONSOLE_CLOSED — NO AUTHORITY")
                return 2
            if choice not in {row[0] for row in ACTIONS}:
                print("Unknown operation; no action taken.")
                continue
            print("Source privacy: path selections stay local. Every generated file is new and private (0600).")
            result = operation(choice)
            print("Human review only; source owner, authorization and CI release gates unchanged.")
            print(f"Result: {'REVIEW_ONLY' if result == 2 else 'HOLD'}")
        except (KeyboardInterrupt, EOFError):
            print("\nOFFLINE_CONSOLE_CLOSED — NO AUTHORITY")
            return 2
        except (archive.Hold, OSError, ValueError, TypeError, UnicodeError, RecursionError, OverflowError, BadZipFile):
            print("ASSESSMENT_ARCHIVE_HOLD — invalid or inaccessible local input")


if __name__ == "__main__":
    raise SystemExit(main())
