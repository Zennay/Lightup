#!/usr/bin/env python3
"""Private offline timeline of selected original Launchpad proposals.

Reopens every full owner-private packet; manual round order is not trusted
chronology. No target is contacted and no original packet is modified.
"""
from __future__ import annotations

import argparse
from base64 import b64encode
from hashlib import sha256
from html import escape
import json
import os
from pathlib import Path
import sys

from build import Hold, _safe_write
from compare import _STYLE, _load

_MAX_ROUNDS = 8
_SCHEMA = "lightup.lab_launchpad_human_timeline.v1"
_FALSE = ("authorized", "consent_verified", "dispatch_allowed", "release_allowed")


def _within(child: str, parent: str) -> bool:
    child_abs = os.path.abspath(child)
    parent_abs = os.path.abspath(parent)
    try:
        return os.path.commonpath((child_abs, parent_abs)) == parent_abs
    except ValueError:
        return False


def _timeline_rows(source_dirs: list[str]) -> tuple[list[dict], dict]:
    if not 2 <= len(source_dirs) <= _MAX_ROUNDS:
        raise Hold("choose 2–8 existing owner-private original packets")
    for i, path in enumerate(source_dirs):
        for earlier in source_dirs[:i]:
            try:
                if os.path.samefile(path, earlier):
                    raise Hold("the same original packet cannot represent two separate rounds")
            except OSError as exc:
                raise Hold("selected original packet is inaccessible") from exc

    sources = [_load(path) for path in source_dirs]
    rounds = []
    previous = None
    for number, source in enumerate(sources, 1):
        endpoints = tuple(source["endpoints"])
        current_set = set(endpoints)
        if previous is None:
            added, absent, unchanged = [], [], []
            order_changed = False
            studio_differs = False
        else:
            previous_set = set(previous["endpoints"])
            added = [url for url in endpoints if url not in previous_set]
            absent = [url for url in previous["endpoints"] if url not in current_set]
            unchanged = [url for url in endpoints if url in previous_set]
            order_changed = endpoints != tuple(previous["endpoints"])
            studio_differs = (
                source["studio_catalog_sha256"], source["studio_scenario_id"]
            ) != (
                previous["studio_catalog_sha256"], previous["studio_scenario_id"]
            )
        rounds.append({
            "round": number,
            "manifest_sha256": source["manifest_sha256"],
            "source_count": len(endpoints),
            "studio_bound": source["studio"],
            "studio_catalog_sha256": source["studio_catalog_sha256"],
            "studio_scenario_id": source["studio_scenario_id"],
            "endpoints": list(endpoints),
            "added": added,
            "absent": absent,
            "unchanged": unchanged,
            "order_changed_vs_previous": order_changed,
            "studio_revision_differs_vs_previous": studio_differs,
        })
        previous = source

    # Re-open each whole original immediately before publication. The
    # unsigned hashes are change-detection only, not identity or permission.
    for directory, source in zip(source_dirs, sources):
        current = _load(directory)
        if (
            current["manifest_sha256"] != source["manifest_sha256"]
            or current["endpoints"] != source["endpoints"]
            or current["studio"] != source["studio"]
            or current["studio_catalog_sha256"] != source["studio_catalog_sha256"]
            or current["studio_scenario_id"] != source["studio_scenario_id"]
        ):
            raise Hold("a selected original packet changed during timeline preparation")

    doc = {
        "schema": _SCHEMA,
        "status": "DRAFT_HOLD",
        "manual_round_order_only": True,
        "chronology_authenticated": False,
        "source_identity_authenticated": False,
        "same_client_or_engagement_authenticated": False,
        "planning_not_permission": True,
        "verified_remediation": False,
        "round_count": len(rounds),
        "source_count_total": sum(row["source_count"] for row in rounds),
        "distinct_endpoint_count": len({url for row in rounds for url in row["endpoints"]}),
        "rounds": rounds,
        **{key: False for key in _FALSE},
    }
    aggregate_rounds = []
    for row in rounds:
        aggregate_rounds.append({
            "round": row["round"],
            "endpoint_count": row["source_count"],
            "baseline": row["round"] == 1,
            "added_count": len(row["added"]),
            "absent_count": len(row["absent"]),
            "unchanged_count": len(row["unchanged"]),
            "order_changed_vs_previous": row["order_changed_vs_previous"],
            "studio_revision_differs_vs_previous": row["studio_revision_differs_vs_previous"],
        })
    aggregate = {
        "schema": "lightup.lab_launchpad_timeline_counts.v1",
        "status": "DRAFT_HOLD",
        "manual_round_order_only": True,
        "chronology_authenticated": False,
        "source_identity_authenticated": False,
        "same_client_or_engagement_authenticated": False,
        "planning_not_permission": True,
        "verified_remediation": False,
        "round_count": len(rounds),
        "source_count_total": doc["source_count_total"],
        "distinct_endpoint_count": doc["distinct_endpoint_count"],
        "rounds": aggregate_rounds,
        **{key: False for key in _FALSE},
    }
    return rounds, {"private": doc, "aggregate": aggregate}


def _endpoint_table(label: str, urls: list[str], note: str) -> str:
    rows = "".join(
        "<tr><th scope='row'>#" + str(i) + "</th><td><code>" +
        escape(url, quote=True) + "</code></td></tr>"
        for i, url in enumerate(urls, 1)
    ) or "<tr><td colspan='2'>No proposed endpoints in this category.</td></tr>"
    return (
        "<section><h3>" + escape(label) + " · " + str(len(urls)) + "</h3><p>" +
        escape(note) + "</p><table><thead><tr><th>Local ordinal</th>" +
        "<th>Private proposed endpoint</th></tr></thead><tbody>" +
        rows + "</tbody></table></section>"
    )


def _html(doc: dict) -> bytes:
    pin = b64encode(sha256(_STYLE.encode("utf-8")).digest()).decode("ascii")
    header = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta name="referrer" content="no-referrer">'
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
        "style-src 'sha256-" + pin + "'; script-src 'none'; connect-src 'none'; "
        'img-src \'none\'; object-src \'none\'; frame-src \'none\'; base-uri \'none\'; form-action \'none\'>'
        "<title>LightUp / Private launch proposal timeline</title><style>" + _STYLE +
        "</style></head><body><header><p>LIGHTUP / OFFLINE LAB PREPARATION / PRIVATE HUMAN TIMELINE</p>"
        "<h1>What changed across selected launch proposals?</h1>"
        "<p>HUMAN REVIEW ONLY · INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NOT AUTHORIZED.</p>"
        "<p>Round order is manually selected, not verified chronology. This brief contains private endpoint URLs; "
        "share only through a separately approved private channel. Missing proposals are not proof of fixes, "
        "revocation, decommissioning or security clearance.</p></header>"
    )
    sections = []
    previous = None
    for row in doc["rounds"]:
        if previous is None:
            sections.append(
                "<section><h2>Selected baseline round " + str(row["round"]) + "</h2><p>" +
                str(row["source_count"]) + " original proposed endpoint(s). This is a human-selected baseline, "
                "not an authenticated first event.</p>" +
                _endpoint_table("Baseline proposal", row["endpoints"],
                                "Original proposal order is retained. Source hashes are unsigned.") +
                "</section>"
            )
        else:
            sections.append(
                "<section><h2>Selected round " + str(row["round"]) + "</h2><p>" +
                str(row["source_count"]) + " endpoint(s); order changed vs prior: " +
                ("YES" if row["order_changed_vs_previous"] else "NO") +
                "; Studio source/scenario declaration differs vs prior: " +
                ("YES" if row["studio_revision_differs_vs_previous"] else "NO") +
                ".</p>" +
                _endpoint_table("Complete selected proposal", row["endpoints"],
                                "Exact private endpoints from this selected packet.") +
                _endpoint_table("Added vs immediately previous selected round", row["added"],
                                "Newly proposed endpoints only; not permission or a verified scan.") +
                _endpoint_table("Absent vs immediately previous selected round", row["absent"],
                                "Absence does not prove remediation, revocation, decommissioning or clearance.") +
                _endpoint_table("Unchanged exact endpoint text vs previous round", row["unchanged"],
                                "Same text does not prove current scope, ownership, consent or safety.") +
                "</section>"
            )
        previous = row
    footer = (
        "<section><aside><h2>Original authority untouched</h2><p>All source, reviewer, client and operator "
        "identity/consent claims remain unverified. No original packet was modified; no target was contacted. "
        "Unsigned hashes provide local change detection only. Original hosted and permanent named VPS CI, "
        "source-owner and independent security/privacy review, issues #177/#182/#829, current separately "
        "authenticated consent with action-time revocation, and explicit HUMAN GO remain separate mandatory gates. "
        "This is not authorization, a security verdict or remediation evidence.</p></aside></section>"
        "</body></html>"
    )
    return (header + "".join(sections) + footer).encode("utf-8")


def timeline(source_dirs: list[str], output_dir: str) -> dict:
    rounds, summaries = _timeline_rows(source_dirs)
    output = Path(output_dir)
    if output.name in ("", ".", "..") or not output.parent.is_dir():
        raise Hold("invalid new private output directory")
    if any(_within(str(output), source_dir) for source_dir in source_dirs):
        raise Hold("timeline output cannot be placed inside an original source packet")
    os.mkdir(output, 0o700)
    fd = -1
    created = []
    try:
        fd = os.open(output, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                     getattr(os, "O_NOFOLLOW", 0))
        os.fchmod(fd, 0o700)
        csv_lines = [
            "round,endpoint_count,baseline,added_count,absent_count,unchanged_count,"
            "order_changed_vs_previous,studio_revision_differs_vs_previous,"
            "chronology_authenticated,source_authenticated,consent_verified,dispatch_allowed,release_allowed"
        ]
        for row in summaries["aggregate"]["rounds"]:
            csv_lines.append(",".join((
                str(row["round"]), str(row["endpoint_count"]), str(row["baseline"]).lower(),
                str(row["added_count"]), str(row["absent_count"]), str(row["unchanged_count"]),
                str(row["order_changed_vs_previous"]).lower(),
                str(row["studio_revision_differs_vs_previous"]).lower(),
                "false", "false", "false", "false", "false",
            )))
        csv_data = ("\n".join(csv_lines) + "\n").encode("ascii")
        items = (
            ("private-timeline.html", _html(summaries["private"])),
            ("private-source-timeline.json",
             (json.dumps(summaries["private"], sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")),
            ("anonymous-counts.json",
             (json.dumps(summaries["aggregate"], sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")),
            ("anonymous-counts.csv", csv_data),
            ("START-HERE.txt", (
                "LIGHTUP / PRIVATE LAB PROPOSAL TIMELINE / HUMAN HOLD\n"
                "Open private-timeline.html locally. Keep this whole directory owner-private.\n"
                "Round order is manually selected, not authenticated chronology or same-client identity.\n"
                "A missing proposal is NOT approved revocation, remediation, or vulnerability clearance.\n"
                "All files are unsigned. No target, model, network, scanner or original packet was changed.\n"
                "Original permissions, source-owner/security/privacy review, CI and HUMAN GO remain required.\n"
            ).encode("utf-8")),
        )
        for name, data in items:
            _safe_write(fd, name, data)
            created.append(name)
        os.fsync(fd)
    except BaseException:
        if fd >= 0:
            for name in reversed(created):
                try:
                    os.unlink(name, dir_fd=fd)
                except OSError:
                    pass
        try:
            os.rmdir(output)
        except OSError:
            pass
        raise
    finally:
        if fd >= 0:
            os.close(fd)
    return summaries["aggregate"]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Privately compare 2–8 original launch packets in manually selected order; never execute."
    )
    parser.add_argument("--packet", action="append", required=True,
                        help="existing owner-private original packet directory; repeat 2–8 times")
    parser.add_argument("--output-dir", required=True,
                        help="new owner-private timeline directory outside all source packets")
    args = parser.parse_args(argv)
    try:
        summary = timeline(args.packet, args.output_dir)
        print("PRIVATE_LAB_PROPOSAL_TIMELINE_CREATED — HUMAN HOLD ONLY; " +
              "rounds=" + str(summary["round_count"]) +
              " endpoint_occurrences=" + str(summary["source_count_total"]) +
              " distinct_endpoints=" + str(summary["distinct_endpoint_count"]) +
              "; NO AUTHORITY")
        return 2
    except (Hold, OSError, ValueError, KeyError, TypeError, UnicodeError,
            OverflowError, RecursionError):
        print("PRIVATE_LAB_PROPOSAL_TIMELINE_HOLD — source, membership or destination refused",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
