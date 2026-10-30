"""Run two isolated fixed-loopback calibrations and verify their saved evidence.

This command is local synthetic scoring, not assessment authorization or a
network target selector. Original evidence remains private on disk.
"""
from __future__ import annotations

import argparse
import csv
from io import StringIO
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

from .lab_score_compare import (
    _SCORE_FIELDS, _compare_inspected_score_runs, compare_score_runs,
    render_score_review,
)
from .lab_score_inspect import inspect_score_run
from .lab_score_history_html import render_history_html, build_history_review_summary, render_history_markdown, focus_archive_review
from .lab_score_review_store import (save_private_review, verify_private_review,
                                     summary_bytes)
from .lab_score_handoff import save_portable_review
from .lab_score_portable_unpack import unpack_portable_review, verify_unpacked_portable_review
from .lab_score_handoff_verify import verify_portable_review
from .lab_score_suite import _EXPECTED_FINDINGS
from .lab_score_inspect import _private_dir_fd, _artifact_fd
from .lab_score_suite import _private_output_directory, _write_report, run_lab_score_suite

SCHEMA = "lightup.lab-score-calibration.v1"
HISTORY_SCHEMA = "lightup.lab-score-calibration-history.v1"

class _HistoryArchiveError(ValueError):
    """Index-only failure for a locally archived original source."""

    def __init__(self, archive_index: int):
        self.archive_index = archive_index
        super().__init__("original saved archive not verified")



def _receipt(comparison: dict[str, Any],
             source_sha256: dict[str, dict[str, str]] | None = None) -> dict[str, Any]:
    """Public-safe result, never an attestation or authorization."""
    report = {
        "schema": SCHEMA,
        "passed": comparison["passed"],
        "saved_runs": ["baseline", "candidate"],
        "comparison": comparison,
        "authorization_granted": False,
        "external_targets_contacted": False,
        "deployment": False,
    }
    if source_sha256 is not None:
        report["source_sha256"] = source_sha256
    return report


_SOURCE_FILES = ("report.json", "service_inventory.sqlite3",
                 "tls_baseline.sqlite3", "http_baseline.sqlite3")


def _source_hashes(root: Path) -> dict[str, dict[str, str]]:
    """Bind the receipt to exact private files without exposing their bytes."""
    digests: dict[str, dict[str, str]] = {}
    for name in ("baseline", "candidate"):
        directory_fd = _private_dir_fd(root / name)
        try:
            digests[name] = {}
            for filename in _SOURCE_FILES:
                size_limit = 1024 * 1024 if filename == "report.json" else 64 * 1024 * 1024
                source_fd = _artifact_fd(directory_fd, filename, size_limit)
                try:
                    before = os.fstat(source_fd)
                    checksum = hashlib.sha256()
                    while chunk := os.read(source_fd, 65536):
                        checksum.update(chunk)
                    after = os.fstat(source_fd)
                    if (before.st_dev, before.st_ino, before.st_size,
                        before.st_mtime_ns, before.st_ctime_ns) != (
                        after.st_dev, after.st_ino, after.st_size,
                        after.st_mtime_ns, after.st_ctime_ns):
                        raise ValueError("source changed during digest")
                    digests[name][filename] = checksum.hexdigest()
                finally:
                    os.close(source_fd)
        finally:
            os.close(directory_fd)
    return digests


def _receipt_bytes(result: dict[str, Any]) -> bytes:
    return (json.dumps(result, indent=2, sort_keys=True, allow_nan=False)
            + "\n").encode("utf-8")


def verify_saved_calibration(output_dir: str | Path) -> dict[str, Any]:
    """Reopen both private saved runs without executing any fixture/worker."""
    root = Path(output_dir).expanduser()
    if ".." in root.parts:
        raise ValueError("parent traversal rejected")
    # Freeze relative path resolution before the first descriptor is opened.
    # A concurrent cwd change must not redirect the later comparison/digests.
    root = Path(os.path.abspath(root))
    fd = _private_dir_fd(root)  # pinned, owner-private, no-follow ancestors
    try:
        original = os.fstat(fd)
        if set(os.listdir(fd)) != {"baseline", "candidate", "report.json"}:
            raise ValueError("unexpected saved calibration entries")
        receipt_fd = _artifact_fd(fd, "report.json", 65536)
        try:
            receipt_before = os.fstat(receipt_fd)
            receipt_raw = os.pread(receipt_fd, 65537, 0)
        finally:
            os.close(receipt_fd)
        children = {}
        for name in ("baseline", "candidate"):
            entry = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if (not stat.S_ISDIR(entry.st_mode) or entry.st_uid != os.geteuid()
                    or stat.S_IMODE(entry.st_mode) & 0o077):
                raise PermissionError("unsafe saved calibration subdirectory")
            children[name] = (entry.st_dev, entry.st_ino, entry.st_mtime_ns,
                              entry.st_ctime_ns)
        comparison = compare_score_runs(root / "baseline", root / "candidate")
        result = _receipt(comparison)
        bound_receipt = _receipt(comparison, _source_hashes(root))
        if receipt_raw != _receipt_bytes(bound_receipt):
            raise ValueError("calibration receipt differs from saved evidence")
        receipt_fd = _artifact_fd(fd, "report.json", 65536)
        try:
            receipt_after = os.fstat(receipt_fd)
            if ((receipt_before.st_ino, receipt_before.st_dev,
                 receipt_before.st_mtime_ns, receipt_before.st_ctime_ns,
                 receipt_before.st_size) !=
                (receipt_after.st_ino, receipt_after.st_dev,
                 receipt_after.st_mtime_ns, receipt_after.st_ctime_ns,
                 receipt_after.st_size)
                    or os.pread(receipt_fd, 65537, 0) != receipt_raw):
                raise ValueError("calibration receipt changed during inspection")
        finally:
            os.close(receipt_fd)
        after = os.fstat(fd)
        if ((original.st_dev, original.st_ino, original.st_mtime_ns,
             original.st_ctime_ns) !=
            (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns)
                or set(os.listdir(fd)) != {"baseline", "candidate", "report.json"}):
            raise ValueError("saved calibration changed")
        for name in children:
            entry = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if children[name] != (entry.st_dev, entry.st_ino, entry.st_mtime_ns,
                                  entry.st_ctime_ns):
                raise ValueError("saved calibration subdirectory changed")
    finally:
        os.close(fd)
    return result


def run_lab_score_calibration(output_dir: str | Path) -> dict[str, Any]:
    """Create two *new* private stores and independently re-inspect both."""
    root = _private_output_directory(output_dir)
    # Each producer creates its own exclusive 0700 directory and 0600 stores.
    # Never proceed to the candidate after a failed baseline; and never emit
    # PASS from producer summaries without independently verifying both saves.
    for name in ("baseline", "candidate"):
        saved = run_lab_score_suite(root / name)
        if saved.get("passed") is not True:
            raise ValueError("synthetic calibration failed")
    comparison = compare_score_runs(root / "baseline", root / "candidate")
    receipt = _receipt(comparison)
    if receipt["passed"] is not True:
        raise ValueError("synthetic calibration drift or reused evaluation")
    # Atomic, owner-only and no-overwrite; partial failed runs have no receipt.
    _write_report(root, _receipt(comparison, _source_hashes(root)))
    return verify_saved_calibration(root)


def _archived_root_identity(root: Path) -> tuple[int | str, ...]:
    """Pin a saved root and its private receipt across offline comparisons."""
    root_fd = _private_dir_fd(root)
    try:
        root_info = os.fstat(root_fd)
        receipt_fd = _artifact_fd(root_fd, "report.json", 65536)
        try:
            info = os.fstat(receipt_fd)
            raw = os.pread(receipt_fd, 65537, 0)
            after = os.fstat(receipt_fd)
            # Reading an archived receipt may legitimately advance atime.
            # Compare only immutable identity/content metadata.
            if ((info.st_dev, info.st_ino, info.st_size,
                 info.st_mtime_ns, info.st_ctime_ns, info.st_mode,
                 info.st_uid) !=
                (after.st_dev, after.st_ino, after.st_size,
                 after.st_mtime_ns, after.st_ctime_ns, after.st_mode,
                 after.st_uid)):
                raise ValueError("saved archive receipt changed")
        finally:
            os.close(receipt_fd)
        return (root_info.st_dev, root_info.st_ino,
                root_info.st_mtime_ns, root_info.st_ctime_ns,
                info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns,
                info.st_size, hashlib.sha256(raw).hexdigest())
    finally:
        os.close(root_fd)


def _compare_verified_archive_pair(
    previous: Path, current: Path,
    old_hashes: dict[str, dict[str, str]],
    current_hashes: dict[str, dict[str, str]],
    previous_score: dict[str, Any] | None = None,
    current_score: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compare candidates using already checked original source snapshots.

    The caller MUST reverify original private sources and receipts after the
    full comparison. This function grants neither provenance nor authority.
    """
    if previous_score is not None and current_score is not None:
        # History calls reuse one already inspected candidate per archive.
        # As with the original comparator, the archives must be distinct.
        if os.path.samefile(previous / "candidate", current / "candidate"):
            raise ValueError("same archived candidate")
        comparison = _compare_inspected_score_runs(previous_score, current_score)
    else:
        comparison = compare_score_runs(
            previous / "candidate", current / "candidate",
        )
    # Verifying two root receipts does not guarantee the archives are
    # independent: one can reuse the other's *baseline* while selecting a
    # new candidate. Reject repeated original evidence anywhere across all
    # four runs, without exposing the private source SHA-256 digests.
    previous_sources = {
        digest for run in old_hashes.values() for digest in run.values()
    }
    current_sources = {
        digest for run in current_hashes.values() for digest in run.values()
    }
    if previous_sources & current_sources:
        comparison["passed"] = False
        comparison["independent_evaluations"] = False
        comparison["reused_archived_source"] = True
        for filename in _SOURCE_FILES[1:]:
            old_digests = {old_hashes[run][filename] for run in old_hashes}
            new_digests = {current_hashes[run][filename] for run in current_hashes}
            if old_digests & new_digests:
                name = filename.removesuffix(".sqlite3")
                comparison["capabilities"][name]["distinct_evaluation"] = False
    return _receipt(comparison)



def compare_saved_calibrations(
    previous_dir: str | Path, current_dir: str | Path,
) -> dict[str, Any]:
    """Compare two archived calibrations after verifying *both* root receipts.

    A standalone score comparison is not enough: the saved source-file hashes
    of each archived calibration must independently match its private receipt.
    """
    paths = (Path(previous_dir).expanduser(), Path(current_dir).expanduser())
    if any(".." in path.parts for path in paths):
        raise ValueError("parent traversal rejected")
    anchor = Path.cwd()
    previous, current = (
        path if path.is_absolute() else anchor / path for path in paths
    )
    identities = (_archived_root_identity(previous),
                  _archived_root_identity(current))
    old = verify_saved_calibration(previous)
    latest = verify_saved_calibration(current)
    if old["passed"] is not True or latest["passed"] is not True:
        raise ValueError("archived calibration refused")
    # Snapshot all eight original private source bindings *before* calculating
    # the cross-archive score. Root/receipt identity alone cannot detect a
    # modified artifact within an unchanged child directory.
    old_hashes = _source_hashes(previous)
    current_hashes = _source_hashes(current)
    result = _compare_verified_archive_pair(
        previous, current, old_hashes, current_hashes
    )
    if identities != (_archived_root_identity(previous),
                      _archived_root_identity(current)):
        raise ValueError("saved archive substituted during comparison")
    # Verify post-comparison bytes and their original receipts, not only the
    # root metadata. An archived source can change after its first successful
    # validation without modifying the calibration root or receipt inode.
    if (old_hashes != _source_hashes(previous)
            or current_hashes != _source_hashes(current)):
        raise ValueError("saved archive evidence changed during comparison")
    if (verify_saved_calibration(previous)["passed"] is not True
            or verify_saved_calibration(current)["passed"] is not True):
        raise ValueError("saved archive failed post-comparison verification")
    result["saved_runs"] = ["previous", "current"]
    result["comparison_mode"] = "archived_calibrations"
    return result



def compare_saved_calibration_history(
    directories: list[str | Path],
) -> dict[str, Any]:
    """Compare 2–8 original private archives, rejecting even non-adjacent replay.

    Comparing only consecutive calibrations lets archive 3 reuse archive 1's
    evidence while both adjacent comparisons appear independent. Verify every
    pair and recheck all source bindings after the entire history review.
    """
    if not 2 <= len(directories) <= 8:
        raise ValueError("history requires 2 to 8 saved calibrations")
    anchor = Path.cwd()
    roots = []
    for raw in directories:
        path = Path(raw).expanduser()
        if ".." in path.parts:
            raise ValueError("parent traversal rejected")
        roots.append(path if path.is_absolute() else anchor / path)
    identities, source_bindings, inspected_candidates = [], [], []
    # Admit each original root once, without exposing input paths or artifacts.
    for index, root in enumerate(roots, 1):
        try:
            identities.append(_archived_root_identity(root))
            if verify_saved_calibration(root)["passed"] is not True:
                raise ValueError("archived source refused")
            source_bindings.append(_source_hashes(root))
            inspected_candidates.append(
                inspect_score_run(root / "candidate", include_metrics=True)
            )
        except Exception:
            raise _HistoryArchiveError(index) from None
    adjacent = []
    pairs = []
    pairwise_holds = []
    independent, stable, all_passed = True, True, True
    compared = 0
    for i in range(len(roots)):
        for j in range(i + 1, len(roots)):
            # Only compare verified candidate records and the cached
            # original digests. The final whole-history recheck below
            # invalidates every result if any source changed mid-comparison.
            pair = _compare_verified_archive_pair(
                roots[i], roots[j], source_bindings[i], source_bindings[j],
                inspected_candidates[i], inspected_candidates[j]
            )
            summary = pair["comparison"]
            compared += 1
            independent &= summary["independent_evaluations"] is True
            stable &= summary["score_stable"] is True
            all_passed &= pair["passed"] is True
            # Bounded, source-free all-pairs status for machine-readable
            # history exports, including passing non-adjacent combinations.
            pairs.append({
                "previous_index": i + 1,
                "current_index": j + 1,
                "passed": pair["passed"],
                "independent_evaluations": summary["independent_evaluations"],
                "score_stable": summary["score_stable"],
            })
            if pair["passed"] is not True:
                # Only canonical first-party capability and metric names from
                # the existing verified comparator; never copy arbitrary keys.
                changes = [
                    {"capability": name, "metric": field,
                     "previous": summary["capabilities"][name]["changed_metrics"][field]["baseline"],
                     "current": summary["capabilities"][name]["changed_metrics"][field]["candidate"]}
                    for name in _EXPECTED_FINDINGS for field in _SCORE_FIELDS
                    if field in summary["capabilities"][name]["changed_metrics"]
                ]
                pairwise_holds.append({
                    "previous_index": i + 1,
                    "current_index": j + 1,
                    "independent_evaluations": summary["independent_evaluations"],
                    "score_stable": summary["score_stable"],
                    "metric_deltas": changes,
                })
            if j == i + 1:
                adjacent.append({
                    "previous_index": i + 1,
                    "current_index": j + 1,
                    "passed": pair["passed"],
                    "independent_evaluations": summary["independent_evaluations"],
                    "score_stable": summary["score_stable"],
                })
    # Every admitted root is independently reverified at completion;
    # a known 1-based index makes HOLD actionable without revealing a path.
    for index, root in enumerate(roots, 1):
        try:
            if (identities[index - 1] != _archived_root_identity(root)
                    or source_bindings[index - 1] != _source_hashes(root)
                    or verify_saved_calibration(root)["passed"] is not True):
                raise ValueError("archived source changed")
        except Exception:
            raise _HistoryArchiveError(index) from None
    return {
        "schema": HISTORY_SCHEMA,
        "passed": bool(all_passed and independent and stable),
        "archives_checked": len(roots),
        "pairs_checked": compared,
        "independent_evaluations": bool(independent),
        "score_stable": bool(stable),
        "adjacent": adjacent,
        "pairs": pairs,
        "pairwise_holds": pairwise_holds,
        "authorization_granted": False,
        "external_targets_contacted": False,
        "deployment": False,
    }


def _private_source_binding(roots: list[Path], html: str,
                            summary: dict[str, Any]) -> dict[str, Any]:
    """Bind a private review to exact *original* receipt contents.

    Archive source hashes are never emitted to HTML or standard output.
    This is local evidence consistency, not independent authentication.
    """
    fingerprints = []
    for index, root in enumerate(roots, 1):
        try:
            before = _archived_root_identity(root)
            if verify_saved_calibration(root)["passed"] is not True:
                raise ValueError("original source verification refused")
            if before != _archived_root_identity(root):
                raise ValueError("source changed during private binding")
            fingerprints.append(before[-1])
        except Exception:
            raise _HistoryArchiveError(index) from None
    return {
        "schema": "lightup.private-html-source-binding.v1",
        "original_receipt_sha256": fingerprints,
        "html_sha256": hashlib.sha256(html.encode("utf-8")).hexdigest(),
        "summary_sha256": hashlib.sha256(summary_bytes(summary)).hexdigest(),
        "authorization_granted": False,
        "external_targets_contacted": False,
        "deployment": False,
    }


def _refuse_review_source_overlap(roots: list[Path],
                                  report_dir: str | Path) -> None:
    """Keep report output and all original archived evidence disjoint.

    Private parent components are no-follow elsewhere. Reject lexical
    overlap before creating a destination: publishing a report inside an
    original archive changes the very evidence we just verified.
    """
    candidate = Path(report_dir).expanduser()
    if ".." in candidate.parts:
        raise ValueError("parent traversal rejected")
    candidate = Path(os.path.abspath(candidate))
    for original in roots:
        if (candidate == original or original in candidate.parents
                or candidate in original.parents):
            raise ValueError("review directory overlaps original evidence")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="lightup-lab-score-calibrate",
        description="Create and verify two fresh private fixed-loopback score runs.",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output-dir",
                      help="new private directory (never overwrites existing files)")
    mode.add_argument("--verify-output-dir",
                      help="read-only reinspection of a saved calibration; no scorers")
    mode.add_argument("--compare-calibrations", nargs=2,
                      metavar=("PREVIOUS", "CURRENT"),
                      help="compare two fully verified private saved calibrations offline")
    mode.add_argument("--verify-unpacked-review", help="read-only review of seven extracted files")
    mode.add_argument("--unpack-portable-review",
                      help="verify and open a synthetic portable HUMAN ZIP in a new private offline directory")
    mode.add_argument("--verify-portable-review",
                      help="read-only transport integrity check of a portable HUMAN ZIP; "
                           "does not authenticate original evidence")
    mode.add_argument("--compare-history", nargs="+", metavar="ARCHIVE",
                      help="compare 2 to 8 private archived calibrations offline")
    parser.add_argument("--format", choices=("json", "text", "csv", "html", "review-json", "review-markdown", "review-csv"),
                        default="text")
    parser.add_argument("--focus-archive-index", type=int, metavar="N",
                        help="show original archive N in source-free review exports")
    parser.add_argument("--html-output-dir",
                        help="new exclusive 0700 directory for private 0600 history.html")
    parser.add_argument("--verify-html-output-dir",
                        help="reverify existing private HTML, receipt and JSON against originals; "
                             "allows source-free review-json, review-markdown and review-csv output")
    parser.add_argument("--portable-review-output-dir",
                        help="create an owner-private, source-free offline HUMAN review ZIP "
                             "after verifying the existing private three-file review")
    parser.add_argument("--unpacked-review-dir", help="existing private review files")
    parser.add_argument("--unpack-output-dir",
                        help="new 0700 private directory for verified source-free review files")
    args = parser.parse_args(argv)
    if args.verify_unpacked_review is not None:
        if (args.unpacked_review_dir is None or args.unpack_output_dir is not None
                or args.format != "text" or args.focus_archive_index is not None
                or args.html_output_dir is not None
                or args.verify_html_output_dir is not None
                or args.portable_review_output_dir is not None):
            parser.error("review reinspection requires --unpacked-review-dir only")
        try:
            result = verify_unpacked_portable_review(args.verify_unpacked_review,
                                                     args.unpacked_review_dir)
        except Exception:
            print("LightUp portable HUMAN review: HOLD; offline files not verified.", file=sys.stderr)
            return 2
        print("LightUp portable HUMAN review: OFFLINE FILES VERIFIED; source NOT authenticated; status " + result["review_status"] + ".")
        return 0 if result["review_status"] == "PASS" else 2
    if args.unpacked_review_dir is not None:
        parser.error("--unpacked-review-dir requires --verify-unpacked-review")
    if args.unpack_portable_review is not None:
        if (args.unpack_output_dir is None or args.format != "text"
                or args.focus_archive_index is not None or args.html_output_dir is not None
                or args.verify_html_output_dir is not None
                or args.portable_review_output_dir is not None):
            parser.error("unpack requires --unpack-output-dir and no other review options")
        try:
            result = unpack_portable_review(args.unpack_portable_review,
                                            args.unpack_output_dir)
        except Exception:
            print("LightUp portable HUMAN review: HOLD; offline files not published.",
                  file=sys.stderr)
            return 2
        print("LightUp portable HUMAN review: OFFLINE FILES READY; "
              "source NOT authenticated; status " + result["review_status"] + ".")
        return 0 if result["review_status"] == "PASS" else 2
    if args.unpack_output_dir is not None:
        parser.error("--unpack-output-dir requires --unpack-portable-review")
    if args.verify_portable_review is not None:
        if (args.format != "text" or args.focus_archive_index is not None
                or args.html_output_dir is not None
                or args.verify_html_output_dir is not None
                or args.portable_review_output_dir is not None):
            parser.error("portable review verification is standalone and read-only")
        try:
            verified = verify_portable_review(args.verify_portable_review)
        except Exception:
            print("LightUp portable HUMAN review: HOLD; transport not verified.",
                  file=sys.stderr)
            return 2
        print("LightUp portable HUMAN review: TRANSPORT VERIFIED; "
              + ("dashboard matched anonymous review; " if verified["dashboard_content_validated"]
                 else "LEGACY dashboard contents NOT independently validated; ")
              + "original source NOT authenticated; status "
              + verified["review_status"] + ".")
        return 0 if verified["review_status"] == "PASS" else 2
    if args.focus_archive_index is not None and (
            args.compare_history is None or args.format not in
            ("review-json", "review-markdown", "review-csv", "html")):
        parser.error("focus requires --compare-history and review-json, "
                     "review-markdown, review-csv or html")
    if args.portable_review_output_dir is not None and (
            args.verify_html_output_dir is None or args.format != "html"
            or args.compare_history is None or args.focus_archive_index is not None):
        parser.error("portable ZIP requires --compare-history, --format html, "
                     "--verify-html-output-dir and no focus")
    if args.html_output_dir is not None and args.verify_html_output_dir is not None:
        parser.error("create and verify must be separate operations")
    if args.html_output_dir is not None and args.focus_archive_index is not None:
        parser.error("focused HTML cannot replace the canonical saved original report")
    if args.html_output_dir is not None and (
            args.format != "html" or args.compare_history is None):
        parser.error("saving a private review requires --compare-history and --format html")
    if args.verify_html_output_dir is not None and (
            args.format not in ("html", "review-json", "review-markdown", "review-csv")
            or args.compare_history is None):
        parser.error("verifying a private review requires --compare-history and "
                     "--format html, review-json, review-markdown or review-csv")
    if args.format in ("csv", "html", "review-json", "review-markdown", "review-csv") and args.compare_history is None:
        parser.error("CSV/HTML/review export applies only to --compare-history")
    try:
        if args.compare_history is not None:
            anchor = Path.cwd()
            roots = []
            for raw in args.compare_history:
                path = Path(raw).expanduser()
                if ".." in path.parts:
                    raise ValueError("parent traversal rejected")
                roots.append(path if path.is_absolute() else anchor / path)
            result = compare_saved_calibration_history(roots)
            if (args.focus_archive_index is not None and not
                    1 <= args.focus_archive_index <= result["archives_checked"]):
                raise ValueError("invalid archive focus")

        elif args.compare_calibrations is not None:
            result = compare_saved_calibrations(*args.compare_calibrations)
        elif args.verify_output_dir is not None:
            result = verify_saved_calibration(args.verify_output_dir)
        else:
            result = run_lab_score_calibration(args.output_dir)
    except Exception as exc:
        # Only the 1-based CLI argument position of a refused private archive
        # may be disclosed. Never echo filesystem paths or raw exceptions.
        index = (exc.archive_index if args.compare_history is not None
                 and isinstance(exc, _HistoryArchiveError) else None)
        if args.format in ("text", "csv", "html", "review-markdown", "review-csv"):
            if index is None:
                message = "LightUp synthetic calibration: HOLD; saved evidence not verified."
            else:
                message = f"LightUp synthetic calibration: HOLD; archive {index} not verified."
            print(message, file=sys.stderr)
        else:
            schema = HISTORY_SCHEMA if args.compare_history is not None else SCHEMA
            rejected = {"schema": schema, "passed": False}
            if index is not None:
                rejected["archive_index"] = index
            print(json.dumps(rejected, sort_keys=True), file=sys.stderr)
        return 2
    # Machine/human exports from a *saved* report must verify the entire
    # original private HTML + JSON + receipt transaction first. Merely
    # re-running a score comparison must never certify a tampered old bundle.
    # Do not emit even an opening line on stdout until all checks succeed.
    if args.verify_html_output_dir is not None and args.format in (
            "review-json", "review-markdown", "review-csv"):
        try:
            html = render_history_html(result)
            summary = build_history_review_summary(result)
            review_dir = Path(args.verify_html_output_dir).expanduser()
            if not review_dir.is_absolute():
                review_dir = anchor / review_dir
            _refuse_review_source_overlap(roots, review_dir)
            binding = _private_source_binding(roots, html, summary)
            verify_private_review(
                review_dir, html, binding, summary,
                lambda: _private_source_binding(roots, html, summary),
            )
        except Exception:
            if args.format == "review-json":
                print(json.dumps({"schema": "lightup.lab-score-private-review-summary.v1",
                                  "passed": False}), file=sys.stderr)
            else:
                print("LightUp synthetic calibration: HOLD; saved review not verified.",
                      file=sys.stderr)
            return 2
    if args.format == "review-csv":
        try:
            summary = build_history_review_summary(result)
            output = StringIO()
            writer = csv.writer(output, lineterminator="\n")
            writer.writerow(("previous_index", "current_index", "status",
                             "independent_evaluations", "score_stable"))
            focus = (focus_archive_review(summary, args.focus_archive_index)
                     if args.focus_archive_index is not None else None)
            if focus is not None:
                # Selected PASSes never conceal an unrelated global HOLD.
                output = StringIO()
                writer = csv.writer(output, lineterminator="\n")
                writer.writerow(("previous_index", "current_index", "status",
                                 "independent_evaluations", "score_stable",
                                 "focus_archive_index", "global_status", "global_hold_pairs"))
            for pair in (focus["pairs"] if focus is not None else summary["pairs"]):
                writer.writerow((
                    pair["previous_index"], pair["current_index"],
                    "PASS" if pair["passed"] else "HOLD",
                    pair["independent_evaluations"], pair["score_stable"],
                    *((focus["archive_index"],
                       "PASS" if focus["global_passed"] else "HOLD",
                       focus["global_hold_pairs"]) if focus is not None else ()),
                ))
            print(output.getvalue(), end="")
        except Exception:
            print("LightUp synthetic calibration: HOLD; review CSV not verified.",
                  file=sys.stderr)
            return 2
    elif args.format == "review-markdown":
        try:
            brief = render_history_markdown(result, args.focus_archive_index)
            print(brief, end="")
        except Exception:
            print("LightUp synthetic calibration: HOLD; review brief not verified.",
                  file=sys.stderr)
            return 2
    elif args.format == "review-json":
        try:
            summary = build_history_review_summary(result)
            if args.focus_archive_index is not None:
                summary["review_focus"] = focus_archive_review(summary, args.focus_archive_index)
            print(json.dumps(summary, indent=2, sort_keys=True, allow_nan=False))
        except Exception:
            print(json.dumps({"schema": "lightup.lab-score-private-review-summary.v1",
                              "passed": False}), file=sys.stderr)
            return 2
    elif args.format == "html":
        try:
            html = render_history_html(result)
            summary = build_history_review_summary(result)
            focused_html = (render_history_html(result, args.focus_archive_index)
                            if args.focus_archive_index is not None else html)
            # Anchor private review paths to the same cwd as source archives.
            raw_review = args.html_output_dir or args.verify_html_output_dir
            review_dir = Path(raw_review).expanduser() if raw_review else None
            if review_dir is not None and not review_dir.is_absolute():
                review_dir = anchor / review_dir
            if args.html_output_dir is not None:
                _refuse_review_source_overlap(roots, review_dir)
                source_binding = _private_source_binding(roots, html, summary)
                save_private_review(
                    review_dir, html, source_binding, summary,
                    lambda: _private_source_binding(roots, html, summary),
                )
            elif args.verify_html_output_dir is not None:
                _refuse_review_source_overlap(roots, review_dir)
                source_binding = _private_source_binding(roots, html, summary)
                verify_private_review(
                    review_dir, html, source_binding, summary,
                    lambda: _private_source_binding(roots, html, summary),
                )
                if args.portable_review_output_dir is not None:
                    kit_dir = Path(args.portable_review_output_dir).expanduser()
                    if not kit_dir.is_absolute():
                        kit_dir = anchor / kit_dir
                    _refuse_review_source_overlap([*roots, review_dir], kit_dir)
                    def reverify():
                        current = _private_source_binding(roots, html, summary)
                        verify_private_review(
                            review_dir, html, current, summary,
                            lambda: _private_source_binding(roots, html, summary),
                        )
                    save_portable_review(kit_dir, result, reverify)
                if args.focus_archive_index is None:
                    print("LightUp saved synthetic HTML: VERIFIED; original comparison "
                          + ("PASS" if result["passed"] else "HOLD"))
                else:
                    print(focused_html, end="")
            else:
                print(focused_html, end="")
        except Exception:
            reason = ("HTML review not verified." if args.verify_html_output_dir
                      is not None else "HTML review not saved.")
            print(f"LightUp synthetic calibration: HOLD; {reason}",
                  file=sys.stderr)
            return 2
    elif args.format == "csv":
        writer = csv.writer(sys.stdout, lineterminator="\n")
        writer.writerow(("previous_index", "current_index", "passed",
                         "independent_evaluations", "score_stable",
                         "capability", "metric", "previous_value", "current_value"))
        holds = {
            (item["previous_index"], item["current_index"]): item["metric_deltas"]
            for item in result["pairwise_holds"]
        }
        for item in result["pairs"]:
            prefix = (item["previous_index"], item["current_index"],
                      item["passed"], item["independent_evaluations"],
                      item["score_stable"])
            deltas = holds.get(prefix[:2]) or []
            if deltas:
                for delta in deltas:
                    writer.writerow((*prefix, delta["capability"], delta["metric"],
                                     delta["previous"], delta["current"]))
            else:
                writer.writerow((*prefix, "", "", "", ""))
    elif args.format == "text":
        if args.compare_history is not None:
            print("LightUp synthetic calibration history:",
                  "PASS" if result["passed"] else "HOLD")
            print(f"Archives: {result['archives_checked']}; pairwise checks: {result['pairs_checked']}")
            print("Independent:", result["independent_evaluations"])
            for item in result["adjacent"]:
                state = "PASS" if item["passed"] else "HOLD"
                print(f"Archive {item['previous_index']} -> {item['current_index']}: {state}")
            for item in result["pairwise_holds"]:
                reasons = []
                if not item["independent_evaluations"]:
                    reasons.append("reused original evidence")
                if not item["score_stable"]:
                    reasons.append("score drift")
                reason = ", ".join(reasons) or "verification HOLD"
                print(f"Archive {item['previous_index']} -> {item['current_index']}: HOLD ({reason})")
                for delta in item["metric_deltas"]:
                    print(f"  {delta['capability']}.{delta['metric']}: {delta['previous']} -> {delta['current']}")
            print("Authority: none; localhost fixtures only; no external assessment.")
        else:
            labels = ("previous and current"
                      if args.compare_calibrations is not None
                      else "baseline and candidate")
            print(f"LightUp saved synthetic calibrations: {labels}")
            print(render_score_review(result["comparison"]))
    else:
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
