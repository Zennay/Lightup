"""Compose 1–64 explicit completed original case files per side into existing
LightUp canonical cohort files. Strictly offline; never assessment execution.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path

from archive import Hold, read_regular
from lightup_review import bundle as original_bundle


ORIGINAL_SINGLE_CASE_LIMIT = 65_536
MAX_CASES = 64


def _snapshots(paths: list[str]):
    if not 1 <= len(paths) <= MAX_CASES:
        raise Hold("original cohort requires 1–64 explicit source cases")
    resolved = [Path(value).absolute() for value in paths]
    if len(set(resolved)) != len(resolved):
        raise Hold("repeated original case file")
    return resolved, [
        sha256(read_regular(str(path), ORIGINAL_SINGLE_CASE_LIMIT)).digest()
        for path in resolved
    ]


def bundle_case_sides(*, baseline: list[str], candidate: list[str],
                      stage: Path) -> tuple[Path, Path, list[Path], list[bytes]]:
    """Run the *original unchanged* cohort bundler on each source set."""
    baseline_paths, baseline_digests = _snapshots(baseline)
    candidate_paths, candidate_digests = _snapshots(candidate)
    if set(baseline_paths) & set(candidate_paths):
        raise Hold("case file cannot be on both sides")
    all_paths = baseline_paths + candidate_paths
    source_hashes = baseline_digests + candidate_digests
    before = stage / "source-baseline-cohort.json"
    after = stage / "source-candidate-cohort.json"
    if (original_bundle([*(str(x) for x in baseline_paths), "--output", str(before)]) != 2
            or original_bundle([*(str(x) for x in candidate_paths), "--output", str(after)]) != 2
            or not before.is_file() or not after.is_file()):
        raise Hold("original case bundler returned HOLD")
    confirm_case_sources(all_paths, source_hashes)
    return before, after, all_paths, source_hashes


def confirm_case_sources(paths: list[Path], hashes: list[bytes]) -> None:
    if len(paths) != len(hashes) or any(
            sha256(read_regular(str(path), ORIGINAL_SINGLE_CASE_LIMIT)).digest() != previous
            for path, previous in zip(paths, hashes)):
        raise Hold("original completed case files changed during packaging")
