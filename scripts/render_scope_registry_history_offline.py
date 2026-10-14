#!/usr/bin/env python3
"""Offline, no-authority Markdown report of distinct local registry manifest files."""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lightup.capability_registry_history_report import render_capability_registry_history_markdown
from review_scope_capability_registry_offline import read_local_regular_file


def main(paths: list[str]) -> int:
    if type(paths) is not list or not 2 <= len(paths) <= 16 or any(type(item) is not str for item in paths):
        report, code = render_capability_registry_history_markdown(())
    else:
        try:
            seen: set[tuple[int, int]] = set()
            snapshots: list[bytes] = []
            for path in paths:
                content, identity = read_local_regular_file(path)
                if identity in seen:
                    raise ValueError("physical history snapshot repeated")
                seen.add(identity)
                snapshots.append(content)
            report, code = render_capability_registry_history_markdown(tuple(snapshots))
        except (OSError, ValueError, TypeError, OverflowError):
            report, code = render_capability_registry_history_markdown(())
    sys.stdout.write(report)
    return code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
