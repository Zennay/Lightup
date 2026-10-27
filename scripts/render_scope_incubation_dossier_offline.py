#!/usr/bin/env python3
"""Opt-in local-only current incubation Markdown report; no authority granted."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lightup.capabilities import get_capabilities
from lightup.capability_registry_incubation_markdown_report import (
    _generic_hold,
    render_incubation_dossier_markdown,
)
from export_scope_capability_registry_offline import snapshot_manifest


def main(args: list[str]) -> int:
    if type(args) is not list or args:
        markdown, code = _generic_hold()
    else:
        try:
            markdown, code = render_incubation_dossier_markdown(
                snapshot_manifest(get_capabilities())
            )
        except (ValueError, TypeError, OverflowError, RecursionError):
            markdown, code = _generic_hold()
    sys.stdout.write(markdown)
    # A source metadata review report must NEVER be a success/zero exit.
    return 3 if code == 3 else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
