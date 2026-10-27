"""Shared fail-closed option parsing for offline assessment-runtime CLIs.

This module only parses local command-line strings. It never reads files,
dispatches tools, performs network access or grants authority.
"""
from __future__ import annotations


_OUTPUT_FORMATS = frozenset((
    "json", "text", "html", "csv",
    "actions-csv", "actions-html", "actions-json",
    "efficiency-json", "efficiency-html", "review-json",
))
_HUMAN_FOCUS_FORMATS = frozenset((
    "actions-csv", "actions-html", "actions-json",
))
_FOCUS = frozenset(("all", "scope", "adverse", "unknown", "source"))


def parse_offline_cli_args(argv):
    """Return format, HUMAN focus, positional files, malformed; never authorize.

    Reject duplicate or unknown flags, non-string elements, and any --focus
    supplied with a format that cannot actually consume the focus.
    """
    if type(argv) not in (list, tuple):
        return "json", "all", (), True
    args = argv
    output_format = "json"
    focus_filter = "all"
    format_seen = False
    focus_seen = False
    malformed = len(args) > 32
    positional = []
    index = 0
    while index < len(args):
        item = args[index]
        if type(item) is not str:
            malformed = True
            index += 1
        elif item == "--format":
            if (format_seen or index + 1 >= len(args)
                    or type(args[index + 1]) is not str
                    or args[index + 1] not in _OUTPUT_FORMATS):
                malformed = True
                index += 2 if index + 1 < len(args) else 1
            else:
                output_format = args[index + 1]
                format_seen = True
                index += 2
        elif item == "--focus":
            if (focus_seen or index + 1 >= len(args)
                    or type(args[index + 1]) is not str
                    or args[index + 1] not in _FOCUS):
                malformed = True
                index += 2 if index + 1 < len(args) else 1
            else:
                focus_filter = args[index + 1]
                focus_seen = True
                index += 2
        elif item.startswith("--"):
            malformed = True
            index += 1
        else:
            positional.append(item)
            index += 1
    if focus_seen and output_format not in _HUMAN_FOCUS_FORMATS:
        malformed = True
    return output_format, focus_filter, tuple(positional), malformed
