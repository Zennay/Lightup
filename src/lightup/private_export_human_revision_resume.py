"""Resume original-ciphertext-bound encrypted HUMAN choices as a local visual editor.

Consumes authenticated .lue/.lun originals and one v2 .lud. Creates only a
new 0600, explicitly UNENCRYPTED one-file HTML editor, with existing booleans
prefilled. The browser may export a new PRIVATE JSON for strict re-sealing.
No source, prior plan, ciphertext or authority record is mutated.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import sys

from .private_export_encrypted import _passphrase
from .private_export_handoff import _atomic_private_publish, _output_path
from .private_export_human_revision_editor import _html
from .private_export_human_revision_vault import (
    _current_source, _read_decisions, _reconcile,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Resume exact-ciphertext-bound PRIVATE HUMAN choices in a one-file offline browser editor"
    )
    parser.add_argument("earlier_source")
    parser.add_argument("earlier_plan")
    parser.add_argument("later_source")
    parser.add_argument("--encrypted-choices", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--ack-private-handling", action="store_true")
    parser.add_argument("--ack-same-real-client", action="store_true")
    parser.add_argument("--ack-plaintext-original-ids", action="store_true")
    args = parser.parse_args(argv)
    try:
        if not (
            args.ack_private_handling and args.ack_same_real_client
            and args.ack_plaintext_original_ids
        ):
            raise ValueError("private recipient, source and plaintext original ID acknowledgment required")
        destination = _output_path(args.output, ".html")
        expected, template, new_rows, new_meta, source_binding = _current_source(
            args.earlier_source, args.earlier_plan, args.later_source
        )
        secret = _passphrase("Existing encrypted HUMAN decisions passphrase")
        decisions, _ciphertext_plain = _read_decisions(
            args.encrypted_choices, secret, source_binding
        )
        del secret
        # No trusting caller-edited HTML or JSON: every re-open fully validates
        # exact source bytes, source ordered rows and all canonical decisions.
        _plan, summary = _reconcile(
            decisions, expected, deepcopy(template), new_meta, new_rows
        )
        rendered = _html(decisions)
        _atomic_private_publish(destination, rendered)
        print("Created NEW UNENCRYPTED 0600 PRIVATE HUMAN visual review editor.")
        print("Existing source-bound HUMAN carry choices are preselected, not executed.")
        for key, value in summary.items():
            print(key + ":", value)
        print("Only a separate explicit browser JSON export and CLI seal/apply can create changes.")
        print("HOLD: no real identity, consent, evidence equality, verified fix or retest.")
        return 0
    except (ValueError, OSError, UnicodeError, EOFError, KeyboardInterrupt):
        print("PRIVATE encrypted HUMAN decision visual resume HOLD: source, choice or output rejected.",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
