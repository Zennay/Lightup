"""Original-account-authenticated private Scope Escalation workspace (human-only).

Requires the unchanged, persisted LightUp DomainStore login and original Casebook.
Authentication is NOT client consent, source release, grant or execution authority.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
from getpass import getpass
from pathlib import Path
import sys


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True, help="existing private original domain SQLite")
    parser.add_argument("--email", required=True, help="existing real LightUp operator/client account")
    parser.add_argument("--client", help="original exact tenant; mandatory for operator")
    parser.add_argument("--workspace", required=True, help="fresh private 0700 directory")
    args = parser.parse_args(argv)
    # The original authentication must remain a human-interactive operation.
    # Never accept password from CLI, pipes, config, environment or disk.
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        print("HOLD: interactive original account authentication required", file=sys.stderr)
        return 3
    try:
        from lightup.auth_casebook import authenticated_casebook, CasebookHold
        spec = importlib.util.spec_from_file_location(
            "scope_escalation_board", Path(__file__).with_name("board.py"))
        if spec is None or spec.loader is None:
            raise RuntimeError("board source unavailable")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        secret = getpass("Original LightUp account password: ")
        try:
            # Uses original persisted identities, account lockout and tenant
            # admission. No new login/authorization representation is minted.
            source = authenticated_casebook(
                args.database, email=args.email,
                password=secret, client_id=args.client)
        finally:
            secret = None
        # Byte representation identical to original Casebook --output.
        original = (json.dumps(source, sort_keys=True, indent=2,
                               allow_nan=False) + "\n").encode("utf-8")
        if len(original) > module.MAX_BYTES:
            raise module.Hold("original source exceeds maximum")
        # Use the same all-false, complete source admission as private read path,
        # but without writing an intermediate plaintext source file.
        admitted = json.loads(
            original.decode("utf-8"),
            object_pairs_hook=module._unique_pairs,
            parse_constant=module._reject_constant)
        if admitted != source:
            raise module.Hold("unstable original source serialization")
        # Fully evaluate original row, lineage and declared count validity.
        # A new private temporary file is intentionally not created here.
        module.admit_source_data(original, admitted)
        module.build_private_workspace(original, admitted, Path(args.workspace))
        print("REVIEW_ONLY: original-account Scope Escalation room created privately")
        return 2
    except (ImportError, Exception):
        # Do not disclose login, tenant, source IDs or original exception text.
        print("HOLD: original authenticated source or private room refused", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
