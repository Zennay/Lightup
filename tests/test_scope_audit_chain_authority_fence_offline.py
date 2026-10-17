"""Offline-only authority/side-effect tripwires and stable fixture vector.

No real grant, target, handler, database, network or shell may be invoked by
these opt-in fictional review routines.
"""

from __future__ import annotations

import ast
from datetime import datetime
import hashlib
import json
from pathlib import Path
import socket
import sqlite3
import subprocess
import unittest
from unittest.mock import patch

from lightup.scope_audit_chain_offline import (
    DOMAIN, SCHEMA as CHAIN_SCHEMA, ZERO_HASH,
    compute_event_hash, verify_chain,
)
from lightup.scope_audit_chain_transition_offline import (
    SCHEMA as TRANSITION_SCHEMA, verify_transition,
)
from lightup.scope_audit_chain_checkpoints_offline import (
    SCHEMA as CHECKPOINT_SCHEMA, verify_checkpoints,
)


OWNED_MODULES = (
    "scope_audit_chain_offline.py",
    "scope_audit_chain_transition_offline.py",
    "scope_audit_chain_checkpoints_offline.py",
)
FORBIDDEN_IMPORT_ROOTS = frozenset({
    "socket", "ssl", "sqlite3", "subprocess", "urllib", "http", "requests",
    "os", "pathlib", "asyncio", "lightup.domain", "lightup.webapp",
    "lightup.activation", "lightup.execution_policy",
})
FORBIDDEN_CALLS = frozenset({
    "eval", "exec", "compile", "__import__", "open", "input",
})


def _synthetic_snapshots():
    body0 = {
        "seq": 0, "kind": "REVIEW_OPENED",
        "at": "2026-10-17T12:00:00Z",
        "scope_sha256": "a" * 64, "previous_sha256": ZERO_HASH,
    }
    head0 = compute_event_hash(body0)
    body1 = {
        "seq": 1, "kind": "REVIEW_NOTE",
        "at": "2026-10-17T12:00:01Z",
        "scope_sha256": "a" * 64, "previous_sha256": head0,
    }
    head1 = compute_event_hash(body1)
    first = {"schema": CHAIN_SCHEMA, "events": [{**body0, "sha256": head0}]}
    second = {
        "schema": CHAIN_SCHEMA,
        "events": [{**body0, "sha256": head0}, {**body1, "sha256": head1}],
    }
    return first, second, head0, head1


def _as_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class OfflineAuthorityFenceTests(unittest.TestCase):
    def test_imports_have_no_execution_or_external_io_dependencies(self):
        root = Path(__file__).resolve().parents[1] / "src" / "lightup"
        for filename in OWNED_MODULES:
            with self.subTest(filename=filename):
                tree = ast.parse((root / filename).read_text(encoding="utf-8"))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            name = alias.name
                            self.assertFalse(
                                name in FORBIDDEN_IMPORT_ROOTS or
                                name.split(".")[0] in FORBIDDEN_IMPORT_ROOTS,
                                (filename, name),
                            )
                    if isinstance(node, ast.ImportFrom):
                        module = node.module or ""
                        self.assertFalse(
                            module in FORBIDDEN_IMPORT_ROOTS or
                            module.split(".")[0] in FORBIDDEN_IMPORT_ROOTS,
                            (filename, module),
                        )
                    if isinstance(node, ast.Call):
                        if isinstance(node.func, ast.Name):
                            self.assertNotIn(
                                node.func.id, FORBIDDEN_CALLS,
                                (filename, node.func.id),
                            )

    def test_runtime_routines_do_not_call_external_io(self):
        # Warm the standard-library parser before forbidding I/O, including
        # lazy locale/regex initialization needed by datetime.strptime.
        datetime.strptime("2026-10-17T12:00:00Z", "%Y-%m-%dT%H:%M:%SZ")
        first, second, tip0, tip1 = _synthetic_snapshots()
        transition = {
            "schema": TRANSITION_SCHEMA, "before": first, "after": second,
        }
        checkpoints = {
            "schema": CHECKPOINT_SCHEMA, "snapshots": [first, second],
        }
        with (
            patch("socket.socket", side_effect=AssertionError("network forbidden")),
            patch("sqlite3.connect", side_effect=AssertionError("database forbidden")),
            patch("subprocess.Popen", side_effect=AssertionError("process forbidden")),
            patch("builtins.open", side_effect=AssertionError("filesystem forbidden")),
        ):
            self.assertEqual(
                "REVIEW_ONLY", verify_chain(_as_bytes(first), tip0)["status"]
            )
            self.assertEqual(
                "REVIEW_ONLY",
                verify_transition(_as_bytes(transition), tip0, tip1)["status"],
            )
            self.assertEqual(
                "REVIEW_ONLY",
                verify_checkpoints(_as_bytes(checkpoints), (tip0, tip1))["status"],
            )

    def test_domain_separation_golden_hash_and_independent_sha(self):
        canonical_body = {
            "seq": 0, "kind": "REVIEW_OPENED",
            "at": "2026-10-17T12:00:00Z",
            "scope_sha256": "a" * 64, "previous_sha256": ZERO_HASH,
        }
        golden = "59267f3feeff8bd6e372509f5aa5fc809cbd28d07f4d1481e472aa45a3206826"
        self.assertEqual(golden, compute_event_hash(canonical_body))
        canonical = (
            b'{"at":"2026-10-17T12:00:00Z","kind":"REVIEW_OPENED",'
            b'"previous_sha256":"' + b"0" * 64 +
            b'","scope_sha256":"' + b"a" * 64 +
            b'","seq":0}'
        )
        self.assertEqual(golden, hashlib.sha256(DOMAIN + canonical).hexdigest())
        self.assertNotEqual(golden, hashlib.sha256(canonical).hexdigest())

    def test_three_receipt_contracts_never_grant_live_authority(self):
        first, second, tip0, tip1 = _synthetic_snapshots()
        raw = _as_bytes(first)
        transition = _as_bytes({
            "schema": TRANSITION_SCHEMA, "before": first, "after": second,
        })
        checkpoints = _as_bytes({
            "schema": CHECKPOINT_SCHEMA, "snapshots": [first, second],
        })
        for receipt in (
            verify_chain(raw, tip0),
            verify_chain(raw, "f" * 64),
            verify_transition(transition, tip0, tip1),
            verify_transition(transition, tip0, "f" * 64),
            verify_checkpoints(checkpoints, (tip0, tip1)),
            verify_checkpoints(checkpoints, (tip0, "f" * 64)),
        ):
            with self.subTest(status=receipt["status"]):
                self.assertIn(receipt["status"], ("REVIEW_ONLY", "HOLD"))
                self.assertIs(receipt["consent_verified"], False)
                self.assertIs(receipt["authorization_granted"], False)
                self.assertIs(receipt["release_approved"], False)


if __name__ == "__main__":
    unittest.main()
