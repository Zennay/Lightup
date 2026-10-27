"""Hermetic, real-entrypoint scope-incubation catalog CLI acceptance.

No customer target or socket is ever contacted. A pre-import socket tripwire
also marks network *attempts*, even if a CLI later catches the exception.
Python hooks are not an operating-system egress boundary.
"""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

from test_scope_offline_cli_no_network import run_denied_network

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts/review_scope_incubation_catalog_offline.py"
_MARKER = "__LIGHTUP_INCU_NETWORK_ATTEMPT_BLOCKED__"
_FLAGS = (
    "authorization_verified", "permit_issued", "execution_enabled",
    "merge_approved", "release_approved",
)

# Source changes below are confined to a new, disposable Python subprocess;
# the actual checkout and source registry are never modified.
_SOURCE_MUTATION_CHILD = r"""
import dataclasses
import json
import os
import runpy
import socket
import sys

def deny(*args, **kwargs):
    sys.stderr.write("__LIGHTUP_INCU_NETWORK_ATTEMPT_BLOCKED__\n")
    raise RuntimeError("attempted network during offline scope review")

for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex",
             "getnameinfo", "create_connection"):
    if hasattr(socket, name):
        setattr(socket, name, deny)
for name in ("connect", "connect_ex", "send", "sendall", "sendto"):
    if hasattr(socket.socket, name):
        setattr(socket.socket, name, deny)

script, mutant = sys.argv[1:3]
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(script)), "src"))
sys.path.insert(0, os.path.dirname(script))
from lightup import capabilities
records = capabilities.get_capabilities()
target_id = "web-baseline"
if mutant == "description":
    records = tuple(dataclasses.replace(c, description="Synthetic private fixture marker")
                    if c.capability_id == target_id else c for c in records)
elif mutant == "name":
    records = tuple(dataclasses.replace(c, name="Synthetic name marker")
                    if c.capability_id == target_id else c for c in records)
elif mutant == "state":
    records = tuple(dataclasses.replace(c, state=capabilities.CapabilityState.LAB_ONLY)
                    if c.capability_id == target_id else c for c in records)
elif mutant == "activation":
    records = tuple(dataclasses.replace(c, requires_explicit_activation=False)
                    if c.capability_id == target_id else c for c in records)
elif mutant == "added":
    records = records + (capabilities.Capability(
        "synthetic-unreviewed", "Synthetic extra", "No targets",
        capabilities.CapabilityState.PLANNING
    ),)
elif mutant == "removed":
    records = tuple(c for c in records if c.capability_id != target_id)
elif mutant != "unchanged":
    raise RuntimeError("invalid fixture selector")
capabilities.get_capabilities = lambda: records
sys.argv = [script]
runpy.run_path(script, run_name="__main__")
"""


def real_cli_with_mutated_source(mode: str):
    return subprocess.run(
        [sys.executable, "-c", _SOURCE_MUTATION_CHILD, str(_SCRIPT), mode],
        text=True, capture_output=True, timeout=15,
    )


class IncubationCliNetworkBoundaryTests(unittest.TestCase):
    def assert_no_authority(self, result):
        receipt = json.loads(result.stdout)
        for name in _FLAGS:
            self.assertIs(receipt[name], False, name)
        self.assertNotIn(_MARKER, result.stderr, "network attempted")
        self.assertNotIn("Synthetic private fixture marker", result.stdout)
        self.assertNotIn("Synthetic name marker", result.stdout)
        self.assertNotIn("Synthetic extra", result.stdout)
        return receipt

    def test_actual_cli_known_catalog_no_network_and_exit_three(self):
        proc = run_denied_network(_SCRIPT.name)
        self.assertEqual(proc.returncode, 3, proc.stderr)
        self.assertEqual(self.assert_no_authority(proc)["status"], "REVIEW_ONLY")

    def test_cli_rejects_target_like_and_activation_args_without_network(self):
        for arg in ("--activate", "https://synthetic.invalid/path", "../../untrusted.json"):
            with self.subTest(arg=arg):
                proc = run_denied_network(_SCRIPT.name, arg)
                self.assertEqual(proc.returncode, 2, proc.stderr)
                self.assertEqual(self.assert_no_authority(proc)["status"], "HOLD")

    def test_source_hook_clean_control_is_review_only(self):
        proc = real_cli_with_mutated_source("unchanged")
        self.assertEqual(proc.returncode, 3, proc.stderr)
        receipt = self.assert_no_authority(proc)
        self.assertEqual(receipt["status"], "REVIEW_ONLY")
        self.assertEqual(receipt["reason"], "incubation_catalog_metadata_only")

    def test_description_only_source_mutation_holds_in_real_cli(self):
        proc = real_cli_with_mutated_source("description")
        self.assertEqual(proc.returncode, 2, proc.stderr)
        receipt = self.assert_no_authority(proc)
        self.assertEqual(receipt["status"], "HOLD")
        self.assertEqual(receipt["reason"], "semantic_metadata_differs_from_reviewed_reference")

    def test_name_only_source_mutation_holds_in_real_cli(self):
        proc = real_cli_with_mutated_source("name")
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertEqual(
            self.assert_no_authority(proc)["reason"],
            "semantic_metadata_differs_from_reviewed_reference",
        )

    def test_state_reclassification_holds_in_real_cli(self):
        proc = real_cli_with_mutated_source("state")
        self.assertEqual(proc.returncode, 2, proc.stderr)
        receipt = self.assert_no_authority(proc)
        self.assertIn({"capability_id": "web-baseline", "code": "incubation_state_changed"},
                      receipt["violations"])

    def test_turned_off_explicit_activation_holds_in_real_cli(self):
        proc = real_cli_with_mutated_source("activation")
        self.assertEqual(proc.returncode, 2, proc.stderr)
        receipt = self.assert_no_authority(proc)
        self.assertIn({"capability_id": "web-baseline", "code": "explicit_activation_required"},
                      receipt["violations"])

    def test_added_capability_holds_in_real_cli(self):
        proc = real_cli_with_mutated_source("added")
        self.assertEqual(proc.returncode, 2, proc.stderr)
        receipt = self.assert_no_authority(proc)
        self.assertIn({"capability_id": "synthetic-unreviewed", "code": "unreviewed_capability_added"},
                      receipt["violations"])

    def test_removed_capability_holds_in_real_cli(self):
        proc = real_cli_with_mutated_source("removed")
        self.assertEqual(proc.returncode, 2, proc.stderr)
        receipt = self.assert_no_authority(proc)
        self.assertIn({"capability_id": "web-baseline", "code": "required_capability_missing"},
                      receipt["violations"])


if __name__ == "__main__":
    unittest.main()
