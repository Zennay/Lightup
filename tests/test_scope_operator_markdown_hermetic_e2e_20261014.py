"""Real human Markdown incubation report CLI, with pre-import side-effect tripwires.

These are *Python-level* hermetic tests, not a security sandbox. Only test
subprocesses are injected, no persisted registry/customer state is modified.
"""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts/render_scope_incubation_dossier_offline.py"
_MARKER = "__LIGHTUP_DOSSIER_SIDE_EFFECT_ATTEMPT__"
_FALSE_FIELDS = (
    "authorization_verified", "permit_issued", "execution_enabled",
    "merge_approved", "release_approved",
)

_CHILD = r'''
import builtins
import os
import pathlib
import runpy
import socket
import sqlite3
import subprocess
import sys
from dataclasses import replace
sys.dont_write_bytecode = True

def deny(*args, **kwargs):
    sys.stderr.write("__LIGHTUP_DOSSIER_SIDE_EFFECT_ATTEMPT__\n")
    raise RuntimeError("offline scope CLI attempted a prohibited effect")

for method in (
    "getaddrinfo", "gethostbyname", "gethostbyname_ex", "getnameinfo",
    "create_connection",
):
    if hasattr(socket, method):
        setattr(socket, method, deny)
for method in ("connect", "connect_ex", "send", "sendall", "sendto"):
    if hasattr(socket.socket, method):
        setattr(socket.socket, method, deny)

_open, _os_open, _path_open = builtins.open, os.open, pathlib.Path.open
def checked_open(path, mode="r", *args, **kwargs):
    if type(mode) is not str or any(c in mode for c in "wax+"):
        return deny()
    return _open(path, mode, *args, **kwargs)
def checked_os_open(path, flags, *args, **kwargs):
    if type(flags) is not int or flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
        return deny()
    return _os_open(path, flags, *args, **kwargs)
def checked_path_open(path, mode="r", *args, **kwargs):
    if type(mode) is not str or any(c in mode for c in "wax+"):
        return deny()
    return _path_open(path, mode, *args, **kwargs)
builtins.open = checked_open
os.open = checked_os_open
pathlib.Path.open = checked_path_open
for name in ("write_text", "write_bytes", "mkdir", "unlink", "rename", "replace"):
    setattr(pathlib.Path, name, deny)
for name in ("mkdir", "makedirs", "rename", "replace", "remove", "unlink"):
    setattr(os, name, deny)
sqlite3.connect = deny
subprocess.Popen = deny

script = pathlib.Path(sys.argv[1])
mode = sys.argv[2]
cli_args = sys.argv[3:]
root = script.parents[1]
sys.path.insert(0, str(root / "src"))
sys.path.insert(0, str(root / "scripts"))
from lightup import capabilities
original = capabilities.get_capabilities()
state = capabilities.CapabilityState
if mode == "name":
    records = tuple(replace(c, name="CONFIDENTIAL_ACME_NAME") if c.capability_id == "web-baseline" else c for c in original)
elif mode == "description":
    records = tuple(replace(c, description="CONFIDENTIAL_ACME_DESCRIPTION") if c.capability_id == "web-baseline" else c for c in original)
elif mode == "both":
    records = tuple(replace(c, name="CONFIDENTIAL_NAME", description="CONFIDENTIAL_DESCRIPTION") if c.capability_id == "web-baseline" else c for c in original)
elif mode == "state":
    records = tuple(replace(c, state=state.DISABLED) if c.capability_id == "web-baseline" else c for c in original)
elif mode == "lab_state":
    records = tuple(replace(c, state=state.PLANNING) if c.capability_id == "wireless-lab" else c for c in original)
elif mode == "activation":
    records = tuple(replace(c, requires_explicit_activation=False) if c.capability_id == "web-baseline" else c for c in original)
elif mode == "added":
    records = original + (capabilities.Capability("added-example", "Added", "Fixture", state.PLANNING),)
elif mode == "removed":
    records = tuple(c for c in original if c.capability_id != "ot-lab")
elif mode == "invalid_container":
    records = list(original)
elif mode == "invalid_name":
    records = tuple(replace(c, name="BAD\u0000PRIVATE") if c.capability_id == "web-baseline" else c for c in original)
elif mode == "malicious_html":
    records = tuple(replace(c, description="<script>EXFIL_PRIVATE</script>") if c.capability_id == "web-baseline" else c for c in original)
else:
    records = original

capabilities.get_capabilities = lambda: records
sys.argv = [str(script), *cli_args]
runpy.run_path(str(script), run_name="__main__")
'''


def run_hermetic(mode: str, *args: str) -> subprocess.CompletedProcess[str]:
    process = subprocess.run(
        [sys.executable, "-B", "-c", _CHILD, str(_SCRIPT), mode, *args],
        capture_output=True, text=True, timeout=15,
    )
    if _MARKER in process.stderr:
        raise AssertionError(f"dossier CLI attempted network, subprocess or persistent mutation: {mode}")
    return process


class HumanMarkdownHermeticCLITests(unittest.TestCase):
    def check_no_authority(self, proc, expected):
        self.assertEqual(proc.returncode, expected, proc.stderr)
        self.assertIn("**Authority: NONE.**", proc.stdout)
        self.assertIn("No target interaction", proc.stdout)
        self.assertNotIn("__LIGHTUP_DOSSIER_SIDE_EFFECT_ATTEMPT__", proc.stderr)

    def test_clean_current_catalog_review_only_no_external_effects(self):
        proc = run_hermetic("clean")
        self.check_no_authority(proc, 3)
        self.assertIn("**Verdict:** `REVIEW_ONLY`", proc.stdout)
        self.assertIn("| Closed-world catalog | `REVIEW_ONLY` |", proc.stdout)

    def test_real_name_drift_exits_hold_without_original_name(self):
        proc = run_hermetic("name")
        self.check_no_authority(proc, 2)
        self.assertIn("**Verdict:** `HOLD`", proc.stdout)
        self.assertIn("| `web-baseline` | `fields` | `name` |", proc.stdout)
        self.assertNotIn("CONFIDENTIAL", proc.stdout)

    def test_real_description_drift_exits_hold_without_original_description(self):
        proc = run_hermetic("description")
        self.check_no_authority(proc, 2)
        self.assertIn("| `web-baseline` | `fields` | `description` |", proc.stdout)
        self.assertNotIn("CONFIDENTIAL", proc.stdout)

    def test_both_semantic_fields_are_disclosed_as_fixed_labels_only(self):
        proc = run_hermetic("both")
        self.check_no_authority(proc, 2)
        self.assertIn("| `web-baseline` | `fields` | `name` |", proc.stdout)
        self.assertIn("| `web-baseline` | `fields` | `description` |", proc.stdout)
        self.assertNotIn("CONFIDENTIAL", proc.stdout)

    def test_ordinary_state_change_holds_even_if_other_gate_review_only(self):
        proc = run_hermetic("state")
        self.check_no_authority(proc, 2)
        self.assertIn("| `web-baseline` | `catalog` | `incubation_state_changed` |", proc.stdout)
        self.assertIn("| Incubation lab / activation posture | `REVIEW_ONLY` |", proc.stdout)

    def test_sensitive_lab_reclassification_never_becomes_public_active(self):
        proc = run_hermetic("lab_state")
        self.check_no_authority(proc, 2)
        self.assertIn("| `wireless-lab` | `posture` | `sensitive_lab_capability_reclassified` |", proc.stdout)

    def test_activation_false_cannot_gain_implicit_permission(self):
        proc = run_hermetic("activation")
        self.check_no_authority(proc, 2)
        self.assertIn("| `web-baseline` | `posture` | `explicit_activation_required` |", proc.stdout)

    def test_unknown_added_capability_holds_in_human_output(self):
        proc = run_hermetic("added")
        self.check_no_authority(proc, 2)
        self.assertIn("| `added-example` | `catalog` | `unreviewed_capability_added` |", proc.stdout)

    def test_missing_sensitive_lab_holds_in_human_output(self):
        proc = run_hermetic("removed")
        self.check_no_authority(proc, 2)
        self.assertIn("| `ot-lab` | `posture` | `required_lab_capability_missing` |", proc.stdout)

    def test_invalid_registry_shape_no_partial_fingerprint_or_details(self):
        proc = run_hermetic("invalid_container")
        self.check_no_authority(proc, 2)
        self.assertIn("**Fingerprint:** unavailable", proc.stdout)
        self.assertNotIn("| `web-baseline` |", proc.stdout)
        self.assertNotIn("sha256:", proc.stdout)

    def test_noncanonical_source_text_atomic_hold_no_private_text(self):
        proc = run_hermetic("invalid_name")
        self.check_no_authority(proc, 2)
        self.assertIn("**Verdict:** `HOLD`", proc.stdout)
        self.assertNotIn("PRIVATE", proc.stdout)

    def test_html_like_description_never_enter_markdown(self):
        proc = run_hermetic("malicious_html")
        self.check_no_authority(proc, 2)
        self.assertIn("| `web-baseline` | `fields` | `description` |", proc.stdout)
        self.assertNotIn("<script>", proc.stdout)
        self.assertNotIn("EXFIL_PRIVATE", proc.stdout)

    def test_cli_does_not_accept_target_or_execute_args(self):
        for arg in ("--activate", "--scan", "https://synthetic.invalid", "../target.json"):
            with self.subTest(arg=arg):
                proc = run_hermetic("clean", arg)
                self.check_no_authority(proc, 2)
                self.assertIn("**Verdict:** `HOLD`", proc.stdout)
                self.assertNotIn("https://synthetic.invalid", proc.stdout)

    def test_invalid_source_and_hostile_flag_never_falls_back_to_review(self):
        proc = run_hermetic("invalid_name", "--activate")
        self.check_no_authority(proc, 2)
        self.assertIn("**Verdict:** `HOLD`", proc.stdout)
        self.assertNotIn("PRIVATE", proc.stdout)


if __name__ == "__main__":
    unittest.main()
