"""Real incubation dossier CLI drift injection with pre-import side-effect tripwires.

These are *Python-level* hermetic tests, not a security sandbox. Only test
subprocesses are injected, no persisted registry/customer state is modified.
"""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts/review_scope_incubation_dossier_offline.py"
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


class RealDossierHermeticCLITests(unittest.TestCase):
    def check_false(self, receipt: dict[str, object]) -> None:
        for key in _FALSE_FIELDS:
            self.assertIs(receipt[key], False, key)

    def test_clean_registry_all_three_gates_review_without_authority(self):
        result = run_hermetic("clean")
        self.assertEqual(result.returncode, 3, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["status"], "REVIEW_ONLY")
        self.assertEqual(receipt["component_statuses"], dict.fromkeys(
            ("catalog", "posture", "fields"), "REVIEW_ONLY"))
        self.assertEqual(receipt["catalog_violations"], [])
        self.assertEqual(receipt["posture_violations"], [])
        self.assertEqual(receipt["changed_fields"], {})
        self.check_false(receipt)

    def test_source_name_drift_holds_privately(self):
        result = run_hermetic("name")
        self.assertEqual(result.returncode, 2, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["status"], "HOLD")
        self.assertEqual(receipt["changed_fields"], {"web-baseline": ["name"]})
        self.assertEqual(receipt["component_statuses"]["posture"], "REVIEW_ONLY")
        self.assertNotIn("CONFIDENTIAL", result.stdout)
        self.check_false(receipt)

    def test_source_description_drift_holds_privately(self):
        result = run_hermetic("description")
        self.assertEqual(result.returncode, 2, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["changed_fields"], {"web-baseline": ["description"]})
        self.assertNotIn("CONFIDENTIAL", result.stdout)
        self.check_false(receipt)

    def test_simultaneous_name_description_drift_reported_together(self):
        result = run_hermetic("both")
        self.assertEqual(result.returncode, 2, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["changed_fields"], {"web-baseline": ["name", "description"]})
        self.assertNotIn("CONFIDENTIAL", result.stdout)
        self.check_false(receipt)

    def test_ordinary_state_change_holds_even_if_posture_review_only(self):
        result = run_hermetic("state")
        self.assertEqual(result.returncode, 2, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["component_statuses"], {
            "catalog": "HOLD", "posture": "REVIEW_ONLY", "fields": "HOLD",
        })
        self.assertIn({"capability_id": "web-baseline", "code": "incubation_state_changed"},
                      receipt["catalog_violations"])
        self.check_false(receipt)

    def test_sensitive_lab_reclassification_holds_both_security_gates(self):
        result = run_hermetic("lab_state")
        self.assertEqual(result.returncode, 2, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["component_statuses"], dict.fromkeys(
            ("catalog", "posture", "fields"), "HOLD"))
        self.assertIn({"capability_id": "wireless-lab", "code": "sensitive_lab_capability_reclassified"},
                      receipt["posture_violations"])
        self.check_false(receipt)

    def test_disabled_activation_is_never_implicitly_authorized(self):
        result = run_hermetic("activation")
        self.assertEqual(result.returncode, 2, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["component_statuses"]["posture"], "HOLD")
        self.assertIn({"capability_id": "web-baseline", "code": "explicit_activation_required"},
                      receipt["posture_violations"])
        self.check_false(receipt)

    def test_unknown_added_capability_is_not_accepted(self):
        result = run_hermetic("added")
        self.assertEqual(result.returncode, 2, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["status"], "HOLD")
        self.assertIn({"capability_id": "added-example", "code": "unreviewed_capability_added"},
                      receipt["catalog_violations"])
        self.check_false(receipt)

    def test_missing_lab_capability_cannot_be_hidden(self):
        result = run_hermetic("removed")
        self.assertEqual(result.returncode, 2, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["status"], "HOLD")
        self.assertIn({"capability_id": "ot-lab", "code": "required_lab_capability_missing"},
                      receipt["posture_violations"])
        self.check_false(receipt)

    def test_bad_registry_container_is_atomically_denied(self):
        result = run_hermetic("invalid_container")
        self.assertEqual(result.returncode, 2, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["status"], "HOLD")
        self.assertEqual(receipt["reason"], "invalid_local_registry")
        self.check_false(receipt)

    def test_noncanonical_metadata_is_atomically_denied(self):
        result = run_hermetic("invalid_name")
        self.assertEqual(result.returncode, 2, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["status"], "HOLD")
        self.assertEqual(receipt["reason"], "invalid_local_registry")
        self.assertNotIn("PRIVATE", result.stdout)
        self.check_false(receipt)

    def test_untrusted_script_like_metadata_is_never_echoed(self):
        result = run_hermetic("malicious_html")
        self.assertEqual(result.returncode, 2, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["changed_fields"], {"web-baseline": ["description"]})
        self.assertNotIn("EXFIL_PRIVATE", result.stdout)
        self.assertNotIn("<script>", result.stdout)
        self.check_false(receipt)

    def test_cli_rejects_network_or_execution_arguments_without_effects(self):
        for arg in ("--activate", "--scan", "https://203.0.113.1", "../some-target.json"):
            with self.subTest(arg=arg):
                result = run_hermetic("clean", arg)
                self.assertEqual(result.returncode, 2, result.stderr)
                receipt = json.loads(result.stdout)
                self.assertEqual(receipt["status"], "HOLD")
                self.assertEqual(receipt["reason"], "no_arguments_accepted")
                self.check_false(receipt)

    def test_invalid_registry_with_cli_argument_cannot_fallback_to_review(self):
        result = run_hermetic("invalid_name", "--activate")
        self.assertEqual(result.returncode, 2, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["status"], "HOLD")
        self.check_false(receipt)


if __name__ == "__main__":
    unittest.main()
