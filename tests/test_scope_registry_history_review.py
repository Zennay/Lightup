"""In-memory and actual offline CLI acceptance for historical registry drift."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from lightup.capabilities import get_capabilities
from lightup.capability_registry_history_review import review_capability_registry_history
from scripts.export_scope_capability_registry_offline import snapshot_manifest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/review_scope_registry_history_offline.py"


def cap(name="web-baseline", state="planning", active=True):
    return {
        "capability_id": name, "state": state,
        "requires_explicit_activation": active,
        "name": "Web baseline", "description": "Synthetic only",
    }


def manifest(*records):
    return json.dumps({"capabilities": list(records)}, sort_keys=True).encode("utf-8")


def cli(files):
    return subprocess.run([sys.executable, str(SCRIPT), *map(str, files)],
                          text=True, capture_output=True, timeout=15)


class RegistryHistoryTests(unittest.TestCase):
    def setUp(self):
        self.base = manifest(cap())
        self.change = manifest(cap(state="lab_only"))

    def assert_non_authorizing(self, review):
        for field in ("authorization_verified", "permit_issued", "execution_enabled", "merge_approved", "release_approved"):
            self.assertIs(review.as_dict()[field], False)

    def test_two_identical_snapshots_only_review(self):
        result = review_capability_registry_history((self.base, self.base))
        self.assertEqual(result.status, "REVIEW_ONLY")
        self.assertEqual(result.snapshot_count, 2)
        self.assertEqual(result.transitions, ())
        self.assertEqual(len(result.fingerprint_history), 2)
        self.assert_non_authorizing(result)

    def test_intermediate_reclassification_then_reversion_holds(self):
        result = review_capability_registry_history((self.base, self.change, self.base))
        self.assertEqual(result.status, "HOLD")
        self.assertEqual(len(result.transitions), 2)
        self.assertEqual(result.fingerprint_history[0], result.fingerprint_history[-1])
        self.assertEqual([item.as_dict()["changed_fields"] for item in result.transitions],
                         [{"web-baseline": ["state"]}, {"web-baseline": ["state"]}])
        self.assert_non_authorizing(result)

    def test_intermediate_capability_addition_then_removal_holds(self):
        expanded = manifest(cap(), cap("temporary-lab"))
        result = review_capability_registry_history((self.base, expanded, self.base))
        self.assertEqual(result.status, "HOLD")
        self.assertEqual(result.transitions[0].as_dict()["changed_fields"], {"temporary-lab": ["added"]})
        self.assertEqual(result.transitions[1].as_dict()["changed_fields"], {"temporary-lab": ["removed"]})

    def test_initial_and_final_same_but_activation_toggle_holds(self):
        transient = manifest(cap(active=False))
        result = review_capability_registry_history((self.base, transient, self.base))
        self.assertEqual(result.status, "HOLD")
        self.assertEqual(result.transitions[0].as_dict()["changed_fields"],
                         {"web-baseline": ["requires_explicit_activation"]})

    def test_only_changed_description_holds_without_text_echo(self):
        modified = manifest({**cap(), "description": "Synthetic private content marker"})
        result = review_capability_registry_history((self.base, modified))
        self.assertEqual(result.status, "HOLD")
        self.assertNotIn("Synthetic private content marker", json.dumps(result.as_dict()))
        self.assertEqual(result.transitions[0].as_dict()["changed_fields"], {"web-baseline": ["description"]})

    def test_stable_history_all_sixteen_snapshots(self):
        result = review_capability_registry_history((self.base,) * 16)
        self.assertEqual(result.status, "REVIEW_ONLY")
        self.assertEqual(result.snapshot_count, 16)
        self.assertEqual(len(result.fingerprint_history), 16)

    def test_seventeen_snapshots_denied(self):
        result = review_capability_registry_history((self.base,) * 17)
        self.assertEqual(result.status, "HOLD")
        self.assertEqual(result.reason, "invalid_snapshot_count")
        self.assert_non_authorizing(result)

    def test_one_snapshot_denied(self):
        self.assertEqual(review_capability_registry_history((self.base,)).reason, "invalid_snapshot_count")

    def test_list_instead_of_tuple_denied(self):
        self.assertEqual(review_capability_registry_history([self.base, self.base]).status, "HOLD")

    def test_subclass_of_tuple_denied(self):
        class Spoof(tuple):
            pass
        self.assertEqual(review_capability_registry_history(Spoof((self.base, self.base))).status, "HOLD")

    def test_nonbytes_payload_denied(self):
        self.assertEqual(review_capability_registry_history((self.base, self.base.decode())).status, "HOLD")

    def test_invalid_intermediate_metadata_holds_without_partial_details(self):
        review = review_capability_registry_history((self.base, b'{"capabilities":[]}', self.base))
        self.assertEqual(review.status, "HOLD")
        self.assertEqual(review.transitions, ())
        self.assertEqual(review.fingerprint_history, ())
        self.assert_non_authorizing(review)

    def test_real_local_source_registry_reversion_holds(self):
        original = get_capabilities()
        raw = snapshot_manifest(original)
        modified = (replace(original[0], description=original[0].description + " synthetic"),) + original[1:]
        review = review_capability_registry_history((raw, snapshot_manifest(modified), raw))
        self.assertEqual(review.status, "HOLD")
        self.assertEqual(len(review.transitions), 2)
        self.assert_non_authorizing(review)

    def test_read_only_cli_distinct_files_equal_non_authorizing(self):
        with tempfile.TemporaryDirectory() as folder:
            first, second = Path(folder) / "one.json", Path(folder) / "two.json"
            first.write_bytes(self.base)
            second.write_bytes(self.base)
            run = cli((first, second))
            self.assertEqual(run.returncode, 3, run.stderr)
            review = json.loads(run.stdout)
            self.assertEqual(review["status"], "REVIEW_ONLY")
            self.assertIs(review["execution_enabled"], False)

    def test_cli_intermediate_reversion_is_hold(self):
        with tempfile.TemporaryDirectory() as folder:
            files = [Path(folder) / f"{index}.json" for index in range(3)]
            for file, content in zip(files, (self.base, self.change, self.base)):
                file.write_bytes(content)
            run = cli(files)
            self.assertEqual(run.returncode, 2, run.stderr)
            self.assertEqual(len(json.loads(run.stdout)["transitions"]), 2)
            self.assertIs(json.loads(run.stdout)["permit_issued"], False)

    def test_cli_same_file_twice_denied(self):
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / "one.json"
            file.write_bytes(self.base)
            run = cli((file, file))
            self.assertEqual(run.returncode, 2)
            self.assertEqual(json.loads(run.stdout)["reason"], "invalid_local_history_files")

    def test_cli_hardlink_denied(self):
        with tempfile.TemporaryDirectory() as folder:
            original, alias = Path(folder) / "one.json", Path(folder) / "two.json"
            original.write_bytes(self.base)
            try:
                os.link(original, alias)
            except OSError:
                self.skipTest("hardlinks unsupported")
            run = cli((original, alias))
            self.assertEqual(run.returncode, 2)
            self.assertIs(json.loads(run.stdout)["authorization_verified"], False)

    def test_cli_symlink_denied(self):
        with tempfile.TemporaryDirectory() as folder:
            original, alias = Path(folder) / "one.json", Path(folder) / "two.json"
            original.write_bytes(self.base)
            alias.symlink_to(original)
            run = cli((original, alias))
            self.assertEqual(run.returncode, 2)
            self.assertIs(json.loads(run.stdout)["release_approved"], False)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO unsupported")
    def test_cli_fifo_denied_without_blocking(self):
        with tempfile.TemporaryDirectory() as folder:
            original, pipe = Path(folder) / "one.json", Path(folder) / "fifo"
            original.write_bytes(self.base)
            os.mkfifo(pipe)
            run = cli((original, pipe))
            self.assertEqual(run.returncode, 2)
            self.assertIs(json.loads(run.stdout)["execution_enabled"], False)

    def test_cli_requires_multiple_input_paths(self):
        run = cli(())
        self.assertEqual(run.returncode, 2)
        self.assertIs(json.loads(run.stdout)["permit_issued"], False)


if __name__ == "__main__":
    unittest.main()
