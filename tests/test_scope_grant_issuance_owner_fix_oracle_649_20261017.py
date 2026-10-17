"""#649: independent future-owner minimal-fix oracle in a child interpreter.

This check does not change production source, grant authority, or source owner.
It proves the original 11 RED acceptance checks can actually become GREEN
under a narrowly scoped *in-memory* exact-builtin-string/single-trim repair.
It must never be confused with a production fix or release authorization.
"""
from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHILD_ORACLE = r'''
import os
import sys
import unittest

src, tests = sys.argv[1:]
sys.path[:0] = [src, tests]
os.environ["LIGHTUP_SCOPE649_REQUIRE_SOURCE_FIX"] = "1"

from lightup.domain import DomainStore

original = DomainStore.record_authorization_grant


def fictional_owner_patch(self, actor, engagement_id, approved_by, reference, *args, **kwargs):
    # This is a deliberately *ephemeral test-only* oracle. It is not a
    # verified or reviewed production fix, nor a grant/consent decision.
    if type(approved_by) is not str or type(reference) is not str:
        raise ValueError("fictional fixture rejects noncanonical provenance")
    cleaned_approver = approved_by.strip()
    cleaned_reference = reference.strip()
    if not cleaned_approver or not cleaned_reference:
        raise ValueError("fictional fixture requires nonblank provenance")
    return original(
        self, actor, engagement_id, cleaned_approver, cleaned_reference,
        *args, **kwargs,
    )


DomainStore.record_authorization_grant = fictional_owner_patch

import test_scope_grant_issuance_provenance_649_20261017 as acceptance

suite = unittest.defaultTestLoader.loadTestsFromTestCase(
    acceptance.GrantIssuanceProvenance649
)
runner = unittest.TextTestRunner(verbosity=1, stream=sys.stderr)
result = runner.run(suite)
assert result.testsRun == 18, ("source-oracle discovery drift", result.testsRun)
assert result.wasSuccessful(), "source-owner minimal oracle is not green"
assert not result.expectedFailures, "patched source still carries expected failures"
assert not result.skipped, "patched source suite unexpectedly skipped tests"
assert DomainStore.record_authorization_grant is fictional_owner_patch
print("SCOPE649_EPHEMERAL_FIXTURE_ONLY=18 ordinary PASS; NOT source repair")
'''


class FutureOwnerSourceOracle649(unittest.TestCase):
    def test_all_original_reds_can_be_resolved_with_ephemeral_exact_str_fix(self):
        env = dict(os.environ)
        env.pop("LIGHTUP_SCOPE649_REQUIRE_SOURCE_FIX", None)
        process = subprocess.run(
            [
                sys.executable, "-I", "-S", "-B", "-c", CHILD_ORACLE,
                str(ROOT / "src"), str(ROOT / "tests"),
            ],
            env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            timeout=35, check=False,
        )
        self.assertEqual(
            process.returncode, 0,
            "ephemeral owner-fix fixture failed, last stderr lines:\n"
            + "\n".join(process.stderr.splitlines()[-14:]),
        )
        self.assertIn(
            "SCOPE649_EPHEMERAL_FIXTURE_ONLY=18 ordinary PASS; NOT source repair",
            process.stdout,
        )
        self.assertIn("Ran 18 tests", process.stderr)
        self.assertIn("OK", process.stderr)
        self.assertNotIn("expected failures", process.stderr.lower())

    def test_oracle_is_child_only_and_source_tree_remains_unpatched(self):
        # Test-only wrapper source is local to CHILD_ORACLE, not the installed
        # DomainStore implementation; never patch main interpreter globals.
        from lightup.domain import DomainStore
        self.assertEqual(
            DomainStore.record_authorization_grant.__module__, "lightup.domain"
        )
        self.assertIn(
            "DomainStore.record_authorization_grant = fictional_owner_patch",
            CHILD_ORACLE,
        )
        self.assertNotIn(
            "LIGHTUP_SCOPE649_FIXTURE_ONLY", os.environ,
            "ephemeral review mode may not escape into normal tests",
        )


if __name__ == "__main__":
    unittest.main()
