"""Hermetic source-owner fix oracle for #829 (no production-file commits).

Runs the REAL issue #829 SQLite acceptance suite against disposable byte copies
of the owner source. The baseline must stay strictly red, an exact-row-owner
query must be green, and plausible weaker "fixes" must remain strictly red.

This is evidence for the source owner, NEVER an authorization to grant, scan,
dispatch, merge, deploy or release. Only local files/temporary SQLite are used.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "lightup" / "domain.py"
REAL_TESTS = ROOT / "tests" / "test_scope_829_grant_tenant_read_integrity_20261017.py"

QUERY = (
    '"SELECT * FROM authorization_grants WHERE engagement_id=? ORDER BY created_at DESC",\n'
    '                (engagement.engagement_id,),'
)
OWNER_FILTER = (
    '"SELECT * FROM authorization_grants WHERE engagement_id=? AND client_id=? ORDER BY created_at DESC",\n'
    '                (engagement.engagement_id, engagement.client_id),'
)
TRIM_FILTER = (
    '"SELECT * FROM authorization_grants WHERE engagement_id=? AND TRIM(client_id)=? ORDER BY created_at DESC",\n'
    '                (engagement.engagement_id, engagement.client_id),'
)
EARLY_LIMIT = (
    '"SELECT * FROM authorization_grants WHERE engagement_id=? AND client_id=? ORDER BY created_at DESC LIMIT 1",\n'
    '                (engagement.engagement_id, engagement.client_id),'
)
CURRENT_ONLY = (
    "if grant.client_id == self.get_engagement(ctx, engagement_id).client_id "
    "and grant.is_current(now):"
)

# Run the original real test methods without unittest.expectedFailure wrappers.
# The child runs Python isolated (-I), with only the copied package explicitly
# placed on sys.path. No root package or site-installed replacement is trusted.
_CHILD = r"""
import importlib.util
import io
import json
import sys
import unittest
sys.path.insert(0, sys.argv[1])
spec = importlib.util.spec_from_file_location("scope_829_real", sys.argv[2])
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
case = mod.GrantTenantReadIntegrity829
for name in dir(case):
    if name.startswith("test_source_red_"):
        getattr(case, name).__unittest_expecting_failure__ = False
suite = unittest.defaultTestLoader.loadTestsFromTestCase(case)
result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)
print(json.dumps({
    "count": result.testsRun,
    "failures": [str(case) for case, _ in result.failures],
    "errors": [str(case) for case, _ in result.errors],
    "skipped": len(result.skipped),
    "unexpected_success": len(result.unexpectedSuccesses),
    "expected_failure": len(result.expectedFailures),
}, sort_keys=True))
"""


def _run_source_variant(variant: str) -> dict:
    """Return strict real-SQLite result for a disposable source copy."""
    if not REAL_TESTS.is_file():
        raise AssertionError("missing original source acceptance tests")
    raw = SRC.read_text(encoding="utf-8")
    if raw.count(QUERY) != 1:
        raise AssertionError("source-owner read-query anchor drift: fail closed")
    if variant == "original":
        patched = raw
    elif variant == "correct":
        patched = raw.replace(QUERY, OWNER_FILTER)
    elif variant == "trim":
        patched = raw.replace(QUERY, TRIM_FILTER)
    elif variant == "limit":
        patched = raw.replace(QUERY, EARLY_LIMIT)
    elif variant == "current_only":
        guard = "if grant.is_current(now):"
        if raw.count(guard) != 1:
            raise AssertionError("get_current_grant source anchor drift")
        patched = raw.replace(guard, CURRENT_ONLY)
    else:
        raise ValueError("unknown oracle variant")

    with tempfile.TemporaryDirectory(prefix="scope-829-owner-proof-") as tmp:
        tmp_root = Path(tmp)
        package = tmp_root / "src" / "lightup"
        shutil.copytree(ROOT / "src" / "lightup", package)
        (package / "domain.py").write_text(patched, encoding="utf-8")
        # Test module comes from source-owned, read-only original checkout and
        # points exclusively to the temporary copied domain implementation.
        proc = subprocess.run(
            [
                sys.executable, "-I", "-c", _CHILD,
                str(tmp_root / "src"), str(REAL_TESTS),
            ],
            cwd=tmp_root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=25,
            check=False,
            env={"PYTHONDONTWRITEBYTECODE": "1"},
        )
        if proc.returncode != 0:
            raise AssertionError(
                f"{variant} child failed ({proc.returncode}): "
                f"{proc.stderr[-1600:]}"
            )
        try:
            result = json.loads(proc.stdout)
        except ValueError as exc:
            raise AssertionError(
                f"{variant} malformed child receipt: {proc.stdout[:300]}"
            ) from exc
        assert set(result) == {
            "count", "failures", "errors", "skipped",
            "unexpected_success", "expected_failure",
        }
        assert result["count"] == 18, (variant, result)
        assert result["skipped"] == 0 and result["expected_failure"] == 0
        assert result["unexpected_success"] == 0
        return result


class Scope829OwnerRepairOracle(unittest.TestCase):
    def test_original_source_has_twelve_strict_reds(self):
        result = _run_source_variant("original")
        self.assertEqual(len(result["failures"]) + len(result["errors"]), 12)

    def test_exact_tenant_owner_filter_fixes_all_real_cases(self):
        result = _run_source_variant("correct")
        self.assertEqual(result["failures"], [])
        self.assertEqual(result["errors"], [])

    def test_trimming_opaque_tenant_ids_is_not_sufficient(self):
        result = _run_source_variant("trim")
        self.assertGreater(len(result["failures"]) + len(result["errors"]), 0)

    def test_only_latest_authorization_grant_is_not_sufficient(self):
        result = _run_source_variant("limit")
        self.assertGreater(len(result["failures"]) + len(result["errors"]), 0)

    def test_filtering_only_get_current_grant_does_not_fix_list_reads(self):
        result = _run_source_variant("current_only")
        self.assertGreater(len(result["failures"]) + len(result["errors"]), 0)


if __name__ == "__main__":
    unittest.main()
