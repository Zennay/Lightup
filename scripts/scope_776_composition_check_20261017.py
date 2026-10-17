"""Offline, fail-closed scope #776 composition of the ORIGINAL source families.

Reads pinned Git objects from the local repository. Does not fetch/network,
write production files, issue actual grants, scan, deploy or produce GO.
The optional --full flag exercises original repo unit/integration fixtures
inside disposable, private filesystem copies only.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
MANIFEST = PROJECT / "manifests/scope-776-three-family-20261017.json"
FIXTURE_PATH = "tests/test_domain.py"
OWNER_SOURCE = "src/lightup/engagements.py"

# Hardcoded allowed Git provenance: manifest values are evidence, not commands.
SOURCE_BLOBS = {
    648: ("db5dc58a422e38ffa886f3a6580527e7047ea0a3",
          "tests/test_scope_immutable_grant_collections_648_20261017.py",
          "5bbc5dd3d5edb30549f761f55785a3862213c7bc"),
    775: ("b0a098e42004e18fe63842bd18d9f481be9c60a2",
          "tests/test_scope_direct_collection_types_775_20261017.py",
          "92c63851175a650b6539df50bef569b341ef8c96"),
}
REFERENCE_773 = (
    "3fd44e97e7f033baf45eef40ea02aa1836c086a3",
    "tests/test_scope_direct_risk_claim_review_773.py",
    "3a71c7f2701b9a6edc31f50ae0390f39bf6b54fc",
)
OWNER_SHA = "4c8d5651fc0e23f94514daae56b4e5fe0549de37"
OWN_FILE = "tests/test_scope_776_composed_identity_20261017.py"
OWN_PATHS = (
    "docs/scope-776-three-family-composition-20261017.md",
    "manifests/scope-776-three-family-20261017.json",
    "scripts/scope_776_composition_check_20261017.py",
    "tests/test_scope_776_composed_identity_20261017.py",
    "tests/test_scope_776_manifest_rules.py",
)
PATTERN = "test_scope_*_20261017.py"

GIT_ENV = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1",
               GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1",
               GIT_OPTIONAL_LOCKS="0")


def git(*args: str) -> bytes:
    done = subprocess.run(
        ["git", "-C", str(PROJECT), *args], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=GIT_ENV, timeout=25, check=False,
    )
    if done.returncode:
        raise RuntimeError("missing_or_inaccessible_pinned_git_object:" + args[0])
    return done.stdout


def blob(commit: str, path: str, checksum: str) -> bytes:
    data = git("cat-file", "-p", commit + ":" + path)
    raw = b"blob " + str(len(data)).encode("ascii") + b"\x00" + data
    if hashlib.sha1(raw).hexdigest() != checksum:
        raise RuntimeError("pinned_source_blob_mismatch:" + path)
    return data


def verify_manifest() -> dict:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if (manifest.get("schema") != "lightup.scope776.composition.v1"
            or manifest.get("pinned_owner_head") != OWNER_SHA
            or manifest.get("own_test") != OWN_FILE
            or manifest.get("expected_total_methods") != 26
            or manifest.get("expected_source_reds") != 18):
        raise RuntimeError("scope776_manifest_shape_or_count_changed")
    for key in ("review_only",):
        if manifest.get(key) is not True:
            raise RuntimeError("scope776_authority_claim")
    for key in ("may_authorize", "may_dispatch", "may_scan",
                "may_deploy", "may_release"):
        if manifest.get(key) is not False:
            raise RuntimeError("scope776_authority_claim:" + key)
    entries = manifest.get("composed_tests")
    if not isinstance(entries, list) or len(entries) != 2:
        raise RuntimeError("scope776_composition_input_count")
    for entry, issue, reds in zip(entries, (648, 775), (6, 7)):
        if (type(entry) is not dict or entry.get("issue") != issue
                or entry.get("source_reds") != reds
                or tuple(entry.get(k) for k in (
                    "source_commit", "path", "git_blob_sha1"
                )) != SOURCE_BLOBS[issue]):
            raise RuntimeError("scope776_composition_source_drift")
    reference = manifest.get("upstream_773_reference_only")
    if (type(reference) is not dict
            or tuple(reference.get(k) for k in (
                "source_commit", "path", "git_blob_sha1"
            )) != REFERENCE_773
            or "do_not_import_or_execute" not in reference.get("policy", "")):
        raise RuntimeError("scope776_external_owner_773_not_fenced")
    git("cat-file", "-e", OWNER_SHA + "^{commit}")
    subprocess.run(["git", "-C", str(PROJECT), "merge-base", "--is-ancestor",
                    OWNER_SHA, "HEAD"], env=GIT_ENV, check=True, timeout=20)
    for c, p, s in (*SOURCE_BLOBS.values(), REFERENCE_773):
        blob(c, p, s)
    # Explicit collision boundary: every change is exactly one new own path.
    expected = {"A\t" + path for path in OWN_PATHS}
    actual = set(git("diff", "--name-status", OWNER_SHA, "HEAD").decode(
        "utf-8", "strict").splitlines())
    if len(actual) != len(OWN_PATHS) or actual != expected:
        raise RuntimeError("scope776_source_or_other_worker_path_changed")
    for path in OWN_PATHS:
        head_entry = git("ls-tree", "HEAD", "--", path).decode("utf-8", "strict")
        original_entry = git("ls-tree", OWNER_SHA, "--", path)
        if not head_entry.startswith("100644 blob ") or original_entry:
            raise RuntimeError("scope776_modified_or_nonregular_path:" + path)
    if git("status", "--porcelain", "--untracked-files=all").strip():
        raise RuntimeError("scope776_git_worktree_not_clean")
    print("scope776_exact_five_additive_owned_paths_and_clean_checkout=PASS")
    print("scope776_pinned_648_775_blobs_and_read_only_773_reference=PASS")
    return manifest


ANCHOR = "    excluded_assets: tuple[str, ...] = ()\n\n    @staticmethod\n"


def local_guard(original: str, variant: str) -> str:
    if original.count(ANCHOR) != 1:
        raise RuntimeError("scope776_owner_source_boundary_changed")
    statement = "    def __post_init__(self) -> None:\n"
    if variant != "no_risk":
        statement += (
            "        if type(self.max_risk) is not RiskLevel:\n"
            "            raise ValueError('scope risk requires exact RiskLevel')\n"
        )
    statement += (
        '        for name in ("assets", "excluded_assets", "allowed_capabilities"):\n'
        "            values = object.__getattribute__(self, name)\n"
        "            if type(values) is not tuple:\n"
        "                raise ValueError('scope collection requires exact tuple')\n"
    )
    if variant != "no_entries":
        statement += (
            "            for item in values:\n"
            "                if type(item) is not str:\n"
            "                    raise ValueError('scope entry requires exact str')\n"
        )
    return original.replace(ANCHOR,
                            "    excluded_assets: tuple[str, ...] = ()\n\n"
                            + statement + "\n    @staticmethod\n")


OLD_FIXTURE = (
    '            ScopeDefinition(\n'
    '                assets=("app.acme.example",),\n'
    '                max_risk=5,  # type: ignore[arg-type]\n'
    '                allowed_capabilities=("web-baseline",),\n'
    '            ),\n'
)
FIXTURE_ANCHOR = "        for index, scope in enumerate(invalid_scopes):\n"
NEW_FIXTURE = (
    '        # #776 disposable migration: constructor rejects malformed risk.\n'
    '        with self.assertRaises(ValueError):\n'
    '            ScopeDefinition(assets=("app.acme.example",), max_risk=5,\n'
    '                            allowed_capabilities=("web-baseline",))\n'
)


def migrate_disposable_fixture(path: Path) -> None:
    content = path.read_text(encoding="utf-8")
    if content.count(OLD_FIXTURE) != 1 or content.count(FIXTURE_ANCHOR) != 1:
        raise RuntimeError("scope776_existing_fixture_migration_not_unique")
    path.write_text(
        content.replace(OLD_FIXTURE, "").replace(
            FIXTURE_ANCHOR, NEW_FIXTURE + FIXTURE_ANCHOR
        ), encoding="utf-8",
    )


def run_unittest(dest: Path, strict: bool, pattern: str, extra: tuple[str, ...] = ()):
    search_path = str(dest / "src")
    if extra:
        search_path += os.pathsep + str(dest / "tests")
    env = dict(os.environ, PYTHONPATH=search_path,
               PYTHONDONTWRITEBYTECODE="1",
               LIGHTUP_SCOPE648_REQUIRE_SOURCE_FIX="1" if strict else "0",
               LIGHTUP_SCOPE775_REQUIRE_SOURCE_FIX="1" if strict else "0",
               LIGHTUP_SCOPE776_REQUIRE_SOURCE_FIX="1" if strict else "0")
    cmd = [sys.executable, "-B", "-m", "unittest", "discover",
           "-s", "tests" if not extra else extra[0], "-p", pattern, "-q"]
    result = subprocess.run(cmd, cwd=dest, env=env, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            timeout=150, check=False)
    return result.returncode, result.stdout


def verify_result(label: str, code: int, output: str, *, strict: bool,
                  expected_count: int = 26) -> None:
    if not re.search(r"(?m)^Ran " + str(expected_count) + r" tests in ", output):
        raise RuntimeError(label + ":test_discovery_count_drift")
    if strict:
        if code or re.search(r"(?m)^OK \(expected failures=", output):
            raise RuntimeError(label + ":strict_failure:" + output[-950:])
        if not re.search(r"(?m)^OK$", output):
            raise RuntimeError(label + ":strict_result_unknown")
    else:
        if code or "OK (expected failures=18)" not in output:
            raise RuntimeError(label + ":original_source_red_count_drift:" + output[-950:])
    print(label + "=PASS")


def verify_original_strict_red_identities(root: Path, code: int,
                                          output: str) -> None:
    # Every source RED is independently named in owner-pinned files; strict
    # unittest emits separate headers for each failing subTest variant.
    expected_methods = set()
    for path in (
        OWN_FILE,
        SOURCE_BLOBS[648][1],
        SOURCE_BLOBS[775][1],
    ):
        contents = (root / path).read_text(encoding="utf-8")
        tree = ast.parse(contents, filename=path)
        names = {
            node.name for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name.startswith("test_source_red_")
        }
        if not names or expected_methods.intersection(names):
            raise RuntimeError("scope776_original_red_method_manifest_collision")
        expected_methods.update(names)
    if len(expected_methods) != 18:
        raise RuntimeError("scope776_original_red_method_count_changed")

    observed = Counter(
        name for kind, name in re.findall(
            r"(?m)^(FAIL|ERROR): (test_source_red_[a-z0-9_]+) \\(", output
        )
    )
    expected = Counter({name: 1 for name in expected_methods})
    expected["test_source_red_all_three_invalid_dimensions_rejected_at_construction"] = 3
    expected["test_source_red_bool_risk_is_not_an_enum_even_if_equal"] = 7
    if (code == 0 or observed != expected
            or not re.search(r"(?m)^Ran 26 tests in ", output)
            or "FAILED (failures=26)" not in output
            or re.search(r"(?m)^ERROR: ", output)):
        raise RuntimeError("scope776_original_strict_source_RED_identity_or_cause_drift")
    print("scope776_original_exact_18_source_RED_methods_26_failing_subcases=PASS")


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline #776 held source composition")
    parser.add_argument("--full", action="store_true",
                        help="Also run original complete unit and localhost integration")
    args = parser.parse_args()
    verify_manifest()
    with tempfile.TemporaryDirectory(prefix="lightup_scope776_") as temp:
        root = Path(temp)
        shutil.copytree(PROJECT / "src", root / "src")
        shutil.copytree(PROJECT / "tests", root / "tests")
        # Whole-suite provenance self-tests import this opt-in, pure offline script.
        shutil.copytree(PROJECT / "scripts", root / "scripts")
        shutil.copytree(PROJECT / "manifests", root / "manifests")
        # Original unit fixtures resolve repository-relative example config.
        if args.full:
            shutil.copytree(PROJECT / "config", root / "config")
        for commit, path, checksum in SOURCE_BLOBS.values():
            target = root / path
            if target.exists():
                raise RuntimeError("scope776_test_path_collision:" + path)
            target.write_bytes(blob(commit, path, checksum))
        if not (root / OWN_FILE).is_file():
            raise RuntimeError("scope776_own_composition_module_missing")
        code, output = run_unittest(root, False, PATTERN)
        verify_result("scope776_original_26_with_18_expected_source_RED",
                      code, output, strict=False)
        strict_code, strict_out = run_unittest(root, True, PATTERN)
        verify_original_strict_red_identities(root, strict_code, strict_out)

        owner = root / OWNER_SOURCE
        source = owner.read_text(encoding="utf-8")
        for variant in ("no_risk", "no_entries", "exact"):
            owner.write_text(local_guard(source, variant), encoding="utf-8")
            code, output = run_unittest(root, True, PATTERN)
            if variant == "exact":
                verify_result("scope776_disposable_exact_three_way_26_strict_GREEN",
                              code, output, strict=True)
                if args.full:
                    migrate_disposable_fixture(root / FIXTURE_PATH)
                    unit_code, unit_out = run_unittest(root, True, "test*.py")
                    if unit_code or not re.search(r"(?m)^OK$", unit_out):
                        raise RuntimeError("scope776_full_unit_regression:" + unit_out[-1400:])
                    print("scope776_full_disposable_units=" +
                          re.search(r"(?m)^Ran (\d+) tests in ", unit_out).group(1) +
                          "_PASS")
                    integration_code, integration_out = run_unittest(
                        root, True, "test*.py", extra=("tests/integration",))
                    if integration_code or not re.search(r"(?m)^OK$", integration_out):
                        raise RuntimeError("scope776_full_integration_regression:" +
                                           integration_out[-1400:])
                    print("scope776_full_local_integration=" +
                          re.search(r"(?m)^Ran (\d+) tests in ", integration_out).group(1) +
                          "_PASS")
            else:
                if code == 0:
                    raise RuntimeError("scope776_weak_guard_unexpected_GREEN:" + variant)
                expected = (
                    "test_source_red_bool_risk_is_not_an_enum_even_if_equal"
                    if variant == "no_risk"
                    else "test_source_red_asset_str_subclass_cannot_spoof_strip"
                )
                if expected not in output:
                    raise RuntimeError("scope776_weak_guard_wrong_RED:" + variant)
                print("scope776_deliberately_incomplete_" + variant + "=RED_EXPECTED")
    print("scope776_no_source_owner_modification_or_release=HOLD")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
        print("scope776_FAIL_CLOSED:" + str(exc), file=sys.stderr)
        raise SystemExit(2)
