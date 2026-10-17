"""Offline, HOLD-only compatibility rehearsal for LightUp scope issue #686.

Composes *pinned* bytes from existing owner commits in a disposable checkout.
It never fetches, pushes, merges, grants authority or edits the source checkout.
NOT a supply-chain proof, deployed entrypoint, or approval to run active scans.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

_SHA = re.compile(r"[0-9a-f]{40}\Z")
# Exact independent owner source commits; never resolve moving branch names.
_OWNER = (
    ("tests/test_scope_legacy_falsy_window_301_red_20261014.py",
     "89c7973a330550cd5b8fad23abb54e4a81f85639",
     "f04d2e7fac403476e1d3b5cc08b5d9aa293ac0a2"),
    ("src/lightup/webapp/app.py",
     "8c97eb0490bc0d5d1bfdb883c9d1434f6b21749c",
     "3912fbaa31ffd30542ea546c048fe2910c0d9a33"),
    ("src/lightup/webapp/session_cookie_guard.py",
     "31055e7f5de9046405afea14bc945feb8f21d8be",
     "272ee4394457f539477f689e5561e7107f8d5db9"),
    # Existing #1536 owner correction; one warning-safe source line, no
    # altered I/O sandbox. Needed by original Python3.14 native-I/O fleet.
    ("src/lightup/capability_registry_history_report.py",
     "f8b91596d48f318cb75050b70ccbf5a50d2cd106",
     "9626d0a41bf44430c27b6a67d11fa509e6ff2b1e"),
)


# Contract-specific coverage floor and deliberate RED inventory. A changing
# test inventory is a review event, not implicit promotion to compatibility.
_EXPECTED = {
    "scope686": (23, 13),
    "webapp": (23, 0),
    "integration": (86, 0),
    "full_unittest": (1297, 46),
}


class CompositionHold(Exception):
    """No trust or compatibility claim may be made."""


def _git(repo: Path, *args: str, input_bytes: bytes | None = None) -> bytes:
    env = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1", GIT_OPTIONAL_LOCKS="0",
               GIT_TERMINAL_PROMPT="0")
    result = subprocess.run(
        ["git", "-C", str(repo), *args], input=input_bytes,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=30,
        check=False)
    if result.returncode:
        # Do not echo paths, credentials or stderr from a possibly malicious repo.
        raise CompositionHold("unavailable pinned git object or unsafe checkout")
    return result.stdout


def _sha(value: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise CompositionHold("expected an exact lowercase 40-character commit SHA")
    return value


def _blob_oid(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def _owner_blob(repo: Path, path: str, commit: str, blob: str) -> bytes:
    _sha(commit)
    _sha(blob)
    if Path(path).is_absolute() or ".." in Path(path).parts or "\\" in path:
        raise CompositionHold("noncanonical owner path")
    # Reject Git link/submodule modes. Commit names are exact pinned OIDs.
    tree = _git(repo, "ls-tree", commit, "--", path)
    expected = f"100644 blob {blob}\t{path}\n".encode("utf-8")
    if tree != expected:
        raise CompositionHold("owner tree entry changed or absent: " + path)
    data = _git(repo, "show", commit + ":" + path)
    if _blob_oid(data) != blob:
        raise CompositionHold("owner blob content mismatch: " + path)
    return data


def _run_tests(checkout: Path, label: str, args: list[str]) -> dict:
    env = dict(os.environ)
    env["PYTHONPATH"] = "src" + os.pathsep + "tests"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    # All steps run in an ephemeral local clone; no target execution is requested.
    try:
        p = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", *args],
            cwd=checkout, env=env, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=100, check=False)
    except subprocess.TimeoutExpired as exc:
        raise CompositionHold("offline test timeout: " + label) from exc
    combined = (p.stdout + b"\n" + p.stderr).decode("utf-8", errors="replace")
    match = re.search(r"Ran (\d+) tests in", combined)
    expected = re.search(r"expected failures=(\d+)", combined)
    if p.returncode or not match or not re.search(r"\nOK(?: \(|\s*$)", combined):
        names = list(dict.fromkeys(re.findall(
            r"^(?:FAIL|ERROR): (test_[A-Za-z0-9_]+)", combined, re.MULTILINE)))[:4]
        # Exception names only: no exception values, request bodies or paths.
        hint = " affected=" + ",".join(names) if names else ""
        raise CompositionHold("offline tests failed: " + label + hint)
    count = int(match.group(1))
    red_count = int(expected.group(1)) if expected else 0
    floor = _EXPECTED.get(label)
    if floor is not None and (count < floor[0] or red_count != floor[1]):
        raise CompositionHold("test coverage/RED inventory drift: " + label)
    return {
        "name": label, "outcome": "PASS", "methods": count,
        "expected_source_failures": red_count,
    }


def _probe_guard(checkout: Path) -> dict:
    env = dict(os.environ, PYTHONPATH="src", PYTHONDONTWRITEBYTECODE="1")
    try:
        result = subprocess.run(
            [sys.executable, "scripts/scope_686_guard_probe_offline.py"],
            cwd=checkout, env=env, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=30, check=False)
    except subprocess.TimeoutExpired as exc:
        raise CompositionHold("opt-in guard probe timed out") from exc
    if result.returncode:
        raise CompositionHold("real opt-in guard probe failed")
    try:
        receipt = json.loads(result.stdout)
    except (UnicodeDecodeError, ValueError) as exc:
        raise CompositionHold("invalid guard probe receipt") from exc
    if (not isinstance(receipt, dict)
            or receipt.get("status") != "HOLD"
            or receipt.get("release_authorized") is not False
            or receipt.get("candidate_compatibility") != "PASS"
            or receipt.get("duplicates_denied_prebody") != 9
            or receipt.get("public_login_denied_prebody") is not True
            or receipt.get("single_session_controls_passed") != 3
            or receipt.get("session_lookup_or_write_before_denial") is not False
            or receipt.get("real_target_io_performed") is not False):
        raise CompositionHold("unsafe or incomplete guard probe claims")
    return receipt



def _probe_mutants(checkout: Path, optimization: str) -> dict:
    if optimization not in {"-O", "-OO"}:
        raise CompositionHold("unsupported python optimization check")
    env = dict(os.environ, PYTHONPATH="src", PYTHONDONTWRITEBYTECODE="1")
    try:
        p = subprocess.run(
            [sys.executable, optimization,
             "scripts/scope_686_guard_mutants_offline.py"],
            cwd=checkout, env=env, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=35, check=False)
    except subprocess.TimeoutExpired as exc:
        raise CompositionHold("opt-in mutant proof timeout") from exc
    if p.returncode:
        raise CompositionHold("opt-in guard mutation falsely accepted or failed")
    try:
        receipt = json.loads(p.stdout)
    except (UnicodeDecodeError, ValueError) as exc:
        raise CompositionHold("invalid guard mutation receipt") from exc
    if (not isinstance(receipt, dict)
            or receipt.get("status") != "HOLD"
            or receipt.get("release_authorized") is not False
            or receipt.get("candidate_mutant_coverage") != "PASS"
            or receipt.get("mutants_rejected") != 7
            or receipt.get("mutation_labels") != [
                "guard_removed", "body_read_early", "body_readline_early",
                "body_readinto_early", "body_getvalue_early",
                "body_iterator_early", "session_cookie_mutation"]
            or receipt.get("real_target_io_performed") is not False):
        raise CompositionHold("unsafe or incomplete guard mutation receipt")
    return {"python_optimization": optimization, "receipt": receipt}


def verify(source: Path, head: str, mode: str) -> dict:
    """Return a non-authorizing result. Raises CompositionHold on any uncertainty."""
    head = _sha(head)
    if mode not in {"smoke", "full"}:
        raise CompositionHold("unsupported test mode")
    source = source.resolve(strict=True)
    if _git(source, "rev-parse", "--show-toplevel").strip() != os.fsencode(str(source)):
        raise CompositionHold("source must be the repository root")
    if _git(source, "rev-parse", "HEAD").decode().strip() != head:
        raise CompositionHold("source HEAD differs from requested exact commit")
    if _git(source, "status", "--porcelain=v1", "--untracked-files=all"):
        raise CompositionHold("source checkout is not clean")
    # Verify all bytes and pin them *before* creating a disposable checkout.
    blobs = [(p, _owner_blob(source, p, commit, blob))
             for p, commit, blob in _OWNER]
    with tempfile.TemporaryDirectory(prefix="lightup-686-hold-") as temp:
        dest = Path(temp) / "checkout"
        subprocess.run(
            ["git", "clone", "--local", "--no-hardlinks", "--quiet",
             "--no-checkout", "--", str(source), str(dest)],
            check=True, timeout=45, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=dict(os.environ, GIT_NO_REPLACE_OBJECTS="1",
                     GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0"))
        _git(dest, "checkout", "--quiet", "--detach", head)
        for path, data in blobs:
            target = dest / path
            if target.is_symlink() or not target.parent.is_dir():
                raise CompositionHold("unexpected destination type: " + path)
            target.write_bytes(data)
        # Ensure the owner's original bytes survived the local composition.
        for path, data in blobs:
            if (dest / path).read_bytes() != data:
                raise CompositionHold("composed owner bytes changed: " + path)
        if mode == "smoke":
            cases = [
                ("scope686", ["-s", "tests", "-p", "test_scope_686_duplicate_session_cookies.py", "-q"]),
                ("webapp", ["-s", "tests", "-p", "test_webapp.py", "-q"]),
                ("integration", ["-s", "tests/integration", "-q"]),
            ]
        else:
            cases = [
                ("full_unittest", ["-s", "tests", "-q"]),
                ("integration", ["-s", "tests/integration", "-q"]),
            ]
        results = [_run_tests(dest, label, argv) for label, argv in cases]
        guard_probe = _probe_guard(dest)
        mutant_checks = [_probe_mutants(dest, mode) for mode in ("-O", "-OO")]
        return {
            "status": "HOLD", "release_authorized": False,
            "real_target_interaction_authorized": False,
            "candidate_compatibility": "PASS", "source_head": head,
            "owner_sources": [
                {"path": path, "commit": commit, "blob": blob}
                for path, commit, blob in _OWNER
            ],
            "test_mode": mode, "checks": results, "guard_probe": guard_probe,
            "optimized_mutant_checks": mutant_checks,
            "limitations": "Disposable local owner composition, not exact-release-head hosted/permanent-VPS CI or deployed ingress proof.",
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Non-authorizing owner compatibility proof (#686)")
    parser.add_argument("--source", type=Path, default=Path.cwd())
    parser.add_argument("--head", required=True)
    parser.add_argument("--mode", choices=["smoke", "full"], default="smoke")
    args = parser.parse_args(argv)
    try:
        receipt = verify(args.source, args.head, args.mode)
        code = 0
    except (CompositionHold, OSError, subprocess.SubprocessError, ValueError) as exc:
        receipt = {
            "status": "HOLD", "release_authorized": False,
            "real_target_interaction_authorized": False,
            "candidate_compatibility": "FAIL",
            "reason": str(exc) if isinstance(exc, CompositionHold)
                      else "verification failed closed",
        }
        code = 2
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
