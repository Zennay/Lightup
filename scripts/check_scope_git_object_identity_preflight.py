"""Read-only offline Git replacement/graft refusal; never a trusted authorization."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    clean_env = {key: value for key, value in os.environ.items()
                 if not key.startswith("GIT_")}
    clean_env.update({
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
    })
    try:
        result = subprocess.run(("git", *args), cwd=repo, env=clean_env,
                                capture_output=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return subprocess.CompletedProcess(("git", *args), 126, b"", b"")
    if len(result.stdout) > 4096:
        return subprocess.CompletedProcess(result.args, 126, b"", b"")
    return result


def inspect(repo: Path) -> str:
    """Only a negative admission hint; never attest to trust or release."""
    if not repo.is_dir():
        return "INVALID_REPOSITORY"
    root = _git(repo, "rev-parse", "--show-toplevel")
    if root.returncode or not root.stdout.strip():
        return "INVALID_REPOSITORY_ROOT"
    try:
        actual = Path(os.fsdecode(root.stdout.strip())).resolve(strict=True)
        requested = repo.resolve(strict=True)
    except (OSError, ValueError):
        return "INVALID_REPOSITORY_ROOT"
    if actual != requested:
        return "INVALID_REPOSITORY_ROOT"
    replacements = _git(repo, "for-each-ref", "--count=1", "--format=%(refname)",
                        "refs/replace")
    if replacements.returncode:
        return "REPLACE_REF_CHECK_UNAVAILABLE"
    if replacements.stdout:
        return "LOCAL_REPLACE_REF_PRESENT"
    # --git-path info/grafts dereferences symlinks before returning a path;
    # querying the raw common-dir lets lstat catch even a dangling graft link.
    common = _git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir")
    if common.returncode or not common.stdout.strip():
        return "GRAFT_PATH_UNAVAILABLE"
    try:
        common_dir = Path(os.fsdecode(common.stdout.strip()))
        if not common_dir.is_absolute():
            return "GRAFT_PATH_UNAVAILABLE"
        graft = common_dir / "info" / "grafts"
        graft.lstat()
    except FileNotFoundError:
        pass
    except (OSError, ValueError):
        return "GRAFT_PATH_UNAVAILABLE"
    else:
        return "LEGACY_GRAFT_PRESENT"
    return "NO_LOCAL_GIT_SUBSTITUTION_OBSERVED"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path("."))
    args = parser.parse_args(argv)
    reason = inspect(args.repo)
    ok = reason == "NO_LOCAL_GIT_SUBSTITUTION_OBSERVED"
    print(json.dumps({
        "status": "REVIEW_ONLY" if ok else "HOLD", "reason": reason,
        "authorization_verified": False, "permit_issued": False,
        "execution_enabled": False, "merge_approved": False,
        "release_approved": False,
    }, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
