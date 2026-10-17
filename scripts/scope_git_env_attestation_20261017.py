#!/usr/bin/env python3
"""Unwired read-only Git environment evidence. NEVER an authorization gate.

REVIEW_ONLY exit 2, HOLD exit 3; always false authority fields.
No Git commands, dynamic imports, network, writes or secret echoes.
"""
from __future__ import annotations

import json
import os
import re
import sys
from collections.abc import Mapping


def _receipt(status: str) -> dict[str, bool | str]:
    return {
        "status": status, "authorized": False, "consent_verified": False,
        "dispatch_allowed": False, "release_allowed": False,
    }


# Conservative runtime-loader interference list; no value inspection.
# The interpreter/loader may already have processed these by script start,
# so the result is only a NEGATIVE attestation, never process integrity proof.
_HOST_RUNTIME_OVERRIDES = frozenset({
    "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "LD_DEBUG",
    "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
    "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONINSPECT",
})


def _expected_hosted_toolcache_path(environment: Mapping, value: str) -> bool:
    """Only match an EXACT hosted setup-python path, never grant trust."""
    root = environment.get("pythonLocation")
    return (
        type(root) is str
        and re.fullmatch(r"/opt/hostedtoolcache/Python/3\.(?:11|14)\.[0-9]+/x64", root) is not None
        and environment.get("Python_ROOT_DIR") == root
        and value == root + "/lib"
        and environment.get("GITHUB_ACTIONS") == "true"
        and environment.get("GITHUB_EVENT_NAME") == "push"
        and environment.get("GITHUB_REF")
        == "refs/heads/chatgpt/scope-auth-git-env-fence-20261017-0115"
        and type(environment.get("GITHUB_SHA")) is str
        and re.fullmatch(r"[0-9a-f]{40}", environment["GITHUB_SHA"]) is not None
        and environment.get("RUNNER_OS") == "Linux"
    )


def review_environment(environment: object) -> dict[str, bool | str]:
    """HOLD on any Git override, even an empty or unknown future GIT_* key.

    A clean result attests only that no Git-prefixed environment was passed;
    it never proves repository provenance, safe PATH, or consent.
    """
    # Arbitrary Mapping/.items() implementations may suppress GIT_* keys.
    # Accept only an exact inert dict snapshot or the actual os.environ.
    # Subclassed dict and custom Mapping objects cannot supply proof.
    if type(environment) is not dict and environment is not os.environ:
        return _receipt("HOLD")
    try:
        for count, (key, value) in enumerate(environment.items(), 1):
            if count > 512 or type(key) is not str or type(value) is not str:
                return _receipt("HOLD")
            if len(key) > 4096 or len(value) > 8192:
                return _receipt("HOLD")
            if key == "LD_LIBRARY_PATH" and _expected_hosted_toolcache_path(environment, value):
                # setup-python's exact GitHub-hosted toolcache lib search path.
                # This is a read-only string profile, NOT library provenance.
                continue
            if key.startswith("GIT_") or key in _HOST_RUNTIME_OVERRIDES:
                return _receipt("HOLD")
    except Exception:
        # A hostile custom Mapping must not turn a bad environment into
        # a traceback or an accidental REVIEW_ONLY approval marker.
        return _receipt("HOLD")
    return _receipt("REVIEW_ONLY")


def main() -> int:
    status = "HOLD" if len(sys.argv) != 1 else review_environment(os.environ)["status"]
    # Fixed output; never echo environment values or give exit 0.
    sys.stdout.write(json.dumps(_receipt(status), separators=(",", ":")) + "\n")
    return 2 if status == "REVIEW_ONLY" else 3


if __name__ == "__main__":
    raise SystemExit(main())
