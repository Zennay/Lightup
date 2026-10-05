"""Offline activation/authentication canaries with per-invocation state.

Safe to repeat or run concurrently on a persistent self-hosted runner.
Requires PYTHONPATH=src. Does not open a listening socket or contact a target.
"""
from __future__ import annotations

import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from lightup.domain import DomainStore
from lightup.webapp import create_app
from lightup.webapp.__main__ import _loopback


def main() -> None:
    denied = subprocess.run(
        [sys.executable, "-m", "lightup.cli", "scope-check", "8.8.8.8"],
        capture_output=True, text=True, check=False,
    )
    assert denied.returncode == 2, (denied.returncode, denied.stdout, denied.stderr)
    assert json.loads(denied.stdout)["allowed"] is False
    plan = subprocess.run(
        [sys.executable, "-m", "lightup.cli", "plan", "127.0.0.1"],
        capture_output=True, text=True, check=True,
    )
    assert json.loads(plan.stdout)["execution_enabled"] is False

    with tempfile.TemporaryDirectory(prefix="lightup-ci-") as directory:
        store = DomainStore(Path(directory) / "web.db")
        app = create_app(store)

        def get(path: str, cookie: str | None = None):
            env = {
                "REQUEST_METHOD": "GET", "PATH_INFO": path,
                "wsgi.input": io.BytesIO(b""),
            }
            if cookie is not None:
                env["HTTP_COOKIE"] = cookie
            response = {}
            body = b"".join(app(
                env, lambda status, headers: response.update(
                    status=status, headers=dict(headers)
                )
            )).decode()
            return response["status"], response["headers"], body

        status, headers, _ = get("/")
        assert status == "303 See Other" and headers["Location"] == "/login"
        user = store.bootstrap_operator("ci@lightup.test", "CI", "ci-canary-password")
        token, _csrf = store.create_session(user.user_id)
        status, _, body = get("/", cookie=f"lightup_session={token}")
        assert status == "200 OK", status
        assert "Locked" in body and "no real-target execution path" in body

        try:
            _loopback("0.0.0.0")
        except Exception:
            pass
        else:
            raise AssertionError("web shell accepted a non-loopback bind")

    assert not Path(directory).exists(), "canary state was not cleaned up"
    print(json.dumps({
        "public_target_denied": True, "execution_enabled": False,
        "authentication_required": True, "activation_locked": True,
        "non_loopback_refused": True, "temporary_state_removed": True,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
