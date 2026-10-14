"""Opt-in real Nginx -> Gunicorn -> *synthetic* WSGI identity boundary proof.

Runs only disposable services bound to IPv4 loopback on ephemeral ports. Never
launches the LightUp application, issues an actual grant, reads real sessions,
loads live config, changes production Nginx, or touches external targets.

Absent binaries, failed startup, unexpected headers or incomplete tests HOLD.
REVIEW_ONLY proves only this particular disposable fixture, not an installed
proxy deployment or a production security boundary.
"""
from __future__ import annotations

import http.client
import importlib.util
import json
import os
import re
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time

AUTHORITY_FLAGS = (
    "authorization_verified",
    "permit_issued",
    "execution_enabled",
    "merge_approved",
    "release_approved",
)
ALTERNATE_HEADERS = (
    "X-Forwarded-Cookie",
    "X-Original-Cookie",
    "X-Auth-Request-Cookie",
    "Cookie2",
    "Authorization",
    "X-Auth-Request-User",
    "X-Forwarded-User",
    "Remote-User",
)
CASE_NAMES = (
    "anonymous",
    *(f"alternate_{name.lower().replace('-', '_')}" for name in ALTERNATE_HEADERS),
    "alternate_combined",
    "revoked",
    "client",
    "operator_no_csrf",
    "operator_with_csrf",
    "client_portal",
)

# All credentials here are public fixed synthetic test strings, *never* secrets.
SYNTHETIC_OPERATOR = "lightup_session=fixture_operator"
SYNTHETIC_CLIENT = "lightup_session=fixture_client"
SYNTHETIC_REVOKED = "lightup_session=fixture_revoked"
SYNTHETIC_CSRF = b"csrf=fixture_csrf"

# Fixture-only application; never imports the real LightUp application.
FIXTURE_WSGI = '''"""Synthetic no-persistence WSGI endpoint; NEVER a real grant issuer."""
import json

def application(environ, start_response):
    path = environ.get("PATH_INFO", "")
    method = environ.get("REQUEST_METHOD", "")
    cookie = environ.get("HTTP_COOKIE", "")
    identity = (
        "operator" if cookie == "lightup_session=fixture_operator" else
        "client" if cookie == "lightup_session=fixture_client" else
        "anonymous"
    )
    length_text = environ.get("CONTENT_LENGTH", "0")
    try:
        length = int(length_text or "0")
    except (ValueError, TypeError):
        length = -1
    body = environ["wsgi.input"].read(length) if 0 <= length <= 64 else b""
    # No authorization grant is ever created. This is a fake verdict only.
    if path == "/engagements/fixture/grants":
        verdict = (
            "WOULD_ALLOW" if (
                identity == "operator" and method == "POST" and
                body == b"csrf=fixture_csrf"
            ) else "DENIED"
        )
    elif path == "/portal/fixture":
        verdict = "VISIBLE" if identity in {"client", "operator"} else "DENIED"
    else:
        verdict = "DENIED"

    # Deliberately expose only low-cardinality fixture outcomes, not headers.
    forbidden = (
        "HTTP_X_FORWARDED_COOKIE", "HTTP_X_ORIGINAL_COOKIE",
        "HTTP_X_AUTH_REQUEST_COOKIE", "HTTP_COOKIE2", "HTTP_AUTHORIZATION",
        "HTTP_X_AUTH_REQUEST_USER", "HTTP_X_FORWARDED_USER", "HTTP_REMOTE_USER",
    )
    response = {
        "identity": identity,
        "verdict": verdict,
        "untrusted_header_forwarded": any(key in environ for key in forbidden),
        "remote_user_present": "REMOTE_USER" in environ,
        "auth_type_present": "AUTH_TYPE" in environ,
        "written_grants": 0,
        "modified_sessions": 0,
    }
    payload = json.dumps(response, sort_keys=True).encode("ascii")
    start_response("200 OK", [
        ("Content-Type", "application/json"),
        ("Content-Length", str(len(payload))),
        ("Cache-Control", "no-store"),
    ])
    return [payload]
'''


def nginx_config(root: Path, listen_port: int, upstream_port: int) -> str:
    if (type(listen_port) is not int or type(upstream_port) is not int or
            not 1024 <= listen_port <= 65535 or
            not 1024 <= upstream_port <= 65535 or
            listen_port == upstream_port):
        raise ValueError("invalid synthetic port")
    if (not isinstance(root, Path) or not root.is_absolute() or
            re.fullmatch(r"/[A-Za-z0-9_./-]+", str(root)) is None):
        # The pathname becomes an unquoted Nginx 'pid' directive. Never
        # interpolate a TMPDIR with whitespace, semicolons or braces.
        raise ValueError("invalid temporary directory")
    # Path comes solely from TemporaryDirectory and is not user-controlled.
    pid_path = root / "nginx.pid"
    return f"""worker_processes 1;
pid {pid_path};
error_log stderr crit;
events {{ worker_connections 32; }}
http {{
    access_log off;
    server {{
        listen 127.0.0.1:{listen_port};
        server_name localhost;
        client_max_body_size 64;
        location / {{
            proxy_pass http://127.0.0.1:{upstream_port};
            proxy_pass_request_headers off;
            proxy_set_header Host $http_host;
            proxy_set_header Cookie $http_cookie;
            proxy_set_header X-Forwarded-Proto http;
            proxy_set_header X-Forwarded-For $remote_addr;
            proxy_set_header Content-Length $content_length;
            proxy_set_header Content-Type $content_type;
            proxy_connect_timeout 1s;
            proxy_read_timeout 3s;
        }}
    }}
}}
"""



def _fixture_environment(root: Path) -> dict[str, str]:
    """Return a fresh, minimal subprocess environment without inherited hooks.

    Caller-controlled PYTHONPATH, GUNICORN_CMD_ARGS, LD_PRELOAD and shell
    environment must never determine what the disposable worker executes.
    """
    if not isinstance(root, Path) or not root.is_absolute():
        raise ValueError("invalid temporary directory")
    return {
        "HOME": str(root),
        "TMPDIR": str(root),
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C",
        "PYTHONNOUSERSITE": "1",
    }


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        if not 1024 <= port <= 65535:
            raise RuntimeError("invalid local port")
        return port


def _wait_listening(proc: subprocess.Popen, port: int, *, seconds: float = 6.0) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("fixture process stopped")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("fixture did not start")


def _request(
    port: int,
    path: str,
    *,
    method: str = "GET",
    cookie: str | None = None,
    alternates: bool = False,
    alternate_name: str | None = None,
    body: bytes | None = None,
) -> dict:
    if alternate_name is not None and (
        type(alternate_name) is not str or alternate_name not in ALTERNATE_HEADERS
    ):
        raise RuntimeError("unsupported synthetic header")
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3.0)
    try:
        headers = {"Host": "localhost"}
        if cookie is not None:
            headers["Cookie"] = cookie
        if alternates:
            for name in ALTERNATE_HEADERS:
                headers[name] = SYNTHETIC_OPERATOR
        if alternate_name is not None:
            headers[alternate_name] = SYNTHETIC_OPERATOR
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        conn.request(method, path, headers=headers, body=body)
        result = conn.getresponse()
        wire = result.read(4097)
        if result.status != 200 or len(wire) > 4096:
            raise RuntimeError("unexpected synthetic response")
        parsed = json.loads(wire)
        if type(parsed) is not dict:
            raise RuntimeError("invalid synthetic response shape")
        return parsed
    finally:
        conn.close()


def _expected(
    reply: dict,
    identity: str,
    verdict: str,
) -> bool:
    return (
        type(reply) is dict and
        set(reply) == {
            "identity", "verdict", "untrusted_header_forwarded",
            "remote_user_present", "auth_type_present",
            "written_grants", "modified_sessions",
        } and
        type(reply["identity"]) is str and reply["identity"] == identity and
        type(reply["verdict"]) is str and reply["verdict"] == verdict and
        reply["untrusted_header_forwarded"] is False and
        reply["remote_user_present"] is False and
        reply["auth_type_present"] is False and
        type(reply["written_grants"]) is int and reply["written_grants"] == 0 and
        type(reply["modified_sessions"]) is int and reply["modified_sessions"] == 0
    )


def _stop(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)


def run_fixture() -> int:
    nginx = shutil.which("nginx")
    gunicorn = importlib.util.find_spec("gunicorn")
    if nginx is None or gunicorn is None:
        raise RuntimeError("real fixture dependencies not installed")
    with tempfile.TemporaryDirectory(prefix="lightup-local-fixture-") as directory:
        root = Path(directory).resolve()
        (root / "synthetic_identity_app.py").write_text(
            FIXTURE_WSGI, encoding="utf-8"
        )
        app_port = _free_port()
        proxy_port = _free_port()
        if app_port == proxy_port:
            raise RuntimeError("ports collided")
        (root / "nginx.conf").write_text(
            nginx_config(root, proxy_port, app_port), encoding="ascii"
        )
        # The global environment may contain Gunicorn arguments, Python
        # import hooks or dynamic-loader overrides; keep those out of both
        # subprocesses, including the preliminary configuration check.
        fixture_env = _fixture_environment(root)
        # These are *new, exact, disposable* subprocesses; never nginx -s
        # reload, systemctl or any installed nginx configuration.
        check = subprocess.run(
            [nginx, "-t", "-p", str(root) + os.sep, "-c", str(root / "nginx.conf")],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=5, check=False, env=fixture_env,
        )
        if check.returncode != 0:
            raise RuntimeError("disposable nginx configuration invalid")
        services = []
        try:
            services.append(subprocess.Popen(
                [
                    sys.executable, "-m", "gunicorn",
                    "--bind", f"127.0.0.1:{app_port}", "--workers", "1",
                    "--worker-class", "sync", "--chdir", str(root),
                    "--access-logfile", os.devnull,
                    "--error-logfile", os.devnull,
                    "synthetic_identity_app:application",
                ],
                cwd=str(root), env=fixture_env, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            ))
            _wait_listening(services[-1], app_port)
            services.append(subprocess.Popen(
                [nginx, "-p", str(root) + os.sep,
                 "-c", str(root / "nginx.conf"), "-g", "daemon off;"],
                cwd=str(root), env=fixture_env, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            ))
            _wait_listening(services[-1], proxy_port)

            results = (
                ("anonymous", _request(
                    proxy_port, "/engagements/fixture/grants", method="POST",
                    body=SYNTHETIC_CSRF
                ), "anonymous", "DENIED"),
                ("alternate_combined", _request(
                    proxy_port, "/engagements/fixture/grants", method="POST",
                    alternates=True, body=SYNTHETIC_CSRF
                ), "anonymous", "DENIED"),
                ("revoked", _request(
                    proxy_port, "/engagements/fixture/grants", method="POST",
                    cookie=SYNTHETIC_REVOKED, body=SYNTHETIC_CSRF
                ), "anonymous", "DENIED"),
                ("client", _request(
                    proxy_port, "/engagements/fixture/grants", method="POST",
                    cookie=SYNTHETIC_CLIENT, body=SYNTHETIC_CSRF
                ), "client", "DENIED"),
                ("operator_no_csrf", _request(
                    proxy_port, "/engagements/fixture/grants", method="POST",
                    cookie=SYNTHETIC_OPERATOR, body=b"csrf=wrong"
                ), "operator", "DENIED"),
                ("operator_with_csrf", _request(
                    proxy_port, "/engagements/fixture/grants", method="POST",
                    cookie=SYNTHETIC_OPERATOR, body=SYNTHETIC_CSRF
                ), "operator", "WOULD_ALLOW"),
                ("client_portal", _request(
                    proxy_port, "/portal/fixture", cookie=SYNTHETIC_CLIENT
                ), "client", "VISIBLE"),
            )
            individual_spoofs = tuple(
                (
                    f"alternate_{header.lower().replace('-', '_')}",
                    _request(
                        proxy_port, "/engagements/fixture/grants",
                        method="POST", alternate_name=header, body=SYNTHETIC_CSRF,
                    ),
                    "anonymous", "DENIED",
                )
                for header in ALTERNATE_HEADERS
            )
            results += individual_spoofs
            checked = set()
            for name, result, expected_identity, verdict in results:
                if name in checked or not _expected(result, expected_identity, verdict):
                    raise RuntimeError("fixture ingress identity mismatch")
                checked.add(name)
            if checked != set(CASE_NAMES):
                raise RuntimeError("incomplete fixture")
            return len(checked)
        finally:
            for service in reversed(services):
                _stop(service)


def receipt(checked: int) -> dict[str, object]:
    if type(checked) is not int or checked != len(CASE_NAMES):
        checked = 0
    status = "REVIEW_ONLY" if checked else "HOLD"
    return {
        "status": status,
        "diagnostic_code": (
            "LOCAL_SYNTHETIC_FIXTURE_ONLY" if checked
            else "LOCAL_FIXTURE_UNVERIFIED"
        ),
        "verified_cases": checked,
        **{key: False for key in AUTHORITY_FLAGS},
    }


def main(argv: object = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    count = 0
    if type(argv) is list and not argv:
        try:
            count = run_fixture()
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
            pass
    print(json.dumps(receipt(count), sort_keys=True, separators=(",", ":")))
    return 3 if count == len(CASE_NAMES) else 2


if __name__ == "__main__":
    raise SystemExit(main())
