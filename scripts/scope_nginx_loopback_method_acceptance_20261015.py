"""Opt-in, localhost-only Nginx -> WSGI method integrity acceptance for #1154.

This is an *offline lab receipt*, never trusted scope, approval, or release
evidence.  It does not inspect or modify an installed Nginx service.
"""
from __future__ import annotations

import http.client
import json
import os
import re
import stat
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

TEMPLATE = Path(__file__).resolve().parents[1] / "deploy" / "nginx.conf.example"
OVERRIDE_NAMES = (
    "X-HTTP-Method-Override",
    "X-Method-Override",
    "X-Original-Method",
    "X-HTTP-Method",
)
FALSE_FLAGS = {
    "authorizes_targets": False,
    "authorizes_grants": False,
    "authorizes_scans": False,
    "authorizes_dispatch": False,
    "authorizes_merge": False,
    "authorizes_deploy": False,
}


def _replace_one(text: str, old: str, new: str) -> str:
    if text.count(old) != 1:
        raise ValueError("unsupported nginx template shape")
    return text.replace(old, new)


def render_loopback_config(template: str, frontend: int, backend: int, root: Path,
                           *, force_rewrite: bool = False) -> str:
    """Only relocate the checked example to disposable *loopback* ports.

    Never accept an arbitrary upstream or preserve TLS certificate paths from the
    real service. The production example is not rewritten on disk.
    """
    if not (0 < frontend < 65536 and 0 < backend < 65536):
        raise ValueError("invalid port")
    if type(template) is not str or len(template) > 65536:
        raise ValueError("invalid template")
    expected = (
        "    listen 443 ssl;",
        "    proxy_pass http://127.0.0.1:8766;",
        "    server_name lightup.example.com;",
    )
    if any(template.count(item) != 1 for item in expected):
        raise ValueError("unsupported nginx template shape")
    # Reject extra upstreams, socket binds or method rewriting in source input.
    uncommented = "\n".join(line.split("#", 1)[0] for line in template.splitlines())
    if len(re.findall(r"\blisten\s+", uncommented)) != 1:
        raise ValueError("unexpected listener")
    if len(re.findall(r"\bproxy_pass\s+", uncommented)) != 1:
        raise ValueError("unexpected upstream")
    if re.search(r"\b(?:proxy_method|include|rewrite|return|error_page)\s+", uncommented):
        raise ValueError("unexpected server directive")
    # Closed-world source: never carry an unreviewed Nginx directive into a
    # runnable fixture. Otherwise 'mirror', 'auth_request', additional
    # locations or a nested remote egress could bypass the proxy_pass check.
    allowed = {
        "server {", "location / {", "}",
        "listen 443 ssl;", "server_name lightup.example.com;",
        "ssl_certificate /etc/letsencrypt/live/lightup.example.com/fullchain.pem;",
        "ssl_certificate_key /etc/letsencrypt/live/lightup.example.com/privkey.pem;",
        "ssl_protocols TLSv1.2 TLSv1.3;",
        "client_max_body_size 64k;", "client_header_timeout 10s;",
        "client_body_timeout 10s;", "send_timeout 30s;", "access_log off;",
        "proxy_pass http://127.0.0.1:8766;",
        "proxy_set_header Host $http_host;",
        "proxy_set_header X-Forwarded-Proto https;",
        "proxy_set_header X-Forwarded-For $remote_addr;",
        "proxy_set_header X-Forwarded-Host \"\";",
        "proxy_set_header Forwarded \"\";",
        "proxy_set_header X-Forwarded-Ssl \"\";",
        "proxy_set_header X-Forwarded-Protocol \"\";",
        "proxy_request_buffering on;", "proxy_connect_timeout 5s;",
        "proxy_send_timeout 30s;", "proxy_read_timeout 35s;",
        *(f'proxy_set_header {name} "";' for name in OVERRIDE_NAMES),
    }
    directives = [line.split("#", 1)[0].strip() for line in template.splitlines()]
    directives = [line for line in directives if line]
    if any(line not in allowed for line in directives):
        raise ValueError("unreviewed Nginx directive")
    if (directives.count("server {") != 1
            or directives.count("location / {") != 1
            or directives.count("}") != 2):
        raise ValueError("invalid server/location layout")
    if any(char in str(root) for char in ('\n', '\r', '"')):
        raise ValueError("unsafe temp path")

    server = _replace_one(template, expected[0], f"    listen 127.0.0.1:{frontend};")
    server = _replace_one(server, expected[1], f"    proxy_pass http://127.0.0.1:{backend};")
    server = _replace_one(server, expected[2], "    server_name localhost;")
    # Remove all example TLS directives, including the certificate paths.
    server = "\n".join(
        line for line in server.splitlines()
        if not re.match(r"\s*(?:ssl_certificate|ssl_certificate_key|ssl_protocols)\s", line)
    )
    if force_rewrite:
        server = _replace_one(
            server, f"    proxy_pass http://127.0.0.1:{backend};",
            f"    proxy_method GET;\n    proxy_pass http://127.0.0.1:{backend};",
        )
    return (
        f'pid "{root / "nginx.pid"}";\n'
        f'error_log "{root / "nginx-error.log"}" warn;\n'
        "worker_processes 1;\nevents { worker_connections 32; }\n"
        f'http {{\n    client_body_temp_path "{root / "body"}";\n'
        f'    proxy_temp_path "{root / "proxy"}";\n'
        + server + "\n}\n"
    )


class _QuietHandler(WSGIRequestHandler):
    def log_message(self, *args):
        pass


class _LoopbackServer(WSGIServer):
    allow_reuse_address = True


def _echo_wsgi(environ, start_response):
    # Read only the tiny, self-generated lab payload, never arbitrary client
    # data. Request-body equality catches an upstream method/frame rewrite
    # that leaves REQUEST_METHOD apparently unchanged.
    size = int(environ.get("CONTENT_LENGTH") or "0")
    if size not in (0, 1):
        start_response("400 Bad Request", [("Content-Length", "0")])
        return [b""]
    payload = environ["wsgi.input"].read(size)
    result = {
        "method": environ.get("REQUEST_METHOD"),
        "path": environ.get("PATH_INFO"),
        "body": payload.decode("ascii") if payload in (b"", b"x") else "INVALID",
        "override_headers": {
            name: environ.get("HTTP_" + name.upper().replace("-", "_"))
            for name in OVERRIDE_NAMES
            if "HTTP_" + name.upper().replace("-", "_") in environ
        },
    }
    data = json.dumps(result, sort_keys=True).encode("ascii")
    start_response("200 OK", [("Content-Type", "application/json"),
                              ("Content-Length", str(len(data)))])
    return [data]


def _available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _request(port: int, method: str, overrides) -> dict:
    # Use HTTPConnection's low-level header API: a dict would coalesce
    # duplicate names, masking case variants before reaching real Nginx.
    pairs = tuple(overrides.items()) if isinstance(overrides, dict) else tuple(overrides)
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        conn.putrequest(method, "/__scope_method_fixture__", skip_host=True)
        conn.putheader("Host", "localhost")
        conn.putheader("Content-Type", "text/plain")
        if method == "POST":
            conn.putheader("Content-Length", "1")
        for name, value in pairs:
            conn.putheader(name, value)
        conn.endheaders(b"x" if method == "POST" else None)
        response = conn.getresponse()
        body = response.read(4096)
        if response.status != 200 or not body:
            raise RuntimeError("upstream did not return a complete lab receipt")
        return json.loads(body)
    finally:
        conn.close()


def _receipt_is_exact(receipt, method: str) -> bool:
    # Even a local upstream can fail unexpectedly or return a malformed JSON
    # shape. No duck-typed list/number, extra fields or fake boolean values
    # may be misclassified as trustworthy WSGI evidence.
    if type(receipt) is not dict or set(receipt) != {
        "method", "path", "body", "override_headers",
    }:
        return False
    return (
        type(receipt["method"]) is str
        and receipt["method"] == method
        and type(receipt["path"]) is str
        and receipt["path"] == "/__scope_method_fixture__"
        and type(receipt["body"]) is str
        and receipt["body"] == ("x" if method == "POST" else "")
        and type(receipt["override_headers"]) is dict
        and not receipt["override_headers"]
    )


def run_probe(template: str, *, force_rewrite: bool = False,
              nginx_bin: str | None = None) -> bool:
    """Return true ONLY for a full synthetic Nginx method+header boundary pass."""
    binary = nginx_bin or shutil.which("nginx")
    if not binary:
        raise RuntimeError("nginx executable not available")
    with tempfile.TemporaryDirectory(prefix="lightup-scope-nginx-") as tmp:
        root = Path(tmp)
        (root / "body").mkdir()
        (root / "proxy").mkdir()
        upstream = make_server("127.0.0.1", 0, _echo_wsgi,
                               server_class=_LoopbackServer,
                               handler_class=_QuietHandler)
        thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        thread.start()
        process = None
        try:
            port = _available_port()
            conf = root / "nginx.conf"
            conf.write_text(render_loopback_config(
                template, port, upstream.server_port, root, force_rewrite=force_rewrite
            ), encoding="utf-8")
            # nginx -t checks the *generated disposable* config, never the installed one.
            tested = subprocess.run([binary, "-p", str(root) + "/", "-c", str(conf), "-t"],
                                    capture_output=True, timeout=4, check=False)
            if tested.returncode:
                raise RuntimeError("disposable nginx config was rejected")
            process = subprocess.Popen(
                [binary, "-p", str(root) + "/", "-c", str(conf), "-g", "daemon off;"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError("disposable nginx exited")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    time.sleep(0.025)
            else:
                raise RuntimeError("disposable nginx never listened")
            # Both directions: a client must not upgrade GET to a write method
            # or downgrade POST to a CSRF-exempt GET.
            cases = [
                (method, {name: spoof})
                for name in OVERRIDE_NAMES
                for method, spoof in (("GET", "DELETE"), ("POST", "GET"))
            ]
            cases += [
                ("GET", {name: "POST" for name in OVERRIDE_NAMES}),
                ("POST", {name: "GET" for name in OVERRIDE_NAMES}),
            ]
            # Independent duplicate-name and mixed-case real HTTP transport
            # probes. HTTP headers are case-insensitive; dict-only tests cannot
            # prove the actual reverse proxy rejects both spellings.
            for name in OVERRIDE_NAMES:
                cases.extend((
                    ("GET", [(name.lower(), "DELETE")]),
                    ("POST", [(name.swapcase(), "GET")]),
                    ("GET", [(name, "DELETE"), (name.lower(), "POST")]),
                    ("POST", [(name.lower(), "GET"), (name, "DELETE")]),
                ))
            for method, overrides in cases:
                receipt = _request(port, method, overrides)
                if not _receipt_is_exact(receipt, method):
                    return False
            return True
        finally:
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
            upstream.shutdown()
            upstream.server_close()
            thread.join(timeout=2)


def _read_candidate_file(path: str) -> str:
    """Bounded local read of a deliberate template snapshot, not a grant.

    Do not follow symlinks or read pipes, sockets, devices or /proc. Never
    return the pathname, user input, or file bytes in a public verdict.
    """
    if type(path) is not str or not path or len(path) > 4096:
        raise ValueError("invalid candidate file")
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    if not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("no no-follow primitive")
    flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        original = os.fstat(descriptor)
        if not stat.S_ISREG(original.st_mode) or not 1 <= original.st_size <= 65536:
            raise ValueError("invalid candidate file")
        raw = os.read(descriptor, original.st_size + 1)
        latest = os.fstat(descriptor)
        stamp = lambda x: (x.st_dev, x.st_ino, x.st_mode, x.st_size,
                           x.st_mtime_ns, x.st_ctime_ns)
        if len(raw) != original.st_size or stamp(original) != stamp(latest):
            raise ValueError("candidate changed during read")
        return raw.decode("utf-8", errors="strict")
    finally:
        os.close(descriptor)


def _get_template(argv) -> str:
    if not argv:
        return TEMPLATE.read_text(encoding="utf-8")
    if len(argv) != 2 or argv[0] != "--candidate-file":
        raise ValueError("invalid candidate arguments")
    return _read_candidate_file(argv[1])


def main(argv=()) -> int:
    # Opacity: do not print submitted headers, upstream responses, paths or
    # process stderr. Real customer data MUST NOT be used.
    verdict = "HOLD"
    reason = "inconclusive"
    try:
        template = _get_template(argv)
        if not shutil.which("nginx"):
            reason = "nginx_unavailable"
        elif not run_probe(template):
            reason = "ingress_boundary_failed"
        elif run_probe(template, force_rewrite=True):
            reason = "negative_control_undetected"
        else:
            verdict = "REVIEW_ONLY"
            reason = "synthetic_loopback_pass"
    except (OSError, ValueError, RuntimeError, TimeoutError,
            http.client.HTTPException, subprocess.SubprocessError):
        reason = "inconclusive"
    print(json.dumps({"verdict": verdict, "reason": reason, **FALSE_FLAGS}, sort_keys=True))
    return 3 if verdict == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
