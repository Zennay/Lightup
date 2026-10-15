"""Opt-in, localhost-only Nginx -> WSGI method integrity acceptance for #1154.

This is an *offline lab receipt*, never trusted scope, approval, or release
evidence.  It does not inspect or modify an installed Nginx service.
"""
from __future__ import annotations

import http.client
import json
import re
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
    result = {
        "method": environ.get("REQUEST_METHOD"),
        "path": environ.get("PATH_INFO"),
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


def _request(port: int, method: str, override: str) -> dict:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        # This HTTP client may ONLY contact the loopback listener above.
        headers = {"Host": "localhost", "Content-Type": "text/plain"}
        headers.update({name: override for name in OVERRIDE_NAMES})
        conn.request(method, "/__scope_method_fixture__", body=b"x" if method == "POST" else None,
                     headers=headers)
        response = conn.getresponse()
        body = response.read(4096)
        if response.status != 200 or not body:
            raise RuntimeError("upstream did not return a complete lab receipt")
        return json.loads(body)
    finally:
        conn.close()


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
            for method, override in (("GET", "DELETE"), ("POST", "GET")):
                receipt = _request(port, method, override)
                if receipt.get("method") != method:
                    return False
                if receipt.get("path") != "/__scope_method_fixture__":
                    return False
                if receipt.get("override_headers"):
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


def main() -> int:
    # Opacity: do not print submitted headers, upstream responses, paths or
    # process stderr. Real customer data MUST NOT be used.
    verdict = "HOLD"
    reason = "inconclusive"
    try:
        template = TEMPLATE.read_text(encoding="utf-8")
        if not shutil.which("nginx"):
            reason = "nginx_unavailable"
        elif not run_probe(template):
            reason = "ingress_boundary_failed"
        elif run_probe(template, force_rewrite=True):
            reason = "negative_control_undetected"
        else:
            verdict = "REVIEW_ONLY"
            reason = "synthetic_loopback_pass"
    except (OSError, ValueError, RuntimeError, TimeoutError, subprocess.SubprocessError):
        reason = "inconclusive"
    print(json.dumps({"verdict": verdict, "reason": reason, **FALSE_FLAGS}, sort_keys=True))
    return 3 if verdict == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    sys.exit(main())
