"""Conservative offline ingress-config snapshot preflight; NEVER release authority.

This utility deliberately reads only caller-supplied local snapshots.  It cannot
prove that snapshots came from a running proxy, that TLS is correct, or that a
request crossed a real Gunicorn/WSGI boundary.  REVIEW_ONLY means only that a
small, deliberately constrained configuration shape matches this offline
reference.  All other shapes HOLD, including unknown configurations.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import stat
import sys

MAX_SNAPSHOT_BYTES = 256 * 1024
FLAGS = (
    "authorization_verified",
    "permit_issued",
    "execution_enabled",
    "merge_approved",
    "release_approved",
)
RISK_DIRECTIVES = frozenset({
    "include", "rewrite", "set", "map", "auth_request",
    "auth_request_set", "real_ip_header", "proxy_pass_request_body",
    "underscores_in_headers", "ignore_invalid_headers",
    "proxy_redirect", "sub_filter", "add_header", "more_set_headers",
    "more_clear_headers", "error_page", "return", "try_files",
    "mirror", "mirror_request_body", "access_by_lua_block",
    "content_by_lua_block", "js_set", "js_content",
})
ALLOWED_NGINX_DIRECTIVES = frozenset({
    "server", "location", "listen", "server_name",
    "proxy_pass", "proxy_pass_request_headers", "proxy_set_header",
})
EXPECTED_FORWARD_HEADERS = {
    "host": "$http_host",
    "cookie": "$http_cookie",
    "x-forwarded-proto": "https",
    "x-forwarded-for": "$remote_addr",
}
REQUIRED_GUNICORN = {
    "bind": "127.0.0.1:8766",
    "forwarded_allow_ips": "",
    "secure_scheme_headers": {},
    "worker_class": "sync",
}


class Hold(Exception):
    pass


def _decode(raw: bytes) -> str:
    if type(raw) is not bytes or not raw or len(raw) > MAX_SNAPSHOT_BYTES:
        raise Hold
    if b"\x00" in raw:
        raise Hold
    try:
        return raw.decode("utf-8", "strict")
    except UnicodeError as exc:
        raise Hold from exc


def _nginx_ok(raw: bytes) -> None:
    config = _decode(raw)
    # nginx -T writes this marker for effective configurations.  A marker
    # supplied by the caller is NOT an authenticated origin attestation.
    if "# configuration file " not in config:
        raise Hold
    lines = [line.split("#", 1)[0].strip() for line in config.splitlines()]
    lines = [line for line in lines if line]
    # No variables, includes, scripts or scope-rewrite constructs except for
    # four explicitly reviewed proxy header bindings below.
    for line in lines:
        directive = line.split(None, 1)[0].rstrip(";{}").lower()
        if (directive in RISK_DIRECTIVES or
                directive not in ALLOWED_NGINX_DIRECTIVES and line != "}"):
            # Unknown Nginx modules can also rewrite request metadata.  A
            # syntactically opaque directive must never earn REVIEW_ONLY.
            raise Hold
        if "$http_" in line and line not in {
            "proxy_set_header Host $http_host;",
            "proxy_set_header Cookie $http_cookie;",
        }:
            raise Hold
        if "proxy_pass_request_headers" in line and line != "proxy_pass_request_headers off;":
            raise Hold
    if sum(bool(re.fullmatch(r"server\s*\{", line)) for line in lines) != 1:
        raise Hold
    locations = [i for i, line in enumerate(lines) if line.startswith("location ")]
    if len(locations) != 1 or lines[locations[0]] != "location / {":
        raise Hold
    location_start = locations[0]
    try:
        location_end = lines.index("}", location_start + 1)
    except ValueError as exc:
        raise Hold from exc
    inside = lines[location_start + 1:location_end]
    # Nested blocks can change effective inheritance or authorization.
    if any("{" in line or "}" in line for line in inside):
        raise Hold
    if sum(line == "proxy_pass http://127.0.0.1:8766;" for line in lines) != 1:
        raise Hold
    if sum(line == "proxy_pass_request_headers off;" for line in inside) != 1:
        raise Hold
    if sum(line == "listen 443 ssl;" for line in lines) != 1:
        raise Hold
    headers: dict[str, str] = {}
    for line in lines:
        if not line.lower().startswith("proxy_set_header "):
            continue
        match = re.fullmatch(r"proxy_set_header\s+([A-Za-z0-9-]+)\s+(\S+);", line)
        if match is None or line not in inside:
            raise Hold
        key, value = match.group(1).lower(), match.group(2)
        if key in headers:
            raise Hold
        headers[key] = value
    if headers != EXPECTED_FORWARD_HEADERS:
        raise Hold
    if any(line.startswith("proxy_pass ") and line !=
           "proxy_pass http://127.0.0.1:8766;" for line in lines):
        raise Hold
    # No hidden top-level request-header forwarding or a second proxy path.
    if len([line for line in lines if line.startswith("proxy_pass ")]) != 1:
        raise Hold


def _gunicorn_ok(raw: bytes) -> None:
    config = _decode(raw)
    found: dict[str, object] = {}
    for line in config.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            raise Hold
        key, literal = stripped.split("=", 1)
        key = key.strip()
        if not re.fullmatch(r"[a-z_]+", key):
            raise Hold
        if key not in REQUIRED_GUNICORN:
            # Non-reviewed Gunicorn settings (raw_env, forwarder_headers,
            # WSGI factories or custom middleware) may change identity.
            raise Hold
        if key in found:
            raise Hold
        try:
            found[key] = ast.literal_eval(literal.strip())
        except (ValueError, SyntaxError, TypeError, MemoryError, RecursionError) as exc:
            raise Hold from exc
    if set(found) != set(REQUIRED_GUNICORN):
        raise Hold
    for key, expected in REQUIRED_GUNICORN.items():
        if type(found[key]) is not type(expected) or found[key] != expected:
            raise Hold


def review(nginx_effective: bytes, gunicorn_effective: bytes) -> dict[str, object]:
    decision = "HOLD"
    code = "SNAPSHOT_REJECTED"
    nginx_hash = None
    gunicorn_hash = None
    try:
        _nginx_ok(nginx_effective)
        _gunicorn_ok(gunicorn_effective)
        # Hashes show only equality with input snapshots, not their provenance.
        nginx_hash = hashlib.sha256(nginx_effective).hexdigest()
        gunicorn_hash = hashlib.sha256(gunicorn_effective).hexdigest()
        decision, code = "REVIEW_ONLY", "STATIC_SHAPE_MATCHED"
    except (Hold, OSError, ValueError, TypeError):
        pass
    return {
        "decision": decision, "diagnostic_code": code,
        "nginx_sha256": nginx_hash, "gunicorn_sha256": gunicorn_hash,
        **{name: False for name in FLAGS},
    }


def _read_snapshot(path: str) -> bytes:
    # Only explicitly supplied ordinary, non-symlink files are admissible.
    # O_NONBLOCK avoids FIFO/device stalls; O_NOFOLLOW denies symlink pivots.
    # No shell, daemon access, DNS, network or implicit config discovery.
    if type(path) is not str or not path or not hasattr(os, "O_NOFOLLOW"):
        raise Hold
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or
                not (0 < before.st_size <= MAX_SNAPSHOT_BYTES)):
            raise Hold
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(MAX_SNAPSHOT_BYTES + 1)
        after = os.fstat(fd)
        if (len(data) != before.st_size or
                after.st_size != before.st_size or
                after.st_mtime_ns != before.st_mtime_ns):
            raise Hold
        return data
    finally:
        os.close(fd)


def main(argv: object = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    receipt = review(b"", b"")
    if (type(argv) is list and len(argv) == 4 and
            type(argv[0]) is str and argv[0] == "--nginx-effective" and
            type(argv[1]) is str and
            type(argv[2]) is str and argv[2] == "--gunicorn-effective" and
            type(argv[3]) is str):
        try:
            nginx = _read_snapshot(argv[1])
            gunicorn = _read_snapshot(argv[3])
            receipt = review(nginx, gunicorn)
        except (Hold, OSError, ValueError, TypeError):
            pass
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 3 if receipt["decision"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
