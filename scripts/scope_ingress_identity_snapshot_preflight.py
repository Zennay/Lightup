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
# This is a deliberately tiny *whole-document* reference grammar, not a
# generic Nginx parser. Real installed nginx -T typically needs independent
# ingress-owner review because includes, http blocks and installed extensions
# cannot be reduced safely to an inventory of familiar directive names.
EXPECTED_LOCATION_LINES = frozenset({
    "proxy_pass http://127.0.0.1:8766;",
    "proxy_pass_request_headers off;",
    "proxy_set_header Host $http_host;",
    "proxy_set_header Cookie $http_cookie;",
    "proxy_set_header X-Forwarded-Proto https;",
    "proxy_set_header X-Forwarded-For $remote_addr;",
})
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
    # No hidden carriage-return rewriting, backspace, NEL, Unicode separators
    # or non-ASCII tokens in this small synthetic reference format.
    if not config.isascii() or any(
        ord(character) < 32 and character not in "\n\t"
        for character in config
    ):
        raise Hold
    # This marker is supplied by the caller; it is NOT authenticated provenance.
    if not any(
        re.fullmatch(r"# configuration file [^\r\n]+:", line.strip())
        for line in config.split("\n")
    ):
        raise Hold

    # Validate the exact location and nesting of every directive. Checking for
    # globally present allowlisted tokens alone is unsafe: an unrelated server,
    # extra public listener, or an out-of-scope location could satisfy that.
    state = "start"
    server_directives: set[str] = set()
    location_directives: set[str] = set()
    for raw_line in config.split("\n"):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line == "server {" and state == "start":
            state = "server"
            continue
        if line == "location / {" and state == "server":
            if server_directives != {"listen", "server_name"}:
                raise Hold
            state = "location"
            continue
        if line == "}" and state == "location":
            if location_directives != EXPECTED_LOCATION_LINES:
                raise Hold
            state = "server_closed_location"
            continue
        if line == "}" and state == "server_closed_location":
            state = "end"
            continue

        if state == "server":
            if line == "listen 443 ssl;":
                key = "listen"
            else:
                match = re.fullmatch(r"server_name ([a-z0-9.-]+);", line)
                if match is None:
                    raise Hold
                hostname = match.group(1)
                labels = hostname.split(".")
                if (len(hostname) > 253 or len(labels) < 2 or
                        any(re.fullmatch(
                            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label,
                        ) is None for label in labels)):
                    raise Hold
                key = "server_name"
            if key in server_directives:
                raise Hold
            server_directives.add(key)
        elif state == "location":
            if line not in EXPECTED_LOCATION_LINES or line in location_directives:
                raise Hold
            location_directives.add(line)
        else:
            # Includes all unknown directives, second server blocks,
            # duplicate/nested locations, and unmatched/extraneous braces.
            raise Hold
    if state != "end":
        raise Hold


def _gunicorn_ok(raw: bytes) -> None:
    config = _decode(raw)
    # Match the tiny source grammar used for nginx: CR, vertical-tab, Unicode
    # line separators and hidden control bytes cannot create alternate keys.
    if not config.isascii() or any(
        ord(character) < 32 and character not in "\n\t"
        for character in config
    ):
        raise Hold
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
