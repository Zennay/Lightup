"""In-process IPv4 loopback socket boundary for the fixed M1 lab canary.

Defense in depth, not an OS network namespace. Only applies while the known
first-party scorer functions execute; it is never an execution authorization.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
from contextlib import ExitStack, contextmanager
import socket
import ssl
from unittest.mock import patch


class PrivateLabArgumentParser(argparse.ArgumentParser):
    """Reject unexpected CLI arguments without echoing sensitive input."""

    def error(self, message: str) -> None:
        self.exit(2, f"{self.prog}: unsupported offline lab arguments\n")


class LabSocketBoundaryError(RuntimeError):
    pass


def _require_fixed_loopback_address(sock: socket.socket, address: object) -> None:
    if (sock.family != socket.AF_INET or type(address) is not tuple
            or len(address) != 2 or address[0] != "127.0.0.1"
            or type(address[1]) is not int
            or not 0 <= address[1] <= 65535):
        raise LabSocketBoundaryError("Offline lab socket must use fixed IPv4 loopback")


@contextmanager
def fixed_loopback_socket_boundary():
    """Refuse getaddrinfo lookup, connect, bind and datagram sends outside 127.0.0.1.

    Preserve original socket operations and restore them even when a scorer
    raises. This is process-global while active; do not use in a multi-tenant
    server. Only for the isolated, single-invocation local canary.
    """
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex
    original_bind = socket.socket.bind
    original_sendto = socket.socket.sendto
    original_send = socket.socket.send
    original_sendall = socket.socket.sendall
    original_sendfile = socket.socket.sendfile
    original_getaddrinfo = socket.getaddrinfo

    def connect(sock, address):
        _require_fixed_loopback_address(sock, address)
        return original_connect(sock, address)

    def connect_ex(sock, address):
        _require_fixed_loopback_address(sock, address)
        return original_connect_ex(sock, address)

    def bind(sock, address):
        _require_fixed_loopback_address(sock, address)
        return original_bind(sock, address)

    def sendto(sock, *args):
        if len(args) not in (2, 3):
            raise LabSocketBoundaryError("Offline lab refuses unrecognized datagram send")
        _require_fixed_loopback_address(sock, args[-1])
        return original_sendto(sock, *args)

    def require_connected_loopback(sock):
        # A socket can have been connected before this temporary boundary.
        # Guard every connected write, not only connect() and sendto().
        if sock.family != socket.AF_INET:
            raise LabSocketBoundaryError("Offline lab refuses non-IPv4 socket peer")
        try:
            address = sock.getpeername()
        except OSError:
            raise LabSocketBoundaryError("Offline lab refuses unverified socket peer") from None
        _require_fixed_loopback_address(sock, address)

    def send(sock, *args, **kwargs):
        require_connected_loopback(sock)
        return original_send(sock, *args, **kwargs)

    def sendall(sock, *args, **kwargs):
        require_connected_loopback(sock)
        return original_sendall(sock, *args, **kwargs)

    def sendfile(sock, *args, **kwargs):
        require_connected_loopback(sock)
        return original_sendfile(sock, *args, **kwargs)

    def getaddrinfo(host, *args, **kwargs):
        if host != "127.0.0.1":
            raise LabSocketBoundaryError("Offline lab refuses DNS and non-loopback hosts")
        return original_getaddrinfo(host, *args, **kwargs)

    def refuse_name_resolution(*args, **kwargs):
        raise LabSocketBoundaryError("Offline lab forbids separate resolver API")

    def fixed_loopback_fqdn(name: str = "") -> str:
        # http.server asks for its numeric bind address during initialization.
        # Never reverse-resolve the local address or consult the network.
        if name == "127.0.0.1":
            return "127.0.0.1"
        raise LabSocketBoundaryError("Offline lab forbids hostname resolution")

    # Guard direct child launches as well as socket calls. The only first-
    # party child needed by the three fixed scorers is the local certificate
    # generator. This is still process-local defense in depth, not OS sandboxing.
    original_popen = subprocess.Popen

    def approved_local_certificate_command(argv):
        if type(argv) is not list or len(argv) != 18 or not all(
            type(token) is str for token in argv
        ):
            return False
        openssl = shutil.which("openssl")
        if openssl is None or argv[0] != openssl:
            return False
        key, cert = Path(argv[7]), Path(argv[9])
        root = key.parent
        if (not root.is_absolute() or not root.name.startswith("lightup-tls-lab-")
                or root.is_symlink() or not root.is_dir()
                or cert.parent != root
                or key.name != "fixture-key.pem"
                or cert.name != "fixture-cert.pem"):
            return False
        return argv == [
            openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "1",
            "-subj", "/CN=127.0.0.1", "-addext",
            "subjectAltName=IP:127.0.0.1", "-addext",
            "basicConstraints=critical,CA:FALSE",
        ]

    def guarded_popen(*args, **kwargs):
        if (len(args) != 1 or not approved_local_certificate_command(args[0])
                or kwargs.get("shell") not in (None, False)
                or kwargs.get("executable") is not None
                or kwargs.get("cwd") is not None
                or kwargs.get("env") is not None
                or kwargs.get("preexec_fn") is not None
                or kwargs.get("pass_fds", ()) != ()):
            raise LabSocketBoundaryError("Offline lab refuses unapproved child process")
        return original_popen(*args, **kwargs)

    original_spawn = os.posix_spawn
    original_spawnp = os.posix_spawnp

    def guarded_spawn(path, argv, env, **kwargs):
        # CPython subprocess.Popen can use posix_spawn beneath the validated
        # Popen call. Independently validate that low-level command as well.
        if (type(path) is not str or type(argv) is not list or path != argv[0]
                or not approved_local_certificate_command(argv)):
            raise LabSocketBoundaryError("Offline lab refuses unapproved child process")
        return original_spawn(path, argv, env, **kwargs)

    def guarded_spawnp(path, argv, env, **kwargs):
        if (type(path) is not str or type(argv) is not list or path != argv[0]
                or not approved_local_certificate_command(argv)):
            raise LabSocketBoundaryError("Offline lab refuses unapproved child process")
        return original_spawnp(path, argv, env, **kwargs)

    def refuse_process(*args, **kwargs):
        raise LabSocketBoundaryError("Offline lab forbids process launch API")

    # SSLSocket overrides the raw socket methods and its write() reaches
    # the TLS engine directly. Cover those methods and its connect overrides,
    # including sockets established before entering this scoped canary.
    def guarded_tls_writer(method):
        original = getattr(ssl.SSLSocket, method)

        def guarded(sock, *args, **kwargs):
            require_connected_loopback(sock)
            return original(sock, *args, **kwargs)

        return guarded

    def guarded_tls_connector(method):
        original = getattr(ssl.SSLSocket, method)

        def guarded(sock, address):
            _require_fixed_loopback_address(sock, address)
            return original(sock, address)

        return guarded

    # TLS handshakes and close-notify can emit encrypted bytes directly via
    # OpenSSL, bypassing all Python-level send methods.
    tls_overrides = {
        name: guarded_tls_writer(name)
        for name in ("send", "sendall", "sendfile", "write", "do_handshake", "unwrap")
    }

    original_wrap_socket = ssl.SSLContext.wrap_socket

    def guarded_tls_wrap(context, sock, *args, **kwargs):
        # wrap_socket can implicitly start a handshake immediately.
        require_connected_loopback(sock)
        return original_wrap_socket(context, sock, *args, **kwargs)
    tls_overrides.update({
        name: guarded_tls_connector(name) for name in ("connect", "connect_ex")
    })

    # ExitStack also avoids the compiler's static nesting limit while
    # restoring every process-global patch even on a scorer exception.
    with ExitStack() as stack:
        for module, replacements in (
            (subprocess, {"Popen": guarded_popen}),
            (os, {
                "system": refuse_process, "popen": refuse_process,
                "posix_spawn": guarded_spawn, "posix_spawnp": guarded_spawnp,
                "fork": refuse_process,
            }),
            (ssl.SSLContext, {"wrap_socket": guarded_tls_wrap}),
            (socket.socket, {
                "connect": connect, "connect_ex": connect_ex,
                "bind": bind, "sendto": sendto, "send": send,
                "sendall": sendall, "sendfile": sendfile,
            }),
            (socket, {
                "getaddrinfo": getaddrinfo,
                "gethostbyname": refuse_name_resolution,
                "gethostbyname_ex": refuse_name_resolution,
                "gethostbyaddr": refuse_name_resolution,
                "getnameinfo": refuse_name_resolution,
                "getfqdn": fixed_loopback_fqdn,
            }),
        ):
            for method, replacement in replacements.items():
                stack.enter_context(patch.object(module, method, replacement))
        # Older or direct Python process APIs must not bypass Popen. This is
        # explicit defense against accidental scorer subprocess expansion,
        # not a security boundary against arbitrary native extension code.
        for name in (
            "execl", "execle", "execlp", "execlpe",
            "execv", "execve", "execvp", "execvpe",
            "spawnl", "spawnle", "spawnlp", "spawnlpe",
            "spawnv", "spawnve", "spawnvp", "spawnvpe", "forkpty",
        ):
            if hasattr(os, name):
                stack.enter_context(patch.object(os, name, refuse_process))
        stack.enter_context(patch.multiple(ssl.SSLSocket, **tls_overrides))
        stack.enter_context(patch.object(
            socket.socket, "sendmsg",
            side_effect=LabSocketBoundaryError("Offline lab refuses sendmsg"),
        ))
        yield
