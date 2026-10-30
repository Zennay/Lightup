"""In-process IPv4 loopback socket boundary for the fixed M1 lab canary.

Defense in depth, not an OS network namespace. Only applies while the known
first-party scorer functions execute; it is never an execution authorization.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import stat
import subprocess
from contextlib import ExitStack, contextmanager
from contextvars import ContextVar
import socket
import ssl
import threading
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


def trusted_local_openssl() -> str:
    """Use only the root-owned system OpenSSL binary, not a PATH shadow."""
    candidate = shutil.which("openssl")
    if candidate is None:
        raise LabSocketBoundaryError("Trusted local TLS tool unavailable")
    try:
        binary = Path(candidate).resolve(strict=True)
        metadata = binary.stat()
    except (OSError, RuntimeError):
        raise LabSocketBoundaryError("Trusted local TLS tool unavailable") from None
    if (str(binary) not in {"/usr/bin/openssl", "/bin/openssl"}
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_mode & 0o022):
        raise LabSocketBoundaryError("Untrusted local TLS tool")
    return str(binary)


# These are process-global monkeypatches. Without a shared lifetime lock,
# overlapping canaries can uninstall each other's guards mid-assessment.
# Reentrant locking permits a scorer nested under the combined safety canary;
# different threads serialize complete guarded scoring invocations.
_boundary_lock = threading.RLock()


@contextmanager
def serialized_lab_invocation():
    """Hold the shared lock across preflight and scoring in a combined canary.

    A second same-process scorer cannot activate process-global Popen/socket
    patches while another combined canary is still running its preflight.
    """
    with _boundary_lock:
        yield


@contextmanager
def fixed_loopback_socket_boundary():
    """Run one entire fixed-loopback lab scope with serialized guard lifetime.

    Nested calls on the same thread are reentrant. Separate threads never
    overlap process-wide patch install/remove, so no scorer can accidentally
    restore unprotected socket APIs while another guarded scorer is active.
    This is still not an OS sandbox or safe for a multi-tenant server.
    """
    with serialized_lab_invocation():
        with _scoped_fixed_loopback_socket_boundary():
            yield


@contextmanager
def _scoped_fixed_loopback_socket_boundary():
    """Install and restore the existing per-process M1 socket/process hooks."""
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex
    original_bind = socket.socket.bind
    original_sendto = socket.socket.sendto
    original_send = socket.socket.send
    original_sendall = socket.socket.sendall
    original_sendfile = socket.socket.sendfile
    original_listen = socket.socket.listen
    original_accept = socket.socket.accept
    original_raw_accept = getattr(socket.socket, "_accept", None)
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

    def require_loopback_listener(sock):
        # A listening socket may have been bound before this scope started.
        if sock.family != socket.AF_INET:
            raise LabSocketBoundaryError("Offline lab refuses non-IPv4 listener")
        try:
            address = sock.getsockname()
        except OSError:
            raise LabSocketBoundaryError("Offline lab refuses unverified listener") from None
        _require_fixed_loopback_address(sock, address)

    def listen(sock, *args, **kwargs):
        require_loopback_listener(sock)
        return original_listen(sock, *args, **kwargs)

    def accept(sock, *args, **kwargs):
        require_loopback_listener(sock)
        client, peer = original_accept(sock, *args, **kwargs)
        try:
            _require_fixed_loopback_address(client, peer)
        except BaseException:
            client.close()
            raise
        return client, peer

    def raw_accept(sock):
        # CPython's public accept() eventually delegates to _accept(); a
        # direct invocation otherwise sidesteps the public API policy.
        require_loopback_listener(sock)
        fd, peer = original_raw_accept(sock)
        try:
            _require_fixed_loopback_address(sock, peer)
        except BaseException:
            # Raw _accept returns an OS descriptor, not a socket object.
            # Close a rejected descriptor so nothing escapes this boundary.
            os.close(fd)
            raise
        return fd, peer

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

    def guarded_reader(original):
        def read(sock, *args, **kwargs):
            # recv/recv_into and their msg/from variants can consume data
            # from a socket connected before the lab boundary was entered.
            require_connected_loopback(sock)
            return original(sock, *args, **kwargs)
        return read

    raw_receivers = {
        name: guarded_reader(getattr(socket.socket, name))
        for name in ("recv", "recv_into", "recvfrom", "recvfrom_into",
                     "recvmsg", "recvmsg_into")
        if hasattr(socket.socket, name)
    }

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
    # The low-level posix_spawn path is only valid while the already-vetted
    # Popen call is actually constructing its own local certificate child.
    # ContextVar scopes this grant to the current thread and call context.
    validated_popen = ContextVar("lightup_m1_pinned_popen", default=False)

    def approved_local_certificate_command(argv):
        if type(argv) is not list or len(argv) != 18 or not all(
            type(token) is str for token in argv
        ):
            return False
        try:
            openssl = trusted_local_openssl()
        except LabSocketBoundaryError:
            return False
        if argv[0] != openssl:
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
        # Restrict not just the command but also child environment, streams,
        # and process attributes. No ambient OpenSSL/provider/loader settings
        # or arbitrary Popen knobs are permitted in the fixed scorer.
        if (len(args) != 1 or not approved_local_certificate_command(args[0])
                or set(kwargs) != {"stdin", "stdout", "stderr", "env"}
                or type(kwargs.get("env")) is not dict or kwargs["env"]
                or any(kwargs[key] != subprocess.DEVNULL
                       for key in ("stdin", "stdout", "stderr"))):
            raise LabSocketBoundaryError("Offline lab refuses unapproved child process")
        grant = validated_popen.set(True)
        try:
            return original_popen(*args, **kwargs)
        finally:
            validated_popen.reset(grant)

    original_spawn = os.posix_spawn
    original_spawnp = os.posix_spawnp

    def guarded_spawn(path, argv, env, **kwargs):
        # CPython subprocess.Popen can use posix_spawn beneath the validated
        # Popen call. Independently validate that low-level command as well.
        if (not validated_popen.get()
                or type(path) is not str or type(argv) is not list
                or path != argv[0] or type(env) is not dict or env
                or not approved_local_certificate_command(argv)):
            raise LabSocketBoundaryError("Offline lab refuses unapproved child process")
        return original_spawn(path, argv, env, **kwargs)

    def guarded_spawnp(path, argv, env, **kwargs):
        if (not validated_popen.get()
                or type(path) is not str or type(argv) is not list
                or path != argv[0] or type(env) is not dict or env
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
    tls_overrides.update({
        name: guarded_reader(getattr(ssl.SSLSocket, name))
        for name in ("recv", "recv_into", "read")
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
                "bind": bind, "listen": listen, "accept": accept,
                "sendto": sendto, "send": send,
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
        if original_raw_accept is not None:
            stack.enter_context(patch.object(socket.socket, "_accept", raw_accept))
        stack.enter_context(patch.multiple(socket.socket, **raw_receivers))
        stack.enter_context(patch.multiple(ssl.SSLSocket, **tls_overrides))
        stack.enter_context(patch.object(
            socket.socket, "sendmsg",
            side_effect=LabSocketBoundaryError("Offline lab refuses sendmsg"),
        ))
        yield
