"""In-process IPv4 loopback socket boundary for the fixed M1 lab canary.

Defense in depth, not an OS network namespace. Only applies while the known
first-party scorer functions execute; it is never an execution authorization.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import socket
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

    def getaddrinfo(host, *args, **kwargs):
        if host != "127.0.0.1":
            raise LabSocketBoundaryError("Offline lab refuses DNS and non-loopback hosts")
        return original_getaddrinfo(host, *args, **kwargs)

    with patch.object(socket.socket, "connect", connect), patch.object(
        socket.socket, "connect_ex", connect_ex
    ), patch.object(socket.socket, "bind", bind), patch.object(
        socket.socket, "sendto", sendto
    ), patch.object(socket, "getaddrinfo", getaddrinfo), patch.object(
        socket.socket, "sendmsg",
        side_effect=LabSocketBoundaryError("Offline lab refuses sendmsg")
    ):
        yield
