"""Run the LightUp web shell: ``python -m lightup.webapp``.

Binds to loopback only. There is no authentication layer yet, so refusing
non-loopback binds is a hard safety default, not a convenience.
"""

from __future__ import annotations

import argparse
from ipaddress import ip_address
from wsgiref.simple_server import make_server

from ..domain import DomainStore
from .app import create_app


def _loopback(value: str) -> str:
    try:
        if not ip_address(value).is_loopback:
            raise argparse.ArgumentTypeError(
                "the web shell has no authentication yet and only binds to loopback"
            )
    except ValueError:
        raise argparse.ArgumentTypeError("host must be a loopback IP address") from None
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="lightup-web")
    parser.add_argument("--db", default="lightup.db", help="domain database path")
    parser.add_argument("--host", type=_loopback, default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8766)
    args = parser.parse_args(argv)

    app = create_app(DomainStore(args.db))
    with make_server(args.host, args.port, app) as server:
        print(f"LightUp web shell on http://{args.host}:{server.server_port} "
              f"(db: {args.db}) — Ctrl+C to stop")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
