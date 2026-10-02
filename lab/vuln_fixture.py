"""Loopback-only lab fixture with selectable planted-weakness profiles.

Unlike ``http_fixture.py`` (always harmless), this fixture serves one of the
profiles from ``lightup.labfixtures`` — e.g. ``exposed`` sends no defensive
headers at all — so the assessment engine can be benchmarked against known
planted ground truth. It still binds only to 127.0.0.1; the planted
weaknesses are response headers, nothing more.

Usage::

    python lab/vuln_fixture.py --profile exposed --port 18081
"""

from __future__ import annotations

import argparse
import sys
from http.server import ThreadingHTTPServer
from pathlib import Path

try:
    from lightup.labfixtures import PROFILES, make_handler
except ImportError:  # running from a source checkout without an install
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
    from lightup.labfixtures import PROFILES, make_handler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="lightup-vuln-fixture")
    parser.add_argument("--profile", choices=sorted(PROFILES), default="exposed")
    parser.add_argument("--port", type=int, default=18081)
    args = parser.parse_args(argv)

    profile = PROFILES[args.profile]
    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(profile))
    print(f"LightUp lab fixture [{profile.profile_id}] on "
          f"http://127.0.0.1:{server.server_port}/ — {profile.description}")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
