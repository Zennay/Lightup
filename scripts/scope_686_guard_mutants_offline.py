"""Prove #686 opt-in guard acceptance FAILS CLOSED under Python -O / -OO.

Each mutation exists only in a disposable synthetic SQLite/WSGI process.
There is NO external HTTP request, real target, grant or user session.
"""
from __future__ import annotations

import json
import sys
from unittest.mock import patch

from lightup.webapp.session_cookie_guard import CookieEnvelopeGuard
import scope_686_guard_probe_offline as probe


class PrematureRead:
    def __init__(self, real_guard, method):
        self.real_guard = real_guard
        self.method = method

    def __call__(self, environ, start_response):
        stream = environ["wsgi.input"]
        if self.method == "read":
            stream.read(1)
        elif self.method == "readline":
            stream.readline(1)
        elif self.method == "readinto":
            stream.readinto(bytearray(1))
        elif self.method == "getvalue":
            stream.getvalue()
        elif self.method == "iterator":
            next(iter(stream), b"")
        else:
            raise RuntimeError("invalid synthetic stream mutation")
        return self.real_guard(environ, start_response)


class CookieInjection:
    def __init__(self, real_guard):
        self.real_guard = real_guard

    def __call__(self, environ, start_response):
        def contaminated(status, headers):
            return start_response(status, [*headers, ("Set-Cookie", "fictional=one")])
        return self.real_guard(environ, contaminated)


def must_reject(label: str, factory) -> None:
    with patch.object(probe, "CookieEnvelopeGuard", factory):
        try:
            probe.verify_guard()
        except probe.GuardProbeHold:
            return
        except Exception:
            # Unrelated exception is NOT a valid expected denial; fail closed.
            raise RuntimeError("mutant failed with unrelated error: " + label) from None
        raise RuntimeError("synthetic guard mutation was falsely accepted: " + label)


def verify_mutations() -> dict:
    must_reject("guard_removed", lambda app: app)
    for label, operation in (
        ("body_read_early", "read"),
        ("body_readline_early", "readline"),
        ("body_readinto_early", "readinto"),
        ("body_getvalue_early", "getvalue"),
        ("body_iterator_early", "iterator"),
    ):
        must_reject(label, lambda app, op=operation: PrematureRead(
            CookieEnvelopeGuard(app), op))
    must_reject("session_cookie_mutation", lambda app: CookieInjection(CookieEnvelopeGuard(app)))
    return {
        "status": "HOLD",
        "release_authorized": False,
        "candidate_mutant_coverage": "PASS",
        "mutants_rejected": 7,
        "mutation_labels": [
            "guard_removed", "body_read_early", "body_readline_early",
            "body_readinto_early", "body_getvalue_early",
            "body_iterator_early", "session_cookie_mutation",
        ],
        "real_target_io_performed": False,
    }


if __name__ == "__main__":
    try:
        print(json.dumps(verify_mutations(), sort_keys=True, separators=(",", ":")))
    except (RuntimeError, ValueError, OSError):
        print(json.dumps({
            "status": "HOLD", "release_authorized": False,
            "candidate_mutant_coverage": "FAIL",
        }, sort_keys=True, separators=(",", ":")))
        sys.exit(2)
