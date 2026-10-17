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
    def __init__(self, real_guard):
        self.real_guard = real_guard

    def __call__(self, environ, start_response):
        environ["wsgi.input"].read(1)
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
    must_reject("body_read_early", lambda app: PrematureRead(CookieEnvelopeGuard(app)))
    must_reject("session_cookie_mutation", lambda app: CookieInjection(CookieEnvelopeGuard(app)))
    return {
        "status": "HOLD",
        "release_authorized": False,
        "candidate_mutant_coverage": "PASS",
        "mutants_rejected": 3,
        "mutation_labels": [
            "guard_removed", "body_read_early", "session_cookie_mutation",
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
