"""Real in-process acceptance of the existing *unwired* cookie owner guard.

Only invoked in an ephemeral owner composition; no external HTTP requests.
Never outputs, creates, or delegates authorization to scan any real target.
"""
from __future__ import annotations

import io
import json
from pathlib import Path
import tempfile
from urllib.parse import urlencode
from unittest.mock import patch

from lightup.domain import DomainStore, Role
from lightup.webapp import create_app
from lightup.webapp.session_cookie_guard import CookieEnvelopeGuard


class CountedStream(io.BytesIO):
    def __init__(self, body: bytes = b""):
        super().__init__(body)
        self.reads = 0

    def read(self, *args, **kwargs):
        self.reads += 1
        return super().read(*args, **kwargs)



class GuardProbeHold(Exception):
    """A review-only invariant failed; never issue a compatibility PASS."""


def _require(condition: bool, invariant: str) -> None:
    # Unlike 'assert', this invariant stays enforced under python -O/-OO.
    if condition is not True:
        raise GuardProbeHold("opt-in guard failed: " + invariant)


def verify_guard() -> dict:
    with tempfile.TemporaryDirectory(prefix="lightup-686-sqlite-") as tmp:
        store = DomainStore(Path(tmp) / "disposable.sqlite3")
        op = store.bootstrap_operator(
            "guard686-operator@lightup.test", "Synthetic Operator",
            "fictional-password")
        admin = store.context_for_user(op.user_id)
        client = store.create_client(admin, "Synthetic Tenant")
        member = store.create_user(
            admin, "guard686-client@lightup.test", "Synthetic Client",
            Role.CLIENT_ADMIN, client.client_id)
        operator, _ = store.create_session(op.user_id)
        tenant, _ = store.create_session(member.user_id)
        wrapped = CookieEnvelopeGuard(create_app(store))

        def invoke(header: str, *, method="GET", route="/", body=b""):
            stream = CountedStream(body)
            environ = {
                "REQUEST_METHOD": method, "PATH_INFO": route,
                "CONTENT_LENGTH": str(len(body)),
                "CONTENT_TYPE": "application/x-www-form-urlencoded",
                "wsgi.input": stream, "HTTP_COOKIE": header,
            }
            result = {}
            with (patch.object(store, "session_context", wraps=store.session_context) as lookup,
                  patch.object(store, "create_session", wraps=store.create_session) as create,
                  patch.object(store, "revoke_session", wraps=store.revoke_session) as revoke,
                  patch.object(store, "create_client") as create_client):
                b"".join(wrapped(environ, lambda status, headers: result.update(
                    status=status, headers=dict(headers))))
                calls = (lookup.call_count, create.call_count,
                         revoke.call_count, create_client.call_count)
            return result, calls, stream.reads

        negative = (
            f"lightup_session={operator}; lightup_session={operator}",
            f"lightup_session={operator}; lightup_session={tenant}",
            f"lightup_session={tenant}; lightup_session={operator}",
            f"lightup_session=invalid; lightup_session={operator}",
            f"lightup_session={operator}; lightup_session=invalid",
            f"theme=dark; lightup_session={operator}; lang=nl; lightup_session={tenant}",
            f"lightup_session={operator}; lightup_session={tenant}; lightup_session={operator}",
            f"lightup_session = {operator}; lightup_session={tenant}",
            f"lightup_session={operator}; lightup_session={operator}; theme=light",
        )
        for header in negative:
            result, calls, reads = invoke(header, method="POST", route="/clients",
                                          body=b"name=ShouldNeverExist")
            _require(result.get("status") == "400 Bad Request", "duplicate denied")
            _require(calls == (0, 0, 0, 0), "zero prehandler state effects")
            _require(reads == 0, "no prehandler request-body reads")
            _require("Set-Cookie" not in result.get("headers", {}), "no cookie mutation")

        payload = urlencode({
            "email": "guard686-operator@lightup.test",
            "password": "fictional-password",
        }).encode("ascii")
        login, calls, reads = invoke(
            negative[1], method="POST", route="/login", body=payload)
        _require(login.get("status") == "400 Bad Request", "public login denied")
        _require(calls == (0, 0, 0, 0), "no public login store effects")
        _require(reads == 0 and "Set-Cookie" not in login.get("headers", {}),
                 "no login request-body reads or Set-Cookie")

        cases = (
            (f"lightup_session={operator}", "200 OK"),
            (f"theme=first; lightup_session={operator}; theme=last", "200 OK"),
            (f"lightup_session={tenant}", "403 Forbidden"),
        )
        for header, expected in cases:
            result, _, _ = invoke(header)
            _require(result.get("status") == expected, "legitimate role isolation")

        _require(store.session_context(operator) is not None, "operator session retained")
        _require(store.session_context(tenant) is not None, "client session retained")
        return {
            "status": "HOLD", "release_authorized": False,
            "guard_source": "opt-in owner #1169, not installed WSGI production entrypoint",
            "candidate_compatibility": "PASS",
            "duplicates_denied_prebody": len(negative),
            "public_login_denied_prebody": True,
            "single_session_controls_passed": len(cases),
            "session_lookup_or_write_before_denial": False,
            "real_target_io_performed": False,
        }


if __name__ == "__main__":
    print(json.dumps(verify_guard(), sort_keys=True, separators=(",", ":")))
