"""Offline activation/authentication canaries with per-invocation state.

Safe to repeat or run concurrently on a persistent self-hosted runner.
Requires PYTHONPATH=src. Does not open a listening socket or contact a target.
"""
from __future__ import annotations

import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from lightup.domain import AccessContext, DomainStore, Role
from lightup.engagements import RiskLevel, ScopeDefinition
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind
from lightup.models import Authorization, Target
from lightup.scope import ScopePolicy, ScopeReason
from lightup.webapp import create_app
from lightup.webapp.__main__ import _loopback


def main() -> None:
    denied = subprocess.run(
        [sys.executable, "-m", "lightup.cli", "scope-check", "8.8.8.8"],
        capture_output=True, text=True, check=False,
    )
    assert denied.returncode == 2, (denied.returncode, denied.stdout, denied.stderr)
    assert json.loads(denied.stdout)["allowed"] is False

    private_denied = subprocess.run(
        [sys.executable, "-m", "lightup.cli", "scope-check", "10.20.30.40"],
        capture_output=True, text=True, check=False,
    )
    assert private_denied.returncode == 2
    private_payload = json.loads(private_denied.stdout)
    assert private_payload["allowed"] is False
    assert private_payload["reason"] == "out_of_scope"

    private_opt_in = subprocess.run(
        [
            sys.executable, "-m", "lightup.cli", "scope-check",
            "--allow-private-lab", "10.20.30.40",
        ],
        capture_output=True, text=True, check=False,
    )
    assert private_opt_in.returncode == 0
    assert json.loads(private_opt_in.stdout)["reason"] == "private_lab"

    link_local = subprocess.run(
        [
            sys.executable, "-m", "lightup.cli", "scope-check",
            "--allow-private-lab", "169.254.169.254",
        ],
        capture_output=True, text=True, check=False,
    )
    assert link_local.returncode == 2
    assert json.loads(link_local.stdout)["allowed"] is False

    legacy_policy = ScopePolicy(
        explicit_hosts=frozenset({"a.example.test", "b.example.test"})
    )
    legacy_auth = Authorization(
        owner="CI owner",
        reference="CI-LEGACY-ASSET",
        assets=("a.example.test",),
    )
    assert legacy_policy.decide(
        Target("a.example.test", authorization=legacy_auth)
    ).allowed is True
    mismatched = legacy_policy.decide(
        Target("b.example.test", authorization=legacy_auth)
    )
    assert mismatched.allowed is False
    assert mismatched.reason is ScopeReason.AUTHORIZATION_ASSET_MISMATCH

    plan = subprocess.run(
        [sys.executable, "-m", "lightup.cli", "plan", "127.0.0.1"],
        capture_output=True, text=True, check=True,
    )
    assert json.loads(plan.stdout)["execution_enabled"] is False

    with tempfile.TemporaryDirectory(prefix="lightup-ci-") as directory:
        store = DomainStore(Path(directory) / "web.db")
        app = create_app(store)

        def get(path: str, cookie: str | None = None):
            env = {
                "REQUEST_METHOD": "GET", "PATH_INFO": path,
                "wsgi.input": io.BytesIO(b""),
            }
            if cookie is not None:
                env["HTTP_COOKIE"] = cookie
            response = {}
            body = b"".join(app(
                env, lambda status, headers: response.update(
                    status=status, headers=dict(headers)
                )
            )).decode()
            return response["status"], response["headers"], body

        status, headers, _ = get("/")
        assert status == "303 See Other" and headers["Location"] == "/login"
        user = store.bootstrap_operator("ci@lightup.test", "CI", "ci-canary-password")
        token, _csrf = store.create_session(user.user_id)
        status, _, body = get("/", cookie=f"lightup_session={token}")
        assert status == "200 OK", status
        assert "Locked" in body and "no real-target execution path" in body

        operator = AccessContext(user.user_id, Role.OPERATOR)
        client = store.create_client(operator, "CI Authorization Canary")
        engagement = store.create_engagement(
            operator, client.client_id, "Revocation canary"
        )
        from datetime import datetime, timedelta, timezone
        now = datetime.now(timezone.utc)
        try:
            store.record_authorization_grant(
                operator,
                engagement.engagement_id,
                approved_by="CI signatory",
                reference="CI-AUTH-EMPTY-CAPABILITIES",
                scope=ScopeDefinition(
                    assets=("canary.example.test",),
                    max_risk=RiskLevel.LOW_IMPACT,
                    allowed_capabilities=(),
                ),
                valid_from=now - timedelta(minutes=1),
                valid_until=now + timedelta(minutes=5),
            )
        except ValueError:
            pass
        else:
            raise AssertionError("empty capability scope was accepted as authorization")

        grant = store.record_authorization_grant(
            operator,
            engagement.engagement_id,
            approved_by="CI signatory",
            reference="CI-AUTH-REVOCATION",
            scope=ScopeDefinition(
                assets=("canary.example.test",),
                max_risk=RiskLevel.LOW_IMPACT,
                allowed_capabilities=("web-baseline",),
            ),
            valid_from=now - timedelta(minutes=1),
            valid_until=now + timedelta(minutes=5),
        )
        policy = ExecutionPolicy()
        request = ExecutionRequest(
            interaction=InteractionKind.TARGET_ACTIVE,
            asset="canary.example.test",
            capability_id="web-baseline",
            requested_risk=RiskLevel.LOW_IMPACT,
            client_id=client.client_id,
            engagement_id=engagement.engagement_id,
            authorization=grant,
        )
        assert policy.decide(request).allowed is True
        store.revoke_engagement_authorization(
            operator, engagement.engagement_id, "CI revocation canary"
        )
        revoked = store.list_authorization_grants(
            operator, engagement.engagement_id
        )[0]
        revoked_request = ExecutionRequest(
            interaction=request.interaction,
            asset=request.asset,
            capability_id=request.capability_id,
            requested_risk=request.requested_risk,
            client_id=request.client_id,
            engagement_id=request.engagement_id,
            authorization=revoked,
        )
        revoked_decision = policy.decide(revoked_request)
        assert revoked_decision.allowed is False
        assert revoked_decision.reason == "authorization is not currently valid"
        assert store.get_current_grant(operator, engagement.engagement_id) is None

        try:
            _loopback("0.0.0.0")
        except Exception:
            pass
        else:
            raise AssertionError("web shell accepted a non-loopback bind")

    assert not Path(directory).exists(), "canary state was not cleaned up"
    print(json.dumps({
        "public_target_denied": True, "execution_enabled": False,
        "private_network_default_denied": True, "private_lab_opt_in_required": True,
        "link_local_private_lab_denied": True,
        "legacy_authorization_asset_bound": True,
        "authentication_required": True, "activation_locked": True,
        "non_loopback_refused": True, "authorization_revocation_enforced": True,
        "explicit_capability_scope_enforced": True, "temporary_state_removed": True,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
