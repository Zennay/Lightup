# Scope #1563 — membership before grant substitution (offline acceptance)

**Stage:** INCUBATE M3/M7 · PLAN/LAB ONLY · **DRAFT/HOLD**.

**Links:** issue [#1563](https://github.com/Zennay/Lightup/issues/1563), original membership-first contract [#364](https://github.com/Zennay/Lightup/issues/364), separate documentation-only [PR #1263](https://github.com/Zennay/Lightup/pull/1263). Runtime source/grant owner is still [PR #100](https://github.com/Zennay/Lightup/pull/100).

## What this actually enforces

The single **new** regression file `tests/test_scope_membership_metamorphic_20261017.py` uses fully synthetic target strings and grant objects. It changes only a target's attached legacy `Authorization` or a policy's `require_authorization_for_public` flag and proves that neither makes an **undeclared** hostname/IP become a member of the explicit host/CIDR allowlist. Missing and malformed targets remain `INVALID_TARGET`.

Each negative decision must:
- be `allowed is False`, with the precise `OUT_OF_SCOPE` or `INVALID_TARGET` reason, not a misleading missing/expired-grant reason;
- leave the input `Target` / `Authorization` unchanged;
- never call `Authorization.is_current`: authorization evaluation is downstream of membership;
- never invoke DNS, socket connection, or urllib HTTP entry points (fail-fast patched sentinels).

Metamorphic dimensions: public hostname/IPv4/IPv6/URL lexical forms; no grant/current/expired/future grant; public authorization required/disabled; private-lab flag enabled/disabled for public IPv6; unrelated hostname allowlists; disjoint IPv4/IPv6 CIDR allowlists; invalid/blank target identity; spoofed `Target.labels` and an authorization-shaped object that raises if accessed.

**Not covered / not asserted:** which legacy authorization fields, assets, provenance, revocation epoch, or approval steps may enable a *positive* declared-public-target decision. Those belong to live source-owner #100/#107 and other branches. The tests are **negative-only**, not an alternative source of authorization.

## Exact execution commands (offline; no target I/O)

```sh
python -m compileall -q tests/test_scope_membership_metamorphic_20261017.py
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_membership_metamorphic_20261017.py' -v
```

Run on original main plus this add-only branch; the dedicated new GitHub-hosted workflow pins its checked-out PR head SHA. Compare separately with the owner-source branch before claiming integration. An older green run is never evidence for a changed head.

## Stop conditions

No existing `src/lightup` sources, `tests/test_scope.py`, shared workflows, state/database, activation, execution, target workers, deployment or peer-worker files are modified. Scope #364 and existing PR #1263 remain independent. A green negative unit suite **is not** evidence of usable positive authority, authenticated two-party consent, at-use revocation, independent security/privacy review, passing full exact-head hosted plus registered VPS CI or HUMAN GO.

**Never merge, deploy, activate, scan, issue grants, dispatch handlers, or release solely on this contract.**
