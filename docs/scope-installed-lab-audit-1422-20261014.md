# Issue #1422 — installed ScopePolicy lab admission audit (W38)

## Scope and intent

A **read-only, opt-in diagnostic of the source in the exact current checkout**, not a deployed-service probe and not a replacement for the source-owner fix in [PR #100](https://github.com/Zennay/Lightup/pull/100).

Source: `src/lightup/scope.py` currently treats `ipaddress.is_private` (which means non-global, not strictly private-use lab) or link-local as `PRIVATE_LAB` membership. Consequently reserved/documentation/benchmarking addresses may be treated as allowed without authorization. That is an actual production-code acceptance gap, tracked in [#1422](https://github.com/Zennay/Lightup/issues/1422) and illustrated in independent expected-RED [PR #1423](https://github.com/Zennay/Lightup/pull/1423).

## Offline use

```bash
python -B scripts/audit_scope_installed_lab_policy_1422_offline.py
python -B -m unittest discover -s tests -p 'test_scope_installed_lab_audit_1422_offline.py' -v
```

No CLI arguments (including `--help`) are admitted, no input files or stdin are read, and no remote addresses are contacted. All checked literals are fictional static in-code examples; loopback/private ranges are **parsed only**, never probed. There is no host-name resolution, socket activity, active executor invocation, customer data, target-specific credential, durable permission/grant mutation, workflow configuration, or deployment.

## Exact outcome

The only stdout is a single minimal JSON line with `status`, `checked_count`, `total_count` and five literal `false` fields:
`authorization_verified`, `permit_issued`, `execution_enabled`, `merge_approved`, `release_approved`.

- **HOLD (exit code 2, checked_count=0):** any unexpected/malformed source result, exception, wrong literal classification, even one forbidden address auto-admitted, or any supplied CLI parameter. Atomic HOLD never claims a partial pass.
- **REVIEW_ONLY (exit code 3):** all fixed positive, negative and disabled-private-lab check cases satisfy the current source-policy behavioral contract. **This still does not grant scope, consent, approval, permit, merge, execution or release.**
- Exit code 0 is impossible by design. Scripts that assume zero means success MUST NOT treat this tool as an authorization prerequisite.
- No failing IP literals, traceback, credential or input arguments are echoed; the static case count is non-sensitive.
- Python 3.11 and 3.14 should run independently to detect `ipaddress` version-dependent classifications. One interpreter's results do not attest to another.


## W39 extension — broad network still requires an authentic grant

The additional third decision per forbidden literal creates an explicit `ScopePolicy(allow_private_lab=False, require_authorization_for_public=True, explicit_networks=("0.0.0.0/0", "::/0"))`, and calls real `decide(Target(literal))` with **no `Target.authorization`**. It must return **`allowed is False` and `reason is AUTHORIZATION_MISSING`**, despite the very broad explicit-network configuration. This specifically guards against a misleading source repair that closes private-lab membership but accidentally lets public or reserved targets through the explicit-network fallback without a grant. This is a simulated no-grant, no-target-I/O scenario — it does **not** test or create a signed real-world customer grant.

The negative matrix now also includes mapped RFC1918 / mapped loopback IPv6 and 6to4 / Teredo transition samples, alongside neighbors on each side of the RFC1918, 127/8 and ULA ranges. Every denial must preserve exact canonical `ScopeDecision`, exact `bool` and `ScopeReason` types, never an outer duck-type. A cross-version difference can only reduce confidence to HOLD, never grant authority. `total_count` is **124** (11 positive × 2 policy configurations plus 34 negative × 3), with `checked_count=0` on any HOLD.

Two new synthetic negative-control tests prove that admitting one public address without a grant, **or returning an incorrect denial reason** in the explicit-network case, forces atomic HOLD. A separate strict synthetic fixture still demonstrates REVIEW_ONLY without ever granting permission. Hosted Python3.11 and 3.14 and separate permanent VPS evidence must be verified on the **new immutable head**; earlier green jobs do not transfer to this revision.

## Safety and ownership

This deliberately evaluates **real unmodified** `ScopePolicy.decide(Target(...))` from this checkout, unlike [#1424/#1425](https://github.com/Zennay/Lightup/pull/1425), which supplies a standalone reference reviewer. It does not write to or import the tool executor, production admission wiring, tenancy logic or the neighboring target parser. All three new files are owned by W38; source-owner #100, RED owner #1423, standalone reviewer #1425, CIDR #1318, CI and runners remain untouched.

Successful green unit tests verify that this diagnostic detects synthetic denial faults. They are not evidence that the **installed policy is fixed**: the currently unsafe source is expected to emit HOLD, not a green release verdict. The source-owner must narrow production IP membership, convert issue #1422 RED assertions to regular passing tests, and obtain independent security/privacy and explicit human review before any activation.

**Project stage: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO MERGE/DEPLOY/SCAN.**
