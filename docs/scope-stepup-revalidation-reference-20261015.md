# #1173 — synthetic snapshot revalidation after an untrusted isolation probe

**State: DRAFT/HOLD · INCUBATE M3/M7 · PLAN/LAB ONLY.**
This is an **uninstalled offline race reference**, not a production safety repair, a permission system or an attestation of actual lab isolation.

## Ownership and files

This isolated branch adds three new paths only:
- `lab/scope_stepup_revalidation_reference_20261015.py`: pure in-memory review oracle.
- `tests/test_scope_stepup_revalidation_reference_20261015.py`: deterministic race, type and expiry regressions.
- This document.

It does **not** change [the #1172 operator step-up producer](https://github.com/Zennay/Lightup/pull/1172), [the #107 canonical executor](https://github.com/Zennay/Lightup/pull/107), [the independent #1451 real-executor RED acceptance](https://github.com/Zennay/Lightup/pull/1451), main, workflow YAML, ingress, runners, deployments or any customer records.

## What the reference actually checks

Only `lab-*` fictional identifiers can be loaded. Both exact-built-in datetime boundaries must be timezone-aware, strictly ordered and current. The synthetic review claim must exactly match run, tenant/client, engagement, asset, tool, capability and risk-5 reference. A separate tool-registry snapshot must match the requested tool/capability/risk.

A deliberately external `isolation_probe` callback runs **after** taking an epoch snapshot and **before** the final synchronized state comparison. Any update, revoke, reissue of the same values (ABA), or tool replacement increments the epoch. Revalidation atomically rejects changed epochs and claim/registry mismatches. All failures yield a generic `HOLD` object without customer fields. A consistent fictional snapshot yields only `REVIEW_ONLY`, never authority.

All six receipt flags are **literally false**: `authorization_verified`, `permit_issued`, `execution_enabled`, `dispatch_allowed`, `merge_approved` and `release_approved`. The sole side effect is a local in-memory review counter; no network, disk, database, subprocess, DNS, target, handler or exploit operation exists.

## Verification

Run from repository root:

```sh
python -m unittest discover -s tests -p 'test_scope_stepup_revalidation_reference_20261015.py' -v
```

The thirty-one tests cover matching synthetic snapshot (review-only), revoked/missing grant, both temporal boundaries, seven mismatched identities, tool swaps, bad probe outcomes, same-thread revoke/swap/reissue, two synchronized cross-thread races, four-round concurrent four-reader revocation fanout, tool-registry ABA, revoke/restore ABA, and two frozen-request mutation/laundering canaries, caller-object mutation, wrong datetime values, string subclass/boolean/polymorphic shapes and redacted output.

The normal full project suite may run on GitHub-hosted CI. **Never conflate hosted tests with registered permanent VPS proof** or green unit tests with production safety.

## Critical remaining gaps: not solved here

1. The *current production/executor source* can still execute the wrong handler after review. This reference **does not lock across actual callback/handler invocation**. A last check on its own cannot close a post-check race; the executor owner must implement atomic/transactional registry + approval resolution across real admission/dispatch, including revocation.
2. Actual operator-only durable approval issuance, expiry/revocation, authentication, stable run/client/engagement/asset/tool/destination provenance and risk authority must be sourced from trusted persisted systems, not model data, local lab strings or an in-memory reference.
3. An installed, independently verified isolation/egress gate is required. Calling `isolation_probe=lambda: True` in these tests **never** proves physical/virtual machine isolation.
4. Every real executor entry point (including raw ToolExecutor), any actual handler and evidence persistence must deny before side effects on revoked/stale/mutated/untrusted state. Preserve original input and exact source identity; do not promote intentionally failing #1451 RED canaries to release evidence.
5. Owner integration, independent privacy/security review, exact integrated SHA hosted Python 3.11/3.14 + producer integration, a separately **permanently registered** VPS runner execution, and explicit human GO remain absent.

**Never merge, deploy, activate, issue real grants, scan real targets or claim a release pass from this reference.**

## Observed first hosted preflight (superseded before W2)

The first exact SHA `5c40664050fb6458d1553b167d303ce4b4aa8176` hosted preflight [#38760164774](https://github.com/Zennay/Lightup/actions/runs/38760164774) executed all 15 original new test methods **OK** on both Python 3.11 and 3.14. The full suite ran 1,252 tests and failed one **unrelated pre-existing** `test_scope_legacy_falsy_window_301_red_20261014.test_all_inputs_remain_unchanged_after_pure_scope_decision` because its fixed expiry time had elapsed; the owning [#301/#1452](https://github.com/Zennay/Lightup/pull/1452) fixture fix has not been imported. Producer jobs were skipped; overall check was FAILED, not green. W2 adds three own race methods (18 total) on a new immutable head: do not apply the older CI receipt to W2. Do not edit the fixture owned by another PR.

## W3 hardened caller identity (20 own tests)

The mutable caller-owned ReviewRequest is now copied to a fresh exact ReviewRequest **before** invoking any isolation probe. After the callback the reference rejects even a matching-looking mutated request, including a formerly out-of-scope request rewritten to match the trusted snapshot. This protects the in-memory **review-only** verdict against in-process data mutation; it does not authorize I/O or close real executor check/use races. New tests specifically corrupt the original frozen dataclass using `object.__setattr__` on both originally valid and originally invalid claims. All current hosted receipts from earlier immutable heads are superseded until this exact latest SHA is verified.

## W4 timezone callback safety

Only exact built-in fixed-offset `datetime.timezone` objects are accepted on review-window and evaluation timestamps. Custom `tzinfo` subclasses (including those capable of triggering arbitrary callbacks, errors or resource access) are rejected before invoking `utcoffset`, including while the ledger lock is held. An additional synthetic test uses a custom timezone that raises on invocation and proves **zero calls**. This conservative offline shape rule can reject otherwise sensible IANA `ZoneInfo` times; it does not replace the source owner's production time-policy design. A new exact-SHA run is required; the previous W3 checks cannot validate W4.

## W5/W6 synthetic seal, required isolation probe and fresh-time callback

A reviewer can no longer emit even `REVIEW_ONLY` without an explicitly callable `isolation_probe` returning the literal built-in `True`. Stored approval and tool snapshots have separately pinned immutable tuples of exact field values. This detects in-place tampering of supposedly frozen Python dataclass instances (including widening the original expiry timestamp) that does **not** increment the normal epoch. The tuples are **diagnostic canaries**, not a secure enclave: arbitrary Python code with access to the same process can still rewrite other private attributes or race after the final check.

A caller may additionally pass `fresh_clock_probe` to obtain a second synthetic datetime observation **after** the isolation callback. It must return an exact built-in aware datetime with an exact fixed-offset `timezone` and cannot move backward relative to `now`. If the new instant is at or beyond the exclusive expiry, the whole review yields `HOLD`; the clock callback runs outside the ledger lock, and revocation while it runs invalidates the epoch. Missing optional freshness callback intentionally means the initial **synthetic fixed instant** is used; thus `REVIEW_ONLY` must *never* be interpreted as current live consent or proof of freshness. A source owner must provide a trusted time source and verify immediately before real dispatch. The offline race oracle itself does not do so.

Ten new methods cover missing/noncallable isolation probes, approval expiry/registry in-place tampering, unchanged callers, only-once valid probe, expired/valid post-callback time, malformed/non-monotone times, revocation during clock read and invalid/erroring callback. Own suite now **31** tests, pending exact latest-head hosted verification. All previous run receipts are superseded.

**Release fence remains DRAFT/HOLD.** No customer identities, network endpoints, production wiring, grants, permissions, real I/O or scanning.
