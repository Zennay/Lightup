# #1565 — Canonical scope-decision offline witness (DRAFT/HOLD)

## Purpose and ownership

This is an **independent offline diagnostic** on the immutable base `e73b7445c87ad239bdb03c50a99078ef93163b02`. It reads the current checkout's real `ScopePolicy.decide()` and `ScopeDecision` but never modifies the scope evaluator or auth state. New files are limited to the `scope_offline_authority_witness_20261017` script/test and this doc. Active owner branches and PRs (including #1564, #1538, #1486 and #346) are not rewritten.

LightUp remains **INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD**. The witness is neither customer consent nor operator signoff nor authorization of any asset. Its `REVIEW_ONLY` is *not* a GitHub merge-go, grant, execution, security-review, deployment or release verdict.

## Execute locally in a disposable checkout

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v tests/test_scope_offline_authority_witness_20261017.py
PYTHONDONTWRITEBYTECODE=1 python3 scripts/scope_offline_authority_witness_20261017.py --offline-lab-only
```

On an installed canonical evaluator that matches the fixed matrix, the CLI emits exactly one sorted ASCII JSON object:
- `schema=lightup.scope-offline-decision-witness.v1`
- `status=REVIEW_ONLY`, `reason=canonical_synthetic_matrix_matches`, `checked=11`, a SHA-256 of ordered observed synthetic classifications
- `client_consent_verified`, `operator_consent_verified`, `authorization_granted`, `dispatch_allowed`, `scan_allowed`, `deployment_allowed` and `release_allowed`: exact JSON `false`
- exit status **3**, never 0.

With missing/malformed opt-in, a changed decision (allow, reason, host), bad shape/schema or evaluation exception, the result is `HOLD`, with a generic failure reason, seven false authority flags, no matrix hash, and exit status **2**. No input/exception text, URL, IP or consent reference is emitted.

## Real test surface

The fixed in-memory matrix uses loopback IP/hostname, private lab IP (allowed and lab-disabled), out-of-scope public IP, a synthetically allowlisted `.example.test` hostname with and without a **fictional, unsourced** `Authorization`, explicit public CIDR with and without that same fictional object, removed explicit-host allowlist, and blank-target denial.

This is a deterministic **behavior witness**, not a proof that the policy is secure for all targets. Canonical examples with a synthetic authorization show existing `ScopePolicy` semantics in an **offline unit invocation only**. They do not create grants or prove that an actual human approved any asset. No DNS, socket, HTTP, scan, subprocess handler, credentials, database, production data or target-capable runner step occurs in the witness itself. The subprocess regression launches only another Python process running the same offline witness.

## Gate interpretation

- Green unit tests validate the witness's own classification, deterministic receipt, zero-network boundary, no authority flags and mutation-detection sensitivities.
- `REVIEW_ONLY` cannot release any blocker. Source-owner #301 time-gate defects, other open source REDs, independent authentic client/operator approval, at-use revocation, review, correct hosted + named registered permanent VPS exact-head CI and explicit HUMAN GO remain required.
- **Do not merge/deploy/scan/grant/dispatch/release** this issue's code merely because the witness passes.
