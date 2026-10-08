# Scope authorization JSON ambiguity acceptance boundary (2026-10-08)

This is an **offline reference-parser test contract**, not a runtime parser,
policy decision, trusted approval or authorization grant. Its purpose is to
prevent parser differentials between approval intake, persistence, signing,
audit, and dispatch. No active target interaction is permitted by this change.

## Requirements for production source owner

- Reject duplicate object members at **every nesting level**, after JSON escape
  decoding, before mapping to a typed approval or grant. First-wins and
  last-wins behavior are both forbidden for authorization-bearing documents.
- Reject non-standard NaN and Infinity tokens, finite-looking exponent overflows/underflows (for example `1e10000` and `1e-10000`), trailing JSON documents,
  malformed JSON and non-object roots.
- The reference parser uses decimal representation for finite fractions rather than silently converting JSON numbers to binary floating-point; the production owner must define explicit per-field numeric ranges and reject unbounded integer values. Numeric syntax acceptance is not a risk-policy decision.\n- After strict parsing, enforce a versioned allowlist schema, exact primitive
  types, canonical tenant/asset/capability identifiers, bounded document depth
  and size, trusted signer/issuer lineage, immutable revision, and live
  revocation checks. Successful parsing by itself must never grant permission.
- Avoid signing one JSON representation and executing another. Verify integrity
  over an agreed deterministic encoding and exact accepted fields.
- Fail closed and emit tenant-safe audit metadata without logging raw consent
  tokens or other secrets. Do not leak cross-tenant identity details.
- Treat duplicate detection as **one layer**, not as proof against Unicode
  confusables, Unicode normalization drift, oversized integer values, float
  precision loss, or alternate service-side decoders; those need separate
  implementation review and production integration tests.

## Reproduction

`python -m unittest discover -s tests -p 'test_scope_json_duplicate_keys_20261008.py' -v`

This branch changes exactly two additive paths (tests and docs). PR #107 owns
the ToolExecutor and production authorization implementation. Other active
scope PRs own review provenance, revocation, audit and release evidence.
Draft only pending source owner review, exact-head hosted CI and permanent VPS
proof. No production implementation, authorization activation, network request,
scanning or executable tool dispatch is included.
