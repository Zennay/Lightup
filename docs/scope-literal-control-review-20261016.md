# Literal authority control characters — isolated scope review (16 October 2026)

## Factual source observation

Unchanged original `main` at `e73b7445c87ad239bdb03c50a99078ef93163b02` uses `urllib.parse.urlparse` in `ScopePolicy.normalize_host`. Python removes embedded ASCII LF, CR and TAB during URL parsing. An in-memory synthetic `Target("local\\nhost")` therefore receives an **allowed loopback** decision; `Target("127.0.0.\\t1")` may similarly normalize to `127.0.0.1`. This is an input identity ambiguity, **not** a demonstrated remote attack or permission to scan.

Original source-authority owner issue [#1289](https://github.com/Zennay/Lightup/issues/1289) / draft [#1290](https://github.com/Zennay/Lightup/pull/1290) owns admission repairs. This independent lane does **not** edit `scope.py`, activation, dispatch or any owner files.

## Delivered independent, runnable safety utility

`src/lightup/scope_literal_control_review_20261016.py` offers pure offline review of a caller-owned builtin tuple of one to 64 exact builtin strings. Rejects all ASCII C0/DEL, invisible Unicode/bidi, leading/trailing/interior ASCII whitespace, polymorphic values, duplicates and oversize strings *without parsing authority or modifying input*. No reflection of input in the result.

`scripts/review_scope_literal_controls_20261016.py` is a bounded stdin-only **fictional** reviewer: exact canonical ASCII JSON `{"authorities":["localhost"]}`, max 8192 bytes, duplicate/unknown/noncanonical fields HOLD. Output is fixed JSON: `REVIEW_ONLY` exit 2 or `HOLD` exit 3, never success exit 0. All consent/authority/dispatch/release flags false. REVIEW_ONLY only means *well-formed for manual offline comparison*, not that any host is safe or authorized.

Run only with fictional data:

```sh
printf '%s' '{"authorities":["localhost"]}' | python3 scripts/review_scope_literal_controls_20261016.py
PYTHONPATH=src python3 -m unittest -v tests.test_scope_literal_controls_20261016
```

The distinct unit suite includes intentionally still-open `expectedFailure` contracts for three original-source policy ambiguities. Tests of a separate reviewer do **not** close those source faults.

## Promotion barrier and ownership

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** No merge/deploy, grants, real scans, real assets, handler dispatch or release. Requires the original source owner to close issues, canonical exact-head hosted plus permanently registered named VPS CI, authenticated independent client+operator consent and at-use revocation, privacy/security review and explicit human GO. Keep review CLI unwired and **never treat its success-like REVIEW_ONLY status as an authorization fact**.

## Additional original-source composition witness

A fourth deliberately open `expectedFailure` proves that the current original `ActivationGate.issue()` may mint an in-memory synthetic LAB_ONLY permit after the lossy scope decision for `local\nhost`. This is an offline object-creation witness only: no executor, network request, real target, activation grant, or handler is involved. The independent AST guard prevents production imports of this unwired reviewer. The existing source owner #1289 owns the actual remediation.

## W4 — conservative encoded-alias and adversarial batch fence

Even a printable fictional candidate is now HOLD when its literal bytes contain `%` or a backslash: future URL/JSON/transport decoders could interpret these as control or identity escapes. This intentionally rejects *more* review inputs and cannot expand a scope. It does not decide whether a hostname is valid and does not replace the existing source-owner admission PR #1290. New isolated `tests/test_scope_literal_encoded_review_20261016.py` proves 64-candidate atomicity, 512 ASCII intrusions, real subprocess stdout privacy, opt-in canonical JSON, and an in-process no-network/no-file/no-process tripwire. Outputs never carry authority, operator/client consent, dispatch or release permissions.

## W5 — 8192-byte RFC JSON boundary and result-state integrity

Added isolated `tests/test_scope_literal_json_boundary_20261016.py` with deterministic exhaustive single-byte mutation of the canonical fictional JSON wire message (all 128 ASCII possibilities at every byte position), assert both hardcoded status outputs carry zero granted authority and never echo input, including with sockets, process spawn and file open forbidden in-process. Exact 8192-byte canonical input succeeds as REVIEW_ONLY (still NOT authorization); an 8193-byte stream fails CLOSED/HOLD. Malformed UTF-8, surrogate JSON escapes, nested JSON objects and 3,000-deep arrays also HOLD. `LiteralReview.__post_init__` now refuses noncanonical and polymorphic status claims before an object can be created. No runtime, grant, network, source-owner or deployment changes.
