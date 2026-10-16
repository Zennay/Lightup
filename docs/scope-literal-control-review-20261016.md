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
