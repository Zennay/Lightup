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

## W6 — fail-closed stdin read failure

The opt-in review-only CLI now maps `OSError`/`InterruptedError` while reading stdin to the same hardcoded generic HOLD, never a traceback echo of a caller-supplied stream error. Dedicated tests prove one bounded read of exactly 8193 bytes maximum, no stdout data leak, partial stream HOLD and four authority/release flags false. The no-socket, no-child, no-file-open tripwires cover this error path too. This is only offline reliability, never an authorization or execution upgrade.

## W7 — deliberately isolated Python 3.11 / 3.14 hosted proof

Added a **branch-specific push-only** GitHub-hosted workflow `.github/workflows/scope-literal-controls-20261016.yml` to test exactly this worker's new files without a pull-request event, canonical permanent self-hosted queue, existing source-owner workflows or any real target. It pins upstream checkout/setup-python actions by immutable SHA, uses no persisted checkout credentials, grants `contents: read` only, verifies checked-out commit equals the pushed SHA, runs compile/tests on Python3.11 and 3.14, checks the production baseline's three small scope/policy unit files and confirms CLI-only exit 2/3 with fixed false-authority JSON. This is *isolated laboratory proof*, never full original LightUp CI, permanent registered VPS evidence or authority to merge/deploy.

## W8 — complete framed stdin, short-read and suffix-replay safety

A single `read(8193)` was insufficient for general stream implementations: a short read could reject valid fragmented canonical JSON, or prematurely accept a complete-looking prefix while later malicious suffix bytes remained unread. New `_read_bounded` strictly reads until EOF, tracks a hard 8192-byte aggregate cap, requests at most 1024 bytes at a time, and denies polymorphic/non-byte, over-returning, interrupted or malformed fragments. New separate isolated regression pack covers synthetic one-byte reads (8192 and 8193 boundary), short fragments, a valid prefix followed by a trailing second packet/whitespace/NUL, read error after an apparently valid prefix, and no sockets/files/processes. Zero changes to original admission or execution layers; the opt-in CLI is still no-authority with exit2 REVIEW_ONLY and exit3 HOLD only.

## W9 — output-delivery fail-closed contract

CLI `_emit` checks exact written-byte count and flush success. A broken pipe, short write, invalid write-result type or failed flush returns non-success exit 3; no exception detail or input is echoed or retried. A partial OS output cannot be retracted, so downstream clients must enforce complete canonical JSON and the explicit exit code; this remains strictly review-only and not an authorization token. The new dedicated offline tests exercise successful exact HOLD/REVIEW_ONLY wire messages and artificial output failures with network, subprocess and local file opens forbidden.

## W10 — atypical stdin/stdout adapter error fail-closed boundary

Synthetic tests reproduced unhandled `AttributeError`, `TypeError`, `ValueError` and `BufferError` when adapter APIs were missing or failed, including closed stdout. The opt-in CLI now uses a strictly enumerated read/write exception fence: stdin adapter failures yield a generic HOLD where an output channel exists, while stdout failures force exit3 without leaking exception details. Six new tests isolate each broken adapter, with in-process socket, process spawning and file-open tripwires. `KeyboardInterrupt` and `SystemExit` remain outside these exception fences and are not reinterpreted as successful review. No runtime authorization, grant, network or original source-owner code changed.

## W11 — conservative case/dot collision + userinfo HOLD

This *text-review-only* layer now conservatively HOLDs duplicate ASCII spellings differing only by letter case or terminal dots and any literal `@` (userinfo confusion). It does not parse destinations, prove DNS equivalence or authorize targets. Five dedicated methods confirm e.g. `fictional.test` + `FICTIONAL.TEST`, dotted case variations, and pasted `operator@localhost` all atomically HOLD with a non-echoing result, while unrelated distinct fictional values remain REVIEW_ONLY without consent/grant. Production source-owner #1289/#1290 controls actual strict target admission and is not modified.

## W12 — own-workflow compile coverage maintained automatically

The dedicated branch-only GitHub-hosted matrix now compiles **all** `tests/test_scope_literal_*20261016.py` owned test modules by glob, not merely a stale hand-maintained subset. The restricted tests remain a distinct offline review lane and do not claim permanent VPS or full-project approval. This change is confined to the already-owned isolated workflow and documentation.

## W13 — no ignored authority-looking CLI flags

An otherwise valid fictional stdin packet previously yielded REVIEW_ONLY when the caller supplied unknown CLI flags such as `--grant=true`, `--mode authorized` or `--dispatch`, because the opt-in executable silently ignored arguments. Its `__main__` gate now requires exactly the interpreter-provided script path in `argv`; any extra option/positional input yields the generic non-echoing HOLD with exit3 **before reading stdin**. New real-subprocess tests cover eleven representative confusing flags, an ordinary flag-free REVIEW_ONLY, and malformed stdin. No new commands or authority are enabled; the in-process unit API remains a narrow test seam, not a public CLI mode.

## W14 — query/fragment text ambiguity cannot become review-eligible

Added a conservative offline HOLD fence for `?` and `#` in exact fictional authority strings. A human review packet is not a URL parser, and query/fragment delimiters may disappear or change meaning in a later parser; accordingly the entire batch is rejected, with no candidate echo or authority/consent/dispatch/release. Three dedicated tests first reproduced ordinary REVIEW_ONLY on synthetic `fictional.example.test?mode=other` and `https://localhost/#allow`, then verified the stricter output and a still-eligible plain fictional control. This does not decide legitimate URL admission and does not modify source-owner #1289/#1290.

## W15 — independent deterministic randomized eligibility oracle

Added an independent regex/ASCII-casefold reference for conservative review eligibility, separate from the production review implementation. A deterministic 1,200-batch fictional seeded corpus plus every ASCII-byte insertion at three positions in first/middle/last entries of a 64-entry batch checks for result mismatches, result privacy and four always-false authority/consent/dispatch/release fields. The corpus is repeatable in both Python interpreters, does not use real targets or network and does not prove real scope admission correctness. Actual source owner #1289 remains responsible for admission.

## W15 — independent deterministic review-status oracle (already pushed)

The branch added synthetic-only mutation proofs in `test_scope_literal_metamorphic_20261016.py`: a separate regular-expression oracle, three locations on three distinct members of a full fictional 64-item batch, every ASCII byte, and 1,200 seeded independent batches. Every output remains non-authorizing; this is an offline status invariance test and no production admission fix.

## W16 — AST import-path isolation proof

Added strictly offline `test_scope_literal_runtime_isolation_20261016.py`. It scans original application Python ASTs and rejects direct import, relative import, from-package imported module alias, literal `__import__`, and literal `importlib.import_module` loading of the owned offline reviewer. It includes synthetic positive and negative shape tests so a future from-list import cannot silently bypass the existing naive AST guard. It intentionally cannot prove safety against computed strings, runtime reflection or `eval`; static proof is NOT a sandbox, authorization fact or production integration approval. It never executes application modules or calls a network.

## W17 — fold only statically literal module-name expressions

Five test cases proved the earlier AST-only reviewer-import fence missed directly reconstructable module names: adjacent constant string concatenation, literal f-strings, and literal `getattr(importlib, 'import_module')`. The guard now reconstructs only bounded, fully static AST string expressions (maximum 256 chars) and checks these additional import-call shapes. It does NOT execute imports or evaluate expressions. Computed variables, reflective imports and `eval` are deliberately outside this static proof; no claim of comprehensive runtime isolation. Original source-owner files remain untouched.
