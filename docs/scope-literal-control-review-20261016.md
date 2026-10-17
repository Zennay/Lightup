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

## W18 — equivalent RFC JSON spellings never silently change review meaning

Added a distinct in-process canonical wire acceptance pack: 4 tests covering every possible ASCII whitespace insertion at every position of a two-candidate fictional packet, JSON unicode escape aliases and escaped object keys, duplicate object keys, noncanonical punctuation, BOM/extra bytes, reversed independent candidate ordering and batch case/dot collisions. Every alternative byte spelling is evaluated without sockets, file opens or subprocesses; only exact canonical review input returns REVIEW_ONLY, always with all authorization/consent/dispatch/release fields false. The input is never echoed in HOLD output. This is input integrity evidence, not a parser-derived authorization or authentication.

## W19 — strict isolated hosted evidence manifest

The own branch-only hosted workflow now runs `scripts/check_scope_literal_suite_20261016.py` instead of accepting a bare unittest zero exit as sufficient. It snapshots discovered tests, checks that every `test_scope_literal_*20261016.py` own module is actually discovered, rejects skips, missing/duplicate test IDs, unexpected failures and additional expected failures, and pins exactly four **original-source** expectedFailure IDs (which remain unrepaired). An explicit minimum count of 77 detects accidental removal of a substantial part of this suite. Six separate synthetic manifest tests deliberately inject missing modules, skipped tests, missing/extra RED witnesses and other failures to prove HOLD, without runtime imports, scans or targets. A PASS is still solely an isolated diagnostic; it confers neither permission nor full project / permanent VPS evidence.

## W20 — parallel-worker branch ownership proven from Git diff

The isolated branch-only hosted workflow now checks full-history SHA-pinned checkout and computes `origin/main` versus the exact checked-out HEAD, with a required ancestry relationship. `scripts/check_scope_literal_branch_20261016.py` demands that *every* delta be an ADD of only explicitly owned offline reviewer, test, doc or isolated workflow paths. Changes, deletes, renames, foreign worker files, production scope/activation, test naming drift, malformed UTF-8/NUL diff output and disappearing required own paths all cause `scope_owned_additive_branch=HOLD` with nonzero exit. Four independent unit methods verify representative malicious changes, truncated or duplicate manifest entries and valid exclusively own additions. This is a non-authorizing CI workstream conflict tripwire, not complete supply-chain or security proof. It does not touch any production source, self-hosted runner or other worker branch.

## W21 — stop replayed original-source expected failures masquerading as evidence

The original strict manifest's expected-source-RED verification used a set and therefore accepted a duplicate replay of one of the four known expectedFailures as valid evidence. New own negative acceptance first demonstrated that false positive, then the check was corrected to require both the **exact four unique RED IDs and exactly four actual expectedFailures**. The hosted minimum owned-suite count is now 88, including a dedicated synthetic replay test. This gate hardening cannot repair original authorisation flaws, authorize assets, or substitute for exact full and named VPS CI.

## W22 — alias-bound literal dynamic imports cannot bypass inert-reviewer isolation

Four synthetic regression cases first demonstrated that the original AST guard failed to detect `import importlib as il`, `from importlib import import_module as load`, constant concatenation through the aliased importer, and literal `getattr(il, 'import_module')` calling the offline reviewer. The revised *strictly static, non-executing* guard now recognizes statically imported aliases and applies the earlier bounded literal-only module-name rule. Runtime reflection, function reassignment, and computed variables remain OUTSIDE the proof; this does not confer authorization or alter production imports.

## W23 — detect accidental promotion in unrelated application scripts

The static-only isolation test now scans *both* normal application Python modules and the project scripts directory. It excludes only this worker's explicitly named inert opt-in CLI and its two diagnostics; any direct/literal import of the offline reviewer in another script causes an isolated test failure. The test also requires that all three explicitly excluded helpers actually exist, preventing overly broad exclusions. This is additive QA for unintended wiring, not a replacement for runtime security review or complete code-flow proof.

## W24 — pin all prior owned test modules against silent deletion

A new synthetic RED showed the count-based strict evidence gate could still return PASS after an entire old owned test module vanished, provided enough remaining tests were discovered. The gate now requires the complete pinned **15-module** original review-test inventory, separately from the actual dynamically discovered module set, exact four original source RED identities and new minimum test count of 90. The negative test removes one previously registered module while keeping test count unchanged; it now correctly HOLDs. New test files may still be added. This is an own-lane CI completeness contract, not full-project verification or permission to deploy.

## W25 — exact Git tree blob modes, no symlinks or submodules

The previous branch ownership fence checked names and add-only status but did not inspect each object's Git mode. A newly-added symlink (`120000`), executable blob (`100755`) or gitlink/submodule (`160000`) at an otherwise approved path could have passed the name-only proof. New `safe_tree` compares the *exact* names from the NUL-delimited add-only Git diff against a SHA-pinned HEAD `git ls-tree -r -z`, and requires every corresponding mode/type to be precisely `100644 blob` plus an ASCII 40-digit hexadecimal object ID. Malformed/missing/duplicate/foreign tree records all HOLD. Five dedicated synthetic tests cover those cases and the live local branch check reports PASS. This verifies only our own branch’s stored tree object metadata, not any real authorization, merge safety or runtime sandbox.

## W26 — newly introduced tree-mode checks become mandatory CI evidence

After adding the independent `test_scope_literal_git_modes_20261016.py` module, the held branch's fixed evidence inventory was upgraded to **16 required owned test modules** and a strict minimum of 96 executed tests. A new negative check explicitly attempts to remove the Git-mode test module without lowering aggregate test count; the evidence gate now HOLDs. The 96-test Python 3.14 isolated local run passed with exactly 4 open original source expectedFailures. No runtime components were activated.

## W27 — reject literal builtins import aliases in offline AST isolation

Four new deliberately RED synthetic samples showed the offline AST proof had overlooked `builtins.__import__`, `import builtins as bi`, `from builtins import __import__ as loader`, and the static `getattr(bi, '__import__')` shape. The strictly non-executing guard now collects those directly imported aliases and recognizes fully literal target strings in their call shapes. This is **not** complete proof against arbitrary reflection/rebinding/computed imports; it does not wire the reviewer, touch production source, or authorize execution. The strict isolated suite minimum rises to 97 to account for the new regression method.


## W28–W29 — keyword-only, runpy and pkgutil static loader gaps (17 October 2026)

The independent static test of *unwired* scope review first missed Python's
`importlib.import_module(name=...)` and `__import__(name=...)` forms. Two
synthetic tests exposed keyword-only loader calls and documented a negative
control for a local, unrelated function named `import_module`. A dedicated
fix now recognizes the exact statically literal `name=` while avoiding that
local function false positive. This is a guard for code review, **not** runtime
sandboxing and **not** a production authorization change.

A further isolated test+fix covers literal `runpy.run_module` (including
`mod_name=`) and `pkgutil.resolve_name`, direct imported aliases, module
aliases and literal `getattr` variants. The latter checks fictional dotted
member lookup and `module:symbol` spelling. Only fully static module names
qualify for this AST fence; computed names, indirect references, monkeypatching,
`eval` and dynamically loaded plugins remain explicitly **unproven**. No
application modules are imported or executed during this check.

The CI manifest now requires **101 distinct discovered owned tests**, including
all existing 16 isolated modules and exactly four still-open *original source*
expectedFailures. Actual registered-VPS-local Python 3.14 run after W29:
`scope_owned_additive_branch=PASS`,
`scope_review_isolated_proof=PASS tests=101 ordinary_pass=97 expected_source_reds=4`;
no unexpected test errors. Full original LightUp CI and permanent named VPS
runner validation are not represented by this count; dedicated hosted status
must be checked independently for the exact final commit.

All changes remain exclusively in the pre-existing owner-owned offline static
review test module, own suite gate and this own documentation. Original target
admission source owner [#1289](https://github.com/Zennay/Lightup/issues/1289),
other parallel workers, installed runtime and deployment remain untouched.
**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD — NO MERGE, REAL ASSET,
SCAN, GRANT, CONSENT CLAIM, HANDLER DISPATCH OR RELEASE.**
