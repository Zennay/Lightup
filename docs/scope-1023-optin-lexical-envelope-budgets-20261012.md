# #1023 opt-in lexical budget screen — isolated prototype / no authority

**Project:** LightUp Incubate M3/M7, PLAN/LAB ONLY. Source owner remains #107; parent [DRAFT #1012](https://github.com/Zennay/Lightup/pull/1012) must not be modified by this child. Nothing here is wired to WSGI, the planner, domain store, a grant provider, ToolExecutor, or deployment.

## Why this slice exists

The #1012 `bounded_envelope` predicate checks raw-byte budget before calling `json.loads`, but enforces `max_nodes` and `max_depth` only after allocating the parsed tree. Two deliberate `@expectedFailure` tests in `test_scope_1023_preparse_resource_gap_20261012.py` record that property and deliberately remain unmodified: those tests must not be promoted into green claims about the original parser.

The standalone, opt-in `lightup.envelope_preflight_optin_1023.bounded_envelope_shape_optin` demonstrates a narrowing, *non-authorizing* alternative:

1. Fail closed on any non-built-in `bytes`, malformed limits (including `bool`, `float`, zero/negative), or bytes above a configured ceiling **before UTF-8 decode**.
2. Strict UTF-8 decode. Scan the JSON lexical grammar iteratively without materializing a dict/list tree; reject malformed separators/escapes/tokens, a non-object root, excessive depth or value-node counts **before `json.loads`**.
3. A JSON object/list/primitive **value** counts as one node, but member-name strings do not; the root object has depth one. Child values have parent-depth +1. Byte/depth/node ceilings are inclusive.
4. Only after preparse budget admission, call `json.loads` with duplicate-key rejection at every nesting level and rejection of `NaN`, `Infinity`, malformed escapes and trailing input. Rewalk the parsed tree, reconfirm budgets and reject float exponent overflow to `inf`.
5. Return a bare `bool` identifying a JSON **shape candidate**, **not** trusted consent, current authorization, a grant or an executable capability. No wrapper for issuer, tenant, live revocation or STOP exists. The correct usage in this phase is only offline unit tests and source-owner review.

This prototype reduces the **full JSON tree allocation before depth/node rejection**, but does **not** establish a hard peak-memory/RSS bound, CPU constant-time behavior, byte budgets suitable for actual traffic, or automatic protection against all parser resource attacks. UTF-8 decoding, string grammar traversal, full JSON parse of admitted documents and a postparse pass still allocate/use resources within a configured raw byte ceiling. A security/source-owner review must select actual limits and may require a streaming decoder, not this prototype.

## Verification

`tests/test_scope_1023_preparse_optin_scanner_20261012.py` covers limits before `json.loads` using a parser spy; inclusive ceilings, keys-vs-values and nested containers; many malformed grammar/UTF-8/duplicate keys; numeric overflow; legal JSON escapes and Unicode; original #1012 predicate parity on bounded legitimate samples; and unchanged input / shape-only forgery. Compare exact-head hosted 3.11/3.14 CI and canonical permanent VPS results separately.

**Promotion acceptance:** original #107 and any future real authorization-envelope endpoint owner must confirm entrypoint and trusted issuer/tenant/grant/scope/expiry/revocation/STOP admission. Prove denial before any queue/write/handler/socket; real multi-tenant SQLite, realistic request streaming / true memory limits, security/privacy review, current-main composition, independently completed permanent VPS CI, and explicit human approval. Do not activate any target interaction to test this library.

**Always DRAFT/HOLD/NO MERGE/NO DEPLOY, issue #1023 OPEN.**


## 2026-10-13 W7: Unicode scalar-value admission before JSON parse

The original Python standard-library decoder can produce **unpaired UTF-16 surrogate code points** from textual \`\uD800\` or \`\uDC00\` escape sequences. Such isolated code points are not Unicode scalar values, can break downstream encoding and make canonical issuer/tenant/object-key comparisons ambiguous across components.

The isolated opt-in lexical scanner now **rejects a high surrogate escape that is not followed immediately by a well-formed escaped low surrogate**, as well as every unpaired low surrogate escape. It applies the same rule inside JSON **member names and values**, before calling \`json.loads\`. Paired \`\uD83D\uDE00\` escapes and ordinary literal UTF-8 supplementary-plane characters remain shape-eligible. A syntactically legal literal backslash-plus-\`uD800\` string is not misclassified as a real Unicode surrogate escape.

Added \`tests/test_scope_1023_optin_unicode_scalar_20261013.py\` (**8 methods**, multiple synthetic cases) covering high/low surrogates at nested depths and in keys, malformed combinations, valid high+low pairs, valid BMP/literal Unicode, and exact budget/parser-order guarantees.

**Compatibility decision required:** this is an intentional **stricter-than-Python-json narrowing** for the optional prototype, and is *not* asserted to be already required or installed by existing production API consumers. The source owner must decide canonical JSON/Unicode semantics before selecting or wiring any parsing boundary. The unmodified #1012 original reference still has its two intentional depth/node postparse RED canaries. No real issuer, tenant, grant or active-target authorization is conferred.


## 2026-10-13 W8: denial-order mutation coverage and real SQLite non-authority

The isolated opt-in preparse contract now has additional **add-only** acceptance files:

- `tests/test_scope_1023_optin_lexical_mutations_20261013.py` (**12 offline methods**) tests malformed object and array separators, invalid number/literal endings, invalid string escapes, partial/multi-document framing, non-object roots, exact nested node/depth bounds, deterministic mid-document truncations, malformed UTF-8, budget types including nonfinite float, multibyte UTF-8 ceilings, and legal escaped/literal Unicode equivalence. For inputs the grammar can recognize as invalid or over-budget, a mocked `json.loads` verifies **no full tree materialization** occurs.
- `tests/test_scope_1023_optin_real_wsgi_non_authority_20261013.py` (**9 real default WSGI + disposable SQLite methods**) demonstrates that **even shape-positive JSON** claiming `approved=true`, risk 5 or a forged tenant is refused at current form-only grant/request endpoints, with **unchanged durable grants, requests, sessions, engagements, approvals, users and clients**. Escaped Unicode pairs, bad surrogates, escaped-duplicate keys, malformed URL-encoded form, anonymous form attempts, invalid Content-Length and transfer framing are covered. These tests exercise the **current installed code in an in-process offline WSGI harness**, not a real Nginx/Gunicorn deployment or a future JSON-envelope production endpoint.

**No semantic authority is ever inferred from `True` returned by the optional shape parser.** This remains a non-authorizing demonstration, not a replacement for trusted issuer, tenant, current same-engagement persisted grant, risk, scope/asset/capability, revocation, STOP and human consent. In production, source owners must implement those checks atomically at actual intake/dispatch boundaries. Running synthetic tests does not authorize active target interaction, network access, scan initiation, grant issuance, merging or deployment.


## 2026-10-13 W9: controlled synthetic memory/time diagnostics (NOT an RSS guarantee)

New **uninstalled/read-only** `src/lightup/envelope_profile_optin_1023.py` contains a manual offline check:

```sh
PYTHONPATH=src python -m lightup.envelope_profile_optin_1023
```

It creates five **local, deterministic, synthetic** JSON objects with varying list cardinality and configured node budgets, calls only the isolated non-authorizing shape preflight, and prints **sample elapsed nanoseconds and Python `tracemalloc` peak bytes**, not raw buffers or customer data. It refuses non-built-in `bytes`, any diagnostic body larger than 256 KiB, and an already-running `tracemalloc` session; it preserves the caller bytes and tears down its own tracing after each sample. Its metrics set `metrics_are_release_proof = false` explicitly. It has no network, WSGI, grant database, real targets or executor connection.

**Measurement limitations:** elapsed time varies by machine, process load and Python version; `tracemalloc` measures traced Python-managed allocations and cannot capture all native allocations, OS page cache, process peak RSS, resident memory of HTTP proxies, streaming server buffers, CPU scheduling or host-level denial-of-service. The 256 KiB diagnostic input cap is **not a recommended production request budget**. Only independent representative traffic profiling and a production source-owner security review can establish acceptable end-to-end limits.

New `tests/test_scope_1023_optin_profile_20261013.py` (**10 tests**) validates shape-positive and budget-negative samples, cap/type rejection, preservation of an existing profiler, cleanup, five deterministic fixtures, raw-buffer immutability, and reporting which never asserts authorization. Neither this diagnostic nor a parser `True` is consent, an authorization grant or permission for a tool/scan.

## 2026-10-13 W10: decoded duplicate JSON names denied before full-tree parsing

The standalone, uninstalled `envelope_preflight_optin_1023.py` lexical scan now tracks the **decoded** member names of each JSON object in a distinct, input-byte-bounded set. It uses `json.decoder.scanstring` solely for the current JSON **key** after validating string syntax; it **does not invoke `json.loads`**, allocate the whole JSON tree or infer any authorization during duplicate checking. Keys are **not** counted as JSON value nodes and parent/sibling objects never share key sets.

The scan refuses duplicate keys *before full JSON decoding* even if aliases use `\\u` escapes, escaped slash/quote/backslash or escaped surrogate pairs equivalent to literal UTF-8 supplementary-plane characters. The existing `object_pairs_hook` duplicate check is retained as a **second defense** after tree parsing for admitted input. Any malformed Unicode surrogate sequences remain denied early. The key-tracking memory overhead is bounded by the strict input byte ceiling, but this does **not** prove a fixed process peak RSS or CPU limit. Real owner-configured HTTP budgets require independent security review and an identified production intake.

New `tests/test_scope_1023_preparse_duplicate_names_20261013.py` (**12 synthetic offline unittests**) mocks `json.loads` to ensure early duplicate rejection; covers root/nested aliases, emoji/UTF-16 pairs, escaped separators, empty names, sibling-object independence, exact node/byte budgets, malformed escapes, forced key-decoder failure and “shape success is not authorization.” It is not a test of any installed WSGI JSON grant endpoint, which is still unconfirmed.

**Safety: LightUp remains Incubate M3/M7 PLAN/LAB ONLY. No scans, users, customer grants, live target operations, merge or deploy. Original source owner #107 and the future ingress owner must explicitly approve and integrate before any production authority.**
