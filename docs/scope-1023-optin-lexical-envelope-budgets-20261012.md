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
