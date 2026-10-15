# Issue #294 — current-main mutable policy input aliasing, expected-RED

**15 October 2026 · INCUBATE M3/M7 / PLAN-LAB ONLY / DRAFT-HOLD.**

## Installed source observation

`ScopePolicy` in `src/lightup/scope.py` is a frozen dataclass, but Python does not enforce its `frozenset[str]` and `tuple[str, ...]` annotations on caller-supplied containers. A caller can supply mutable `set` or `list`, and subsequent mutations can change a previously created policy's decisions. This is an **actual open scope-integrity gap (#294)**, not an authorized grant or demonstration on a real asset.

## Independent additive current-main acceptance

`tests/test_scope_294_current_main_mutable_alias_red_20261015.py` adds **nine** real `unittest` methods and no runtime changes:

- Exactly **six** `@unittest.expectedFailure` security canaries: original host-set and network-list containers must become immutable canonical snapshots and later **additions and removals** must not widen or narrow an already-created policy.
- Three passing controls: canonical `frozenset`/`tuple` membership remains stable; a declared synthetic public host/IP requires separate authorization when not supplied; and policy decisions invoke no socket, DNS or subprocess.
- Test fixtures use `.test` host strings and fictional address literals solely as in-memory values; there is no DNS, HTTP, scan, handler, activation or real customer grant. `FICTIONAL_AUTH` is explicitly not consent.

The previous owner-created acceptance is on an untouched October 6 branch `chatgpt/scope-authorization-policy-snapshot-red-20261006`; a separate original combined #291/#294 branch has historical [registered VPS expected-RED receipt](https://github.com/Zennay/zCloud/actions/runs/37545983813) for its **own older SHA only**. Neither is proof for this new branch. This independent test keeps original branch filenames, old worker-owned docs, source and runtime separate.

## Verification and release

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_294_current_main_mutable_alias_red_20261015.py' -v
PYTHONPATH=src python -m unittest discover -s tests -v
```

The required evidence is *exactly six expected failures and three ordinary positive controls*, with no unexpected failures or accidental successes. An `expectedFailure` acknowledges the **original installed problem still exists** and must not be interpreted as remediation or release readiness. Source owner #100 must implement validated immutable snapshots in `scope.py` and then convert these six expected RED canaries to plain passing tests. Other source boundaries #177 consent, #347 revocation, identity, destination and ingress still need independent review, canonical registered permanent VPS proof, privacy/security and explicit human approval.

**Never merge, deploy, issue grants, scan external targets, or infer authorization from CI. DRAFT/HOLD.**

## Independent W2: opt-in non-authorizing collection snapshot reference

The follow-on **new-only** `src/lightup/scope_collection_snapshot_review_294.py` and `tests/test_scope_collection_snapshot_review_294_20261015.py` provide a real reusable but **not installed** reference for safe policy-metadata review.

- `snapshot_untrusted_scope_collections(hosts, networks)` accepts strictly **exact built-in** set/frozenset/list/tuple host containers and list/tuple network containers with exact built-in string members; it enforces 128-element limits, bounded string lengths and syntactically parseable CIDRs. Invalid values yield generic `HOLD` without calling untrusted coercion methods. A valid shape produces **REVIEW_ONLY**, never authority.
- The reference copies admitted collections to an independent `frozenset` and `tuple`, so **subsequent caller-owned set/list mutation cannot change that detached review snapshot**. This makes *no* claim of atomic concurrency for mutations during snapshotting.
- `inspect_existing_scope_policy(policy)` requires an **exact** installed `ScopePolicy`, exact boolean switches and already immutable canonical collection types. A currently installed policy constructed with mutable set/list receives `HOLD`; the reference does **not** patch or intercept `ScopePolicy.decide`.
- Every receipt is always false in a boolean context, all six authority/release properties are hard False and public serialization omits host/network data. Code does **not** return or construct an executable policy, grant or permit.
- Dedicated tests cover detached snapshot behavior after additions/removals, exact-type confusion, hostile subclasses, malformed CIDRs, over-budget collections, forged status, mutation protection, privacy and real DNS/socket/subprocess tripwires.

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_collection_snapshot_review_294_20261015.py' -v
```

Passing W2 cannot cancel or convert the six original *installed* `expectedFailure` canaries; it is an opt-in helper for security review and future source-owner handoff, not an authorization bypass fix. Source owner must independently integrate/validate an actual fail-closed production configuration boundary; independent current-head hosted and permanently registered VPS proof, customer consent, pre-I/O revocation, security/privacy review and explicit human approval remain separate blockers.

## W3: usable private offline JSON manifest review CLI

The **new-only** `scripts/scope_294_collection_review_cli.py` is a bounded operator command, not an executor, target scanner, policy source modification or grant issuer. It parses **at most 16 KiB** of stdin as strict UTF-8 JSON with duplicate-key rejection even inside nested objects; JSON nonfinite constants, unknown fields, malformed shapes, invalid CIDRs and noncanonical containers all yield a redacted generic HOLD. Only the exact two keys `hosts` and `networks` with JSON arrays are recognized.

```bash
printf '%s' '{"hosts":["fixture.example.test"],"networks":["8.8.8.0/24"]}' | python scripts/scope_294_collection_review_cli.py
# JSON status REVIEW_ONLY, all six authority/release fields false, exit 3 (NONZERO)
```

The CLI **never returns exit 0** (HOLD=2, REVIEW_ONLY=3), reads no customer files, connects to no network or target, and outputs no provided host/network strings or private data. It must not be used as an auth/grant/release gate because `REVIEW_ONLY` is non-authorizing. `tests/test_scope_294_offline_manifest_cli_20261015.py` exercises actual child-process execution, over-budget input, duplicates, nonfinite/invalid Unicode, malformed shapes, 128/129-boundary sizes, deterministic no-data receipts and six hard-false fields.

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_294_offline_manifest_cli_20261015.py' -v
```

**Release remains blocked by installed source-owner #294 and original six expected-RED tests, live customer consent #177, revocation #347, independent permanently registered VPS CI, security/privacy and explicit human approval.**

## W4: exact CIDR spelling, no silent scope inflation (#294 / related #296)

The optional reference formerly passed `ip_network(text, strict=False)` for network shape. That silently rewrote noncanonical spellings (for example `8.8.8.8/24` into `8.8.8.0/24`) and treated bare IPs as implicit /32 or /128; such a rewrite is inappropriate to label as *canonical review metadata*.

This patch narrows **only the new uninstalled review helper** to `ip_network(value, strict=True)` followed by `str(parsed) == value`. Consequently, the separate reviewer now **HOLDs** host-bit CIDR forms, bare IPs, legacy address/mask aliases, padded prefix lengths and noncanonical IPv6 spellings without silently converting any of them into an accepted network. It still handles **exact** canonical IPv4/IPv6 CIDR strings as `REVIEW_ONLY`, with every authority flag False. The installed `ScopePolicy` source and its original product authorization vulnerabilities are NOT changed.

New add-only `tests/test_scope_294_exact_network_spelling_review_20261015.py` covers valid IPv4/IPv6 identities, host-bit and alias refusal, bare literal vs /32, `int`/`bool`/`bytes`/`bytearray` coercion admission, atomic all-or-nothing mixed input, caller mutation after review, current legacy installed policy flagged HOLD, and explicit DNS/socket/subprocess tripwires. CLI path uses the same strict helper and returns generic HOLD without echoing user network data. This is intentionally narrower than installed source: do not interpret passing reviewer tests as repair of #292, #294, #296, or real permissions.

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_294_exact_network_spelling_review_20261015.py' -v
```

**Release still requires original source-owner fixes, installed expected-RED -> plain-PASS conversion, real #177 consent, #347 revocation, independent registered VPS runner evidence and human/security/privacy sign-off.**

## W5: duplicate host declarations cannot disappear silently in the optional review

The detached metadata snapshot formerly accepted `["host.example.test", "host.example.test"]` and silently deduplicated it into one `frozenset` item. The stricter **uninstalled** reviewer now holds list/tuple inputs whose exact lexical host identity occurs more than once. Since host membership is a set-like concept, a caller must explicitly supply unique entries instead of relying on implicit normalization.

The behavior remains conservative and non-authorizing: original `set` / `frozenset` hosts already have unique entries and remain REVIEW_ONLY (not permits). Distinct *textual spellings* such as `HOST.EXAMPLE.TEST` and `host.example.test` are not unexpectedly collapsed by this metadata layer; IDNA, case and Unicode semantic alias interpretation remain separate source-owner #285/#1437 concerns and cannot confer grants here.

New dedicated `tests/test_scope_294_duplicate_host_identity_review_20261015.py` executes nine tests: list/tuple duplicate rejection, all-or-nothing behavior with valid networks, retaining exact lexical aliases without normalization, stable post-snapshot caller mutation, no installed-policy mutation, an **actual local CLI subprocess** with private HOLD response/exit 2, and no DNS/socket/executor I/O.

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_294_duplicate_host_identity_review_20261015.py' -v
```

A shape REVIEW_ONLY after this additional narrowing remains explicitly **not authorization, consent, grant, approval, scan permission or release readiness**, and does not fix installed #294/#292/#296 policy code. DRAFT/HOLD.

## W6 — opt-in lexical host-metadata review cannot swallow URL authority

**Source-owner boundaries remain unchanged.** An exact-host metadata field in the new offline reviewer previously classified values like `https://fixture.example.test`, `fixture.example.test:443`, `user@fixture.example.test`, `fixture..example.test` or a bidi/zero-width formatting character as `REVIEW_ONLY`, despite those not being ordinary hostname-shaped declarations. This was a concrete ambiguity **in the new uninstalled reviewer**, not evidence that production source issued such a permission.

New `_lexical_host_metadata_identity` performs only a bounded local lexical shape check: exact string type, at most 253 code points, nonempty labels of at most 63 code points, alphanumeric start/end and interior letters/numbers/combining marks/hyphens. No IDNA decode, case folding, alias merging, DNS, browser parsing, port/URI userinfo interpretation or permission is performed. Literal `bücher.example.test`, `xn--bcher-kva.example.test` and uppercase names remain **distinct** metadata, never a grant; resolver and actual IDNA/canonicalization issues remain for source owner #285/#1437.

New `tests/test_scope_294_host_metadata_syntax_review_20261015.py` has nine tests for forbidden URI, path, userinfo, port, query, fragment and malformed label syntax; invisible/bidi/surrogate/space; lexically safe IDN and punycode controls, atomic mixed manifests, no input leakage, true current installed-policy diagnostic, and no DNS/socket/subprocess. Any rejected manifest emits only generic privacy-minimal **HOLD**; accepted shape remains only **REVIEW_ONLY**, false in Boolean contexts with all six authority/release fields False.

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_294_host_metadata_syntax_review_20261015.py' -v
```

Explicit limitation: this lexical gate **does not prove real DNS/IDNA validity**, does not make authorization decisions, and does not repair source-owned installed `ScopePolicy` #294/#292/#296, grant provenance #177, revoke #347 or runtime executor trust. Remain INCUBATE / DRAFT-HOLD.
