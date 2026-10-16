# Scope policy determinism and input purity — #344

**LightUp: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. Not execution authority.**

## Real source and independent owner boundary

This standalone acceptance runs the *installed* `ScopePolicy.decide` from `src/lightup/scope.py` on synthetic canonical `Target`, `Authorization` and immutable `ScopePolicy` objects. A source-integrated decision is expected to stay identical through repeat evaluation, not mutate the exact caller-owned target/grant/labels or original policy containers, and never invoke network/DNS/HTTP/process/shell functions. The tests are additive only; **no production policy implementation is modified**.

## Covered invariants

- 32x per-case replay for loopback host/IP, private lab allowed/denied, public exact hostname, exact IPv4 network, missing/expired authorization, out-of-scope name, empty target and case-normalized host.
- Actual `ScopeDecision` type, exact Boolean `allowed`, stable reason and normalized host across repeated calls.
- Original `Target.value`, labels, `Authorization` identity/provenance/window values, `ScopePolicy` identity/toggles/frozenset/tuple remain unchanged.
- Interleaved distinct allowed/denied requests never contaminate each other's scope decisions.
- During installed-source calls, unittest mocks fail if socket/DNS/HTTP, subprocess or system shell are invoked.

## Reproduction

```bash
PYTHONPATH=src python -m unittest tests.test_scope_repeatability_input_purity_344_20261016 -v
```

Run on GitHub-hosted Python 3.11 and 3.14, plus the canonical registered LightUp VPS workflow when capacity is available; examine original exact-head logs rather than treating a queued VPS job as proof.

## What this does NOT prove

These tests deliberately cover **canonical immutable inputs only**. They do not establish race-free snapshots for mutable caller containers (#294), reject corrupted authorization types (#301/#729), improve parsing (#1289/#291), or confer live client consent, tenant/asset/capability grant, revocation safety, trusted source provenance or approval to run any tool. A passing policy decision is *not* an execution permit, approved scan or production release.

Original source owners retain production fixes; independently confirm security/privacy and real consent, permanent-runner provenance and explicit human GO before any merge or deployment.

**NO MERGE, DEPLOY, TARGET/NETWORK TEST, ACTIVE GRANTS, SCANS OR HANDLERS.**


## Seeded replay matrix — addendum W2



The initial 14 checks establish input purity and 32x same-request replay for selected scenarios. The new independent test file `tests/test_scope_repeatability_matrix_344_20261016.py` extends that to an orthogonal Cartesian batch of **96 scenarios** across four immutable policies, eight fictitious/lexical target values, and three authorization states. It uses seeded local `Random(344)` shuffles to inspect replay-order cross contamination, not real-world randomness or network I/O.

### Concrete safety expectations

- 96 scenarios x 32 repeated evaluations remain equal to their first actual `ScopePolicy.decide` result.
- 64 shuffled ordering cycles over the same exact instances cannot change results or their input snapshots.
- Positive and negative canaries independently check actual reason and `allowed` type, preventing a vacuous pass where every input is denied.
- Alternating allowed, expired and nonmember public host decisions cannot leak earlier authorization state.
- Case-normalized canonical public input yields equal results but never overwrites original caller text.
- Explicit host frozenset and network tuple remain intact; detached equal-value canonical objects produce equivalent decisions.
- Socket, DNS and subprocess calls are patched to raise during real in-process decision evaluation. No target is contacted.
- Decision record never contains an executable permit or activation reference; this is not sufficient live approval.

### Reproduce the single owned test module

```bash
PYTHONPATH=src python -m unittest tests.test_scope_repeatability_input_purity_344_20261016 -v
```

### Limitations and ownership

This is restricted to stable canonical **immutable** objects, controlled fictional labels and fixed grant windows (2020–2099 current; 2020–2021 expired). It does not establish deterministic behaviour at a moving grant-expiry boundary (time can legitimately change a decision), defend mutable external policy buffers (#294), replace source-owner repairs, validate actual customer grants or stop malformed target parsing (#1289). No original runtime, tests owned by other workers, existing workflows, or runner configurations changed. PR and project remain DRAFT/HOLD until independent owner/security review, genuine client/operator consent, durable revocation, permanent registered VPS CI and explicit human GO.

### W3 — Seven synthetic mutation-kill canaries

The main acceptance had proved that canonical production-source decisions were repeatable and value-equal. The dedicated **seven extra negative controls** now deliberately instrument only a `unittest.mock.patch.object(ScopePolicy, "decide", ...)` context to verify that the acceptance oracle actually refuses accidental regressions. Patching is immediately undone; original source files are never edited or deployed.

- An injected second-call changed decision must trigger an assertion, and a truthy non-Boolean `allowed="yes"` must not pass exact Boolean checks.
- An injected rewrite of the original target value, or replacement of a tuple of unchanged label **values with a new tuple object**, must be detected.
- A forged replacement of an attached fictional authorization reference must be detected even where the normalized scope decision would otherwise still be equal.
- Replacement of exact policy host-frozenset or network-tuple objects with **equal-content new objects** must be detected by newly pinned container identities. This checks *input purity*, not merely equal returned decisions.
- Every negative canary also asserts that the local mock ran, so a vacuous expectation of `AssertionError` cannot disguise unused patches. The tests never invoke adapters, scans, network, handlers, real customer assets or real grants.

Current exact own acceptance: **31 methods** (24 genuine installed-source checks + seven test-harness mutation canaries) in the same single test module. This is a local review/test contract; it does not protect against concurrent mutable callers, malicious test runners, trusted source tampering or consent forgery.

### W4 — Storage and environment non-interference

A genuine source-integrated **96-case matrix, repeated four times**, now patches `builtins.open`, `pathlib.Path.open`, `sqlite3.connect` and `os.getenv` to raise if `ScopePolicy.decide` attempts any local file, database or environment access. This is distinct from W1–W3's socket/DNS/process guards. Two additional deliberately injected test-only mutation canaries exercise actual blocked file/database calls to show the denial guards are live, then confirm that the real unpatched `ScopePolicy.decide` method is restored. No file/database read is ever actually allowed by the tests.

**Total 34 owner methods**: 24 original real-source acceptance tests, seven deterministic synthetic decision/input mutation canaries, and three filesystem/storage/environment boundary tests. Their results never authorize real targets, create permits, admit grants, dispatch handlers or prove source chain-of-custody. The entire matrix remains fabricated and in-process.

### W5 — Concurrent in-process source replay (no live authority)

The same installed `ScopePolicy.decide` is now exercised by an eight-worker in-process `ThreadPoolExecutor` on **768 shuffled evaluations of the 96 fixed canonical synthetic scenarios**. A separate 384-evaluation six-way mixed authorized/expired/missing/out-of-scope test deliberately shares **one immutable ScopePolicy instance** across workers. Results must match an independently specified allow/deny/expiry/missing reason, not merely one stale positive cache entry. Original `Target`, `Authorization`, label, frozenset, and tuple object identities and values remain unchanged. These are worker-thread scheduling probes, NOT process-isolation, mutation-race proof, trusted production grant verification or installed adapter tests.

Concurrency is deliberately bounded to 8 threads and deterministic shuffled input order (seeds 344 / 3441); results are re-associated with their original input positions so asynchronous completion order cannot make tests flaky. All target identifiers are fictional local test records, no network, credentials, database or tool handlers are contacted. The test remains an acceptance-only operation inside the existing sole #344 test module.

**New owner total: 36 offline tests.** This additional acceptance cannot establish a right to scan an asset or release LightUp; maintain INCUBATE / DRAFT-HOLD and independent original source/security/privacy review.

The W5 **37th regression**, an intentionally faulty policy-identity-wide cached `ScopeDecision` inserted only inside `unittest.mock.patch.object`, checks that the real 384-call concurrent oracle rejects a previously allowed grant being reused for denied/expired/new requests. It asserts the injected faulty method ran and that original unmodified source behavior is restored outside the mock. No active dispatch or external target is touched.

### W6 — Parallel source I/O prohibition

A further single source-integrated test replays **384 bounded calls over the same 96 synthetic canonical scenarios through an eight-worker thread pool** while blocking socket/DNS, urllib HTTP, subprocess/system shell, file/Path.open, SQLite, and os.getenv. Every result is compared to its exact previously captured decision and each original target, grant, and policy field/object identity is rechecked after the thread pool returns. Both allowed and denied real-source decisions must appear. This test does not contact any network or filesystem or create any active adapter; it only enforces the pure authorization-decision contract under parallel loads.

**38 offline owner tests** in one standalone test module; identical source-owner, human-go and draft hold restrictions apply.