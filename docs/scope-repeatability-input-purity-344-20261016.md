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
