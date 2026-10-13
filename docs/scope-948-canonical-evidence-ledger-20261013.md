# Scope #948 — canonical evidence-ledger identity and lifetime

**LightUp: INCUBATE M3/M7, offline PLAN/LAB only. DRAFT/HOLD, NO MERGE, NO DEPLOY.**

## Owner boundary
Original source-owner [PR #107](https://github.com/Zennay/Lightup/pull/107) at frozen `c37ee27d922a7dd400eee1db39268f4a6269e431` owns `ToolExecutor`. Original StateStore persistence and FK owners, notably #170, remain untouched. This independent branch changes **new tests/docs paths only** and owns the [issue #948](https://github.com/Zennay/Lightup/issues/948) identity/lifetime acceptance contract. No other worker branch or main files modified.

## Actual risk
Original executor constructor checks only `state is None` and retains a writable `executor.state` attribute. A duck ledger or `StateStore` subclass can fabricate an evidence ID while storing no evidence; a later reassignment can redirect persistence after constructor acceptance. Canonical local SQLite evidence lineage is a mandatory post-handler contract, not caller-controlled metadata.

## Isolated real-executor test pack
`tests/test_scope_948_canonical_evidence_ledger_red_20261013.py` invokes the authentic source `ToolExecutor.execute` with a strictly inert local `ANALYSIS` handler and disposable SQLite. A synthetic domain `synthetic.invalid` is **never accessed**; no sockets, DNS, models, scanners, grants, real assets or deployment. Ten methods: seven intentionally unresolved `unittest.expectedFailure` RED for duck/subclass ledgers, public attribute assignment, `object.__setattr__`, direct `__dict__` shadow and deletion of canonical ledger. Four normal controls prove real canonical SQLite persistence, null StateStore rejection and no handler/evidence on unknown tool.

Denial must happen before any untrusted handler and before evidence writes. The original ledger must remain the same exact object selected at construction. A test summary `OK (expected failures=7)` is NOT an authorization fix. Original owner must convert each RED into ordinary passing acceptance after implementing the invariant.

## Release gates
Owner #107 enforces `type(state) is StateStore` before handler registration/use and lifetime-binding of exact ledger identity. Preserve StateStore transaction/FK and source-owner registration contracts, and verify evidence is persistently attached only to actual runs. Confirm hosted exact SHA Python3.11/3.14 and separately registered permanent VPS, latest-main composition, independent privacy/security + source-owner + explicit human release approval before any merge. A passing hosted job with unresolved RED and queued VPS is still **HOLD**.

## Hosted CI finding and independently owned #170
Exact PR #1299 hosted run `38466192070` at superseded SHA `fafaab1` FAILED on both 3.11 and 3.14: the new direct real SQLite orphan run assertion did not raise `sqlite3.IntegrityError`. This confirms already-open [#170](https://github.com/Zennay/Lightup/issues/170): SQLite `PRAGMA foreign_keys` is per connection, but subsequent `StateStore.connect()` calls do not enable it. The test now pins an **explicit expected RED** rather than faking a PASS. `state.py`, #167 source owner and existing production flows remain untouched. Both #948 and #170 defects must be resolved by their respective owners and converted to ordinary passing tests before release; no merge/deploy.
