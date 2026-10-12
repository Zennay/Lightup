# Scope authorization: exact interaction + risk identity (opt-in)

**Issues:** [#986](https://github.com/Zennay/Lightup/issues/986), [#987](https://github.com/Zennay/Lightup/issues/987)  
**Phase:** Incubate, M3/M7 ST5, **PLAN/LAB ONLY**  
**Status:** DRAFT / HOLD / NO MERGE / NO DEPLOY

## Observed gap on main

`ExecutionPolicy.decide` checks the first three known `InteractionKind` members and otherwise falls into its TARGET_ACTIVE grant logic. A foreign interaction value can therefore be treated as active. The PASSIVE_PUBLIC path compares `requested_risk > RiskLevel.PASSIVE` without requiring a canonical RiskLevel; `True`, integral values and foreign IntEnums compare numerically. These are type-admission gaps, not independently proven production authorization bypasses.

## Isolated material implementation

- `src/lightup/scope_exact_identity_policy.py`: optional `StrictIdentityExecutionPolicy` subclass, refusing anything except **exact enum types** before delegating to the unchanged `ExecutionPolicy`. It does **not** normalize, coerce, approve, issue grants or interact with targets.
- `tests/test_scope_986_987_exact_identity_optin_20261012.py`: pure policy matrix and real `ToolExecutor` + `ToolRegistry` + disposable SQLite acceptance. Synthetic handlers return fixed evidence bytes and perform no I/O. Twenty optional-policy unittest methods now include a 96-case canonical interaction × risk × lab flag × grant reference-equivalence matrix, poison-grant short-circuit probes, expired/future grant and capability refusal, canonical active ToolExecutor positive and denied/mismatched-grant zero-evidence controls, malformed active risk denial, preservation of pre-existing durable evidence on rejection, and an explicit default-executor-is-unchanged assertion. Malformed tool metadata must be denied before handler and evidence write; valid canonical passive/active policy controls remain permitted only under inherited constraints.
- Production `src/lightup/execution_policy.py`, `src/lightup/ai/orchestration.py`, installed application, config, CI and all existing tests are **unchanged**. This opt-in module is deliberately **not wired into the default runtime**.

## Local reproduction / promotion requirements

```sh
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_986_987_exact_identity_optin_20261012.py' -v
PYTHONPATH=src python -m unittest discover -s tests -p 'test_execution_policy.py' -v
PYTHONPATH=src python -m unittest discover -s tests -p 'test_orchestration.py' -v
```

Treat the tests as **proposed acceptance** until actual exact-head raw CI records prove them. An offline green is **not** production enforcement. Before owner-gated integration, explicitly revalidate all interaction identity, risk ceiling, trusted issuer, tenant, engagement, asset, capability, authorization window, revocation and destination binding under current state. The original production owners of #100 / #107 must decide integration order with #986/#987 and any dependent stacked branches. No shared code change or ownership transfer is implied.

**Release gate:** exact final SHA hosted Python 3.11 and 3.14 unit + genuine producer integration; separate registered permanent VPS LightUp CI; independent security/privacy/source review and latest-main compatibility; explicit human approval. No real-client/target data, DNS, sockets, network testing, live grants, active scanning, merge or deploy from this draft.

## W2 additional safety interpretation

The 96-case enumeration compares the optional policy with the untouched baseline for **valid exact enum identities only**; it is equivalence evidence, not proof that the baseline is secure or that caller-owned grants cannot change concurrently. Poison-grant cases assert malformed interaction/risk admission does not read a grant at all. An accepted synthetic passive call is followed by a denied call; the full durable evidence-row snapshot (including SHA-256 and metadata) must be byte-for-byte unchanged. Existing owner sources, actual ingress/dispatcher wiring and grants remain unmodified. The default executor still uses the original policy.

**Important:** each commit invalidates tests on prior SHAs. A hosted successful run only belongs to its recorded exact SHA. Registered permanent VPS proof is separate, and a queued VPS run never authorizes merge/deploy.

## W3: original producer expected-RED acceptance

The independent new file `tests/test_scope_986_987_default_producer_expected_red_20261012.py` adds **six additional methods**. Two canonical baseline positives remain ordinary passing tests. Four intentionally `@unittest.expectedFailure` tests demonstrate currently unfixed default-policy and genuine ToolExecutor handling for unknown interaction text and boolean passive requested risk, on disposable SQLite and fixed in-memory handlers only. These tests **do not install** or repair the default policy and **must not be reported as green authorization**; expected failures explicitly show that the unsafe original behavior persists. The original #100/#107 owners must convert these RED cases into normal passing, zero-handler/zero-evidence tests after their actual implementation repairs. The separately opt-in policy's 20 tests remain independent. Total **26 test methods**, including four intentional expected RED, prior to raw CI verification. A successful CI job that includes expected failures is NOT signoff of the default executor.

Suggested focused command:

```sh
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_986_987_*20261012.py' -v
```
