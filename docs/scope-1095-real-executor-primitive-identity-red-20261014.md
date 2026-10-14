# Scope issue #1095 — real ToolExecutor polymorphic value admission (RED)

**2026-10-14 · PLAN/LAB ONLY · DRAFT/HOLD · NO MERGE/DEPLOY**

## Purpose and immutable ownership boundary

This branch starts from original ToolRegistry owner [PR #156](https://github.com/Zennay/Lightup/pull/156) exact head `e84f2cd74d24f143c02b38cc05cb1c4c64352966`. Only two newly introduced tests/docs paths belong to this work. **No modifications** to `src/lightup/ai/orchestration.py`, original registry/executor, default deployment, workflows or other workers. Parent PR #156 remains owner of production source; [issue #1095](https://github.com/Zennay/Lightup/issues/1095) describes the mismatch.

The real source implementation uses `isinstance` in `ParamKind.accepts`. Accordingly STRING currently admits subclasses of `str`, INTEGER admits subclasses of `int` and `IntEnum`, and NUMBER admits subclasses of `int`/`float` and `IntEnum`. Builtin `bool` is correctly excluded from INTEGER and NUMBER. Subclass admissibility is **unfixed** until the original owner installs strict exact-builtin checks.

## Concrete test coverage

`tests/test_scope_1095_real_executor_typed_values_red_20261014.py` has two independent layers:

1. Standard-library built-in positive and negative controls on all four ParamKind choices, a no-coercion numeric-protocol control and seven clearly marked expected RED checks for exact primitive identity.
2. Real `ToolRegistry` + `ToolDefinition` + `ToolExecutor.execute`, genuine `ExecutionPolicy`, `RunContext` in **ANALYSIS_ONLY**, disposable `StateStore` SQLite and synthetic `ToolOutput` through an in-memory recording handler. Positive exact built-ins are expected to run as a **synthetic analysis-only control**. Canonical invalid arguments must deny without handler calls or persisted evidence. Seven additional expected RED checks require subclasses/IntEnum to be refused before both the handler and evidence ledger (including a late bad call after an accepted control).

Expected RED tests are decorated `@unittest.expectedFailure` individually so CI can characterize the unresolved defect without falsely claiming a repaired authorization boundary. **Unexpected success** is not green: Python unittest treats XPASS as a signal that tests need reevaluation and relabelling. To close #1095, original production source owner must convert these explicit expected RED cases to ordinary passing requirements and inspect absence of side effects.

Run after review, via hosted workflow and permanent registered VPS on the exact final commit:

```sh
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_1095_real_executor_typed_values_red_20261014.py' -v
```

## Limits and required release gates

All sample names are synthetic and are not queried over DNS. No network, scan, target interaction, customer data, grant, persisted authorization mutation, attack path, CI workflow edit or deployment. Even real SQLite and handler controls provide **typed-value input diagnostics only**; they do not establish customer consent, revocation coherence, live tenant scope, or real-target dispatch safety.

Remain DRAFT/HOLD with both owner-level and independent privacy/security review. Require latest-main compatibility, unmasked ordinary security tests after original owner repair, exact-head Python 3.11/3.14 hosted and independently **permanently registered vps-bb300bba** results (not merely queued jobs), and explicit human release approval before any merge/deploy. No automatic activation.
