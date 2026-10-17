# LightUp #776 — pinned three-family ScopeDefinition integrity composition

**2026-10-17 · INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This is a branch-only, non-authorizing integration harness. It does **not** merge, deploy, issue actual grants, run real scans, review actual customer consent, or change any production/other-worker source.

## Why it exists

Independent issues [#648](https://github.com/Zennay/Lightup/issues/648) (immutable caller collections), [#775](https://github.com/Zennay/Lightup/issues/775) (exact tuple/string identities) and [#773](https://github.com/Zennay/Lightup/issues/773) (direct exact risk identity) have distinct owners. A successful isolated acceptance family does not prove the three constraints work together. This isolated #776 harness validates them **together** on an unmodified pinned #554 source parent and in deliberately disposable candidate source copies.

## Ownership and exact pinned inputs

Original #554 owner HEAD: `4c8d5651fc0e23f94514daae56b4e5fe0549de37`.

- **#648** imported **read-only** from its own branch-only head `db5dc58a422e38ffa886f3a6580527e7047ea0a3`, exact Git blob `5bbc5dd3d5edb30549f761f55785a3862213c7bc`.
- **#775** imported **read-only** from its own branch-only head `b0a098e42004e18fe63842bd18d9f481be9c60a2`, exact Git blob `92c63851175a650b6539df50bef569b341ef8c96`.
- **#773** existing active-owner draft [PR #1439](https://github.com/Zennay/Lightup/pull/1439), historical source snapshot `3fd44e97e7f033baf45eef40ea02aa1836c086a3`, blob `3a71c7f2701b9a6edc31f50ae0390f39bf6b54fc`. It is **verified as a read-only provenance reference only, not imported or executed**. Its original test family was developed against a different main-line source: an exploratory disposable run against #554 produced **16 failures and 8 unexpected successes** in 38 tests. Calling that family compatible or GREEN would be false. The new #776 cross-family constructor-risk probes are independent and **do not replace, modify or claim completion of #773**.

The checker pins each allowed remote blob in two independent ways (immutable commit:path, and computed native Git blob SHA-1), hardcodes allowed paths/SHAs, uses `GIT_NO_REPLACE_OBJECTS=1`, requires the original owner ancestor and rejects any change in the no-authority manifest. It also verifies that the current branch differs from the original owner **by exactly five added, regular Git blob files**, without changes to any production or other-worker path; the original checkout must be fully clean before the temporary tests start. The negative selftests prove a modification to `src/lightup/domain.py` or an existing test fails this boundary. No network fetch is performed by the tool: necessary pinned Git objects must be present **locally**. Missing objects fail closed with a non-zero exit and do not fall back to floating branch heads.

### Own new-only files

- `tests/test_scope_776_composed_identity_20261017.py` — 8 distinct cross-family methods, 3 ordinary controls and 5 genuinely outstanding original source REDs. Combined with 9 #648 and 9 #775 methods gives **26 total (8 ordinary PASS + 18 original source expectedFailures)** on original unchanged #554.
- `manifests/scope-776-three-family-20261017.json` — exact owner, immutable source heads/blob identities and five literal `false` authority flags.
- `scripts/scope_776_composition_check_20261017.py` — actual runnable offline aggregator. It materializes source and tests into an automatically cleaned temporary directory, checks exact 26/18 original results, creates a local constructor-level exact risk + tuple + string guard and requires all 26 strict tests to PASS ordinarily, and verifies two intentionally incomplete repairs (`no_risk`, `no_entries`) still fail for their original issue probes. Does not mutate original source Git working tree.
- `tests/test_scope_776_manifest_rules.py` — **11 ordinary, independently tested** positive/negative controls for authority flags, provenance SHA/source order, #773 non-execution, expected counts, literal booleans, and explicit rejection of modified owner/other-worker or non-additive paths.
- This handoff document.

The previous #648 and #775 owners' own files are **not copied into this branch**. They are materialized by SHA into a temporary directory solely when the checker is run.

## Exact source-owner repair rehearsal (disposable only)

The synthetic local constructor guard was added only to `src/lightup/engagements.py` **inside the temporary checkout**, never committed or pushed:

```python
def __post_init__(self) -> None:
    if type(self.max_risk) is not RiskLevel:
        raise ValueError("scope risk requires exact RiskLevel")
    for name in ("assets", "excluded_assets", "allowed_capabilities"):
        values = object.__getattribute__(self, name)
        if type(values) is not tuple:
            raise ValueError("scope collection requires exact tuple")
        for item in values:
            if type(item) is not str:
                raise ValueError("scope entry requires exact str")
```

This **reject-noncanonical** policy (instead of snapshots) satisfies the original #648/775 contract, but may be less ergonomic than defensively copying plain lists; source owner decides. No exotic tuple/string callbacks are evaluated. The existing original full `tests/test_domain.py` fixture constructs `ScopeDefinition(max_risk=5)` before entering its `assertRaises` scope, so a constructor-level risk fix initially made one old unit test ERROR **even though all 26 strict acceptance tests passed**. The optional `--full` check migrates that exact one fixture **in its temporary copy only** by asserting malformed construction raises `ValueError` at creation, then runs the original full suite. This migration and the production source change require separate review before source-owner adoption. The tool refuses to migrate if the original fixture no longer matches the exact expected source pattern.

## Reproduce (connected authorized zSSH, no direct manual SSH)

```sh
# Clone or check out this isolated branch locally, with complete Git object
# history for its fixed source owner and the pinned three test blobs.
python3 -B scripts/scope_776_composition_check_20261017.py
# Optional: full original unit/integration suite, may use loopback-only
# fixtures (never real targets or external scans):
python3 -B scripts/scope_776_composition_check_20261017.py --full
```

**First real VPS zSSH observations (original source vs disposable source):**

- Local cached pinned #773 historical tests when forcibly transplanted onto #554: **38 tests; 16 FAIL and 8 unexpected successes**. Not a compatible or approved #773 source test suite. This is why import is prohibited.
- Original parent #554 with #648/#775/#776 own inputs: **26 tests = 8 ordinary controls + 18 intentionally unresolved original source expectedFailures** (GREEN as an evidence runner only; actual original defects remain). A second **strict original-source run** (no source patch at all) now verifies the **exact identities of all 18 source RED methods**, including the **26 individual failing subtest cases** (three combined invalid-shape variants, seven raw-risk variants, and sixteen other individual cases). If any of those original canaries disappear, change identity, turn into an unrelated exception, or acquire an unexpected success, the offline checker exits non-zero instead of reporting a false positive.
- Disposable combined exact-type constructor guard: **26/26 ordinary strict PASS**. Partial/no-risk and partial/no-entry guards each **RED**.
- First original whole suite with constructor-level risk check had **593 tests; one ERROR** due only to the early-constructor fixture above; independent real integration **86/86 PASS**.
- With **fixture migrated in disposable copy only**: **593/593 whole unit tests PASS, 86/86 integration PASS**.
- Initial 9 manifest tamper/control tests were **9/9 PASS**; then two real source-path collision tests were added for **11/11 PASS**. On this later exact owned code, **604/604 whole unit PASS + 86/86 integration PASS** under the same **disposable-only** source+fixture corrections.
- All temporary source checkouts cleaned automatically by the script; original Git worktree clean after execution.

**Do not treat a GREEN acceptance runner with intentionally expected source failures or a local-only temporary patch as source-owner remediation, actual consent, live at-use authorization/revocation, named permanent VPS runner CI, security/privacy signoff, or HUMAN GO.** #773 independent work remains owned by its active reviewer. [#776](https://github.com/Zennay/Lightup/issues/776) explicitly directs branch-only composition while the canonical permanent VPS queue is saturated. **Do not open another redundant PR/workflow or release.**
