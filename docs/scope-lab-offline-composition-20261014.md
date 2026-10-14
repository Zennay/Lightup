# Cross-check all offline lab scope-review surfaces (#103)

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO MERGE/DEPLOY/SCANS.**

The additive `tests/test_scope_lab_offline_composition.py` executes
cross-surface tests against all six optional, uninstalled offline helpers
owned by [DRAFT PR #1317](https://github.com/Zennay/Lightup/pull/1317).
They independently inspect bare literal shape, declared inventory,
pairwise narrowing, multiple-version narrowing, checksummed chain shape
and the intact-prefix chain-extension shape.

The suite checks that:
- public, link-local, unspecified, multicast and mapped IP literals
  cannot be promoted in any of six review surfaces;
- canonical positive in-memory fixtures are at most `REVIEW_ONLY`;
- IPv6 textual aliases are not silently accepted by the inventory
  functions even if a base literal parser normalizes them;
- transient scope widening is refused in both history comparators;
- a rewritten initial snapshot is refused by extension comparison;
- deterministic IPv4/IPv6 samples exercise cross-surface HOLD behavior;
- customer/privacy strings are not echoed by any of the receipts;
- DNS/socket calls are absent; no result has a true authority flag.

Run only synthetic offline tests:

```sh
python3 -m unittest discover -s tests -p 'test_scope_lab_offline_composition.py' -v
```

**Important:** this proves only consistency across our six opt-in
shape checks; all consume untrusted user-controlled text. It does not
establish true customer consent, inventory provenance, asset
ownership, grant validity, signed audit data, a target allowlist
decision or safe production integration. No network, DNS, scans,
real customer assets, permits, database writes, deployment, original
scope policy modifications, or runner changes. All response authority
flags are hard-false, and none of the helper CLIs exits zero.

Source-owner [#100](https://github.com/Zennay/Lightup/pull/100),
independent security/privacy review, exact-head hosted and permanent
registered VPS execution, latest-main composition and explicit
human authorization are separate mandatory gates. Keep DRAFT/HOLD.
