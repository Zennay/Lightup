# Issue #954 — branch-only temporal window composition

**Hold posture:** LightUp INCUBATE M3/M7, PLAN/LAB ONLY. **NO MERGE / NO DEPLOY / NO active targets.**

## Exact parent and ownership

New isolated branch `chatgpt/scope-954-time-window-composition-branchonly-20261013` is based on the exact, unchanged child-head `cae4bc1974a298690d9e23520911d28e6952c15c` from independently authored [#952 composition draft](https://github.com/Zennay/Lightup/pull/1305), whose underlying original ToolExecutor source-owner [PR #107](https://github.com/Zennay/Lightup/pull/107) remains frozen at `c37ee27d922a7dd400eee1db39268f4a6269e431`. This is an **additional branch-only acceptance path**, not a replacement of existing issue #954's earlier pack or any source-owner branch.

This branch adds only two *new* paths (test module and this documentation); zero edits to source, other worker branches or CI. **No new PR intentionally created** while permanent VPS CI jobs for #1304/#1305 are waiting for registered runner capacity.

## Combined contract and executable tests

`tests/test_scope_954_temporal_composition_branchonly_20261013.py` executes actual `ToolExecutor.execute` with original execution policy, disposable SQLite and inert handler (synthetic `.invalid` labels). Twelve test methods:

- **Five intentionally unresolved expected RED:** live grant starts earlier, expires later, widens both bounds, same-ID duck grant with false expiry semantics, and widened expiry plus fake evidence sink. The last two ensure canonical live grant and canonical evidence identity still apply during time-window revalidation.
- **Seven ordinary controls:** exact window persists durable SQLite evidence, safe narrowing remains usable, narrower expired/future window denies, revoked grant denies, missing live grant denies and different grant ID denies.

Expected failure is *not* production hardening. All rejection paths must precede handler and evidence writes. Preserve the original run snapshot and current-grant validity, tenant/engagement/capability/asset/mode/risk/revocation checks; never widen authority by shifting clock bounds.

## Source-owner and release handoff

Original #107 owner must implement the temporal monotonic validation before handler execution and turn the five RED obligations into normal PASS. Existing #953 and #954 ownership remains untouched; #170 StateStore FK work remains separate. This branch is held without promotion; any later PR requires exact-head hosted Python 3.11 + 3.14 real-producer tests, permanent registered VPS evidence, latest-main composition, original code-owner and independent security/privacy review, explicit human approval. No DNS, network, scanning, active grants, real targets or deployment.
