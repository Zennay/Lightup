# Scope #1563 — membership before grant substitution (offline acceptance)

**Stage:** INCUBATE M3/M7 · PLAN/LAB ONLY · **DRAFT/HOLD**.

**Links:** issue [#1563](https://github.com/Zennay/Lightup/issues/1563), original membership-first contract [#364](https://github.com/Zennay/Lightup/issues/364), separate documentation-only [PR #1263](https://github.com/Zennay/Lightup/pull/1263). Runtime source/grant owner is still [PR #100](https://github.com/Zennay/Lightup/pull/100).

## What this actually enforces

The single **new** regression file `tests/test_scope_membership_metamorphic_20261017.py` uses fully synthetic target strings and grant objects. It changes only a target's attached legacy `Authorization` or a policy's `require_authorization_for_public` flag and proves that neither makes an **undeclared** hostname/IP become a member of the explicit host/CIDR allowlist. Missing and malformed targets remain `INVALID_TARGET`.

Each negative decision must:
- be `allowed is False`, with the precise `OUT_OF_SCOPE` or `INVALID_TARGET` reason, not a misleading missing/expired-grant reason;
- leave the input `Target` / `Authorization` unchanged;
- never call `Authorization.is_current`: authorization evaluation is downstream of membership;
- never invoke DNS, socket connection, or urllib HTTP entry points (fail-fast patched sentinels).

Metamorphic dimensions: public hostname/IPv4/IPv6/URL lexical forms; no grant/current/expired/future grant; public authorization required/disabled; private-lab flag enabled/disabled for public IPv6; unrelated hostname allowlists; disjoint IPv4/IPv6 CIDR allowlists; invalid/blank target identity; spoofed `Target.labels` and an authorization-shaped object that raises if accessed.

**Not covered / not asserted:** which legacy authorization fields, assets, provenance, revocation epoch, or approval steps may enable a *positive* declared-public-target decision. Those belong to live source-owner #100/#107 and other branches. The tests are **negative-only**, not an alternative source of authorization.

## Exact execution commands (offline; no target I/O)

```sh
python -m compileall -q tests/test_scope_membership_metamorphic_20261017.py
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_membership_metamorphic_20261017.py' -v
```

Run on original main plus this add-only branch; the dedicated new GitHub-hosted workflow pins its checked-out PR head SHA. Compare separately with the owner-source branch before claiming integration. An older green run is never evidence for a changed head.


## Mutation-kill proof (add-only, offline)

The dedicated `scripts/scope_1563_membership_mutation_proof_20261017.py` first verifies the unmodified seven-test suite is entirely green. It then temporarily replaces the **in-memory** policy decision with four intentionally unsafe implementations and **requires** a corresponding rejection test to fail for every broken variant:

1. Allow a public host/IP without membership (`grant_mints_membership`).
2. Permit an empty or syntactically invalid target (`invalid_identity_rescued`).
3. Evaluate attached grants before scope membership (`grant_checked_before_scope`).
4. Treat an attacker-controlled `AUTHORIZED` label as authority (`spoofed_label_authorizes`).

The policy method is restored after each mutation, and the script explicitly checks its identity afterward. A source suite that fails by itself, an uncaught deliberate mutation, or an unexpected test count results in exit 2/HOLD. **Mutations are tests only, never merged into runtime behavior.**

Run independently with `PYTHONDONTWRITEBYTECODE=1 python scripts/scope_1563_membership_mutation_proof_20261017.py`.

Connected zSSH on the independent temporary checkout at exact `bc946fc59e7fa070e54ca6b3416be688ec7ba2ad` reproduced all four detection gates (134 / 32 / 126 / 2 deliberately failing assertions, respectively) and the unmodified seven-test baseline PASS. The own hosted matrix executes the mutation controls on both Python 3.11 and 3.14 at each **exact PR head**; final-head run status must be observed separately and is not inferred from this earlier VPS proof. No DNS, sockets, client data, live assets, grant issuance or dispatch is involved.


## Pinned sibling #301 fixture composition — hosted non-release gate

Original `main` still has independently owned #301 stale-clock test fixture and Python 3.14 #1535 native-I/O `SyntaxWarning`/exit-92 failures. Without editing either owner branch, `.github/workflows/scope-1563-owner301-compat-offline.yml` reads **two immutable source-owner commits** in a fresh ephemeral GitHub-hosted checkout: #1452 exact `89c7973a330550cd5b8fad23abb54e4a81f85639` for only `tests/test_scope_legacy_falsy_window_301_red_20261014.py`, plus #1536 exact `f8b91596d48f318cb75050b70ccbf5a50d2cd106` for only `src/lightup/capability_registry_history_report.py`. Exactly **TWO** intentionally overlaid file paths are allowed; both fetched owner commit SHAs and the original exact PR head are pinned. No checkout credentials, owner-branch update, service or target interaction.

On the connected zSSH VPS, this exact-source overlay has already passed:
- The owner #301 fixture acceptance: **39 tests OK, 20 known intentional expectedFailures**.
- Our original seven no-authority regressions: **7 ordinary PASS**.
- Our four fail-open mutation controls: **all correctly detected**.
- The independently owned #1452 branch remains untouched; a temporary worktree is removed after the proof.

The compatibility workflow first demonstrated **Python 3.11 full green** with only #301; the Python 3.14 attempt correctly uncovered **four original #1535 exit-92 errors** (none in our test files). A second isolated connected-zSSH temporary composition of **both** independently owned files then passed **3/3 native offline CLI tests, 12/12 socket-fleet tests, 7/7 own scope tests, and all four mutation canaries** on Python 3.14. The updated GitHub-hosted compatibility workflow separately runs Python 3.11 and 3.14 full unit discovery, real producer integration and canonical safety canaries against this exact two-file temporary composition. This is a **source-composition test only**, not permission to merge either PR or a green claim for unmodified `main`. Intentional expectedFailures still represent unresolved source defects. A hosted success must be verified on the exact SHA and cannot substitute for authentic client/operator consent, owner acceptance, or the permanent named-VPS gate.

## Exact owner-tree gate: no cross-worker paths

The entirely new `scripts/scope_1563_exact_tree_boundary_20261017.py` checks a clean immutable-base **Git object tree** rather than working-tree `git status`. It pins the original main commit `e73b7445c87ad239bdb03c50a99078ef93163b02`, verifies ancestry and the caller-provided exact HEAD, parses NUL-separated Git name-status records as strict ASCII, and requires the **exact set of seven issue-owned new paths** with only `A` (add) changes and canonical regular blobs (`100644`). Any change to an original source file, CI runner or another worker path, any omission, rename, alias, duplicate, symlink, submodule, malformed Git result or ancestry mismatch produces `HOLD` / exit 2.

The positive result is `REVIEW_ONLY` / exit **3**, explicitly never exit 0, and the returned consent/release flags stay false. This is a **caller-controlled repository ownership check**, not a cryptographic guarantee of release authorization or independently verified worker identity. The separate CI verifies the exact PR SHA, fetches full ancestry without persisting checkout credentials, runs eleven additional synthetic regression methods including genuine temporary local Git repositories, and accepts only the expected non-authorizing exit 3.

On connected allowed zSSH Python 3.14.4, isolated exact SHA `58b8d62acbdb52d7df387f4b9964eeab62e2785b`: **9/9 tree-gate regressions PASS; exact seven-file review outputs REVIEW_ONLY exit3; temp checkout removed.** An independent later GitHub-hosted Python3.11/3.14 run must be checked separately for the final branch SHA. No runtime source, shared workflows, other owners' branches, target I/O, release or deployment is modified.

## W6 — source-only changes can no longer skip the owner-tree gate

The dedicated GitHub-hosted tree workflow previously used a `pull_request.paths` trigger. A future PR revision consisting **only** of an unauthorized source-file change could suppress the run. The workflow now triggers on every pull-request head synchronization, but the job is explicitly restricted to this exact #1563 branch and same-repository ownership; unrelated workers' PR jobs are skipped.

The test module includes two additional negative static CI regressions verifying `synchronize` is covered without a path filter, checkout ancestry is complete and credentials are not persisted, and the gate requires **non-authorizing exit 3** rather than success exit 0. On connected allowed zSSH, exact head `35a414298bf93d0a50d71157612dd2bfebd0bf24`: **11/11 tree/CI controls ordinary PASS, 7/7 membership controls PASS, 4/4 deliberate fail-open mutations detected, 86/86 producer integrations PASS, six original safety canaries correct; Git tree clean**. The final hosted PR-head run must be verified independently; there is no automatic merge or release from a passing run.

## W15 — per-commit ownership, not just final-tree appearance

A concrete **security defect in this review gate** was reproduced on the connected zSSH VPS before remediation: in a disposable local branch, a commit changed original \`src/lightup/scope.py\` and the immediately following commit reverted it byte-for-byte. \`git diff original_base final_head\` showed only the seven permitted new files, so the previous gate incorrectly returned \`REVIEW_ONLY/exit 3\`. No source was pushed, merged, scanned, or deployed.

The corrected new-only \`scripts/scope_1563_exact_tree_boundary_20261017.py\` now checks **every commit** reachable between immutable base and the pinned exact head:

- Requires one contiguous **linear** parent chain, with no ambiguous merge ancestry; maximum 128 commits and bounded Git output. Empty/truncated records fail closed.
- Checks each individual NUL-delimited Git tree transition, rather than only the net diff; permits \`A\` and \`M\` **only on the seven dedicated own paths**.
- Rejects transient modification of original source, addition then deletion of foreign-worker paths, deletion then re-creation of own files, intermediate symlinks or executable \`100755\` modes, and merge commits even where final changes appear legitimate.
- Independently verifies each changed path's committed Git object type, exact name, canonical regular-file mode and object identity. The output also reports the count of individually checked commits, but still returns non-authorizing \`REVIEW_ONLY/exit 3\`; every anomaly returns \`HOLD/exit 2\`.

The extra **seven ordinary local-Git fixture tests** cover intermediate forbidden edit/revert, foreign add/remove, own delete/readd, symlink/permission-mode toggles, non-linear merges and commit count. Combined with earlier guards, the isolated Git/witness suite now contains **28 real test methods**. Connected zSSH ran them all PASS on the actual own branch code at \`3d14491efc500590a64665254bea68400324fc51\`. This is offline verification of PR **path ownership**, not a source-security audit or permission to merge.

CI remains tied to the exact current PR head and validates this history **before** composed #301/#1535 owner-file overlays. These owner snapshots remain temporary test-only and cannot turn the original base suite or permanent registered VPS CI green. Release requires all independent authorization, revocation, security/privacy, exact-head CI and human GO gates.

## W16 — CI checkout index/tracked/untracked custody

The original post-test \`git diff --exit-code\` is **unstaged-only**. In a synthetic disposable repository, an owned file changed only in the Git index: \`git diff --name-only\` produced no output while \`git diff --cached --name-only\` reported the staged modification. This is independent from the immutable committed-tree history review: both must run.

Both exclusively issue-owned CI workflows now check \`git diff --cached --exit-code\` and \`git ls-files --others --exclude-standard\` in addition to their previous requirements. The focused workflow also reasserts the precise checkout head at the end. The compatibility workflow continues to require exactly the **two known temporarily overlaid, unstaged** foreign owner paths; any additional index or nonignored untracked changes causes a failure. Two new acceptance tests prove the staged-only blind spot and enforce cleanup lines in both workflow files.

Connected permitted zSSH, exact \`bf4fcf083987c74333210e69d6e8ad44279bbfe2\`: **28/28 Git/tree/CI tests PASS, 86/86 producer integrations PASS and original safety canaries PASS**; exact audit receipt \`REVIEW_ONLY ... added_paths 7 checked_commits 38\`; checkout clean. Full hosted CI on the ultimately updated HEAD must be verified separately and is not release authorization.

## W17 — fail-closed pre-execution CI fence and complete PR coverage (2026-10-17)

Two real workflow ordering/coverage gaps were closed **without touching runtime or foreign-owner files**:

1. The primary GitHub-hosted workflow formerly ran project Python tests **before** its own immutable-history review. Its new immediately-post-checkout, pre-setup-python step pins the exact HEAD, refuses dirty tracked/index/nonignored-untracked state and requires the history reviewer to return literal non-authorizing **exit 3** before any project test. The post-test immutable gate remains as a separate defense.
2. The independent #301/#1535 composition workflow formerly had a **pull_request.paths filter**. A source-only malicious revision could skip this otherwise independent gate. It now triggers on every change to the exact #1563 branch (and skips all other branch heads), and verifies clean original checkout **before** history review and external owner-file overlays. Original owner blobs remain temporary, unstaged, exact-SHA pinned, and source owners retain ownership.

Three additional regression methods in the existing own test file guard **both workflows** for no path-filter bypass, pre-execution audit order, and clean index/untracked preflight. All changes are contained in the original seven issue-owned paths. This is an **offline CI integrity repair**, not a runtime authorization fix.

Actual permitted connected zSSH on source **HEAD `11ea6df518b2f6ae123a779c0c0a34e7e3de8127`** (before this documentation-only change), using automatically removed isolated checkout:
- **31/31** own temporary-Git / CI guard regression methods ordinary PASS.
- **7/7** original membership-before-grant methods PASS.
- **Four/four** deliberate unsafe scope mutations rejected with genuine assertions (no crash counted as success).
- **86/86** genuine original producer integration tests PASS.
- Original unchanged full unit suite: **1,275 methods, five existing ordinary FAIL and 23 expected source failures**, the same #301 wall-clock and #1535 registry-history failures already reproduced on main, so project CI is NOT all green.
- Exact branch history gate: `REVIEW_ONLY / exit 3`, seven owned paths, **42 linear commits**; index and working tree clean.
- New source-head [focused hosted run #39068343988](https://github.com/Zennay/Lightup/actions/runs/39068343988) **SUCCESS 2/2** (Python 3.11 and 3.14).
- New source-head [composition hosted run #39068343991](https://github.com/Zennay/Lightup/actions/runs/39068343991) **SUCCESS 2/2** (Python 3.11 and 3.14).
- Original [hosted preflight #39068344004](https://github.com/Zennay/Lightup/actions/runs/39068344004) **FAIL** in both Python jobs; producer dependency **SKIPPED**. Permanent named runner proof remains independent and is NOT claimed.

**Limitations:** the offline history reviewer itself is branch-local, not a trusted external attestator, and its favorable exit code is never deploy/release approval. Authorization correctness, canonical original full-green suite, independent security/privacy, real authenticated two-party consent with at-use revocation, exact approved-SHA permanent registered VPS CI, and explicit human GO remain unsatisfied. No merge, real permit, scan, production handler, shared-runner change or deploy.

## W19–W22 — wider negative membership oracle, canonical decision integrity and test manifest (2026-10-17)

Issue #1563's **existing isolated add-only branch** now checks a substantially larger independent negative authorization matrix. No source-owner, live admission, scanning, release, shared-runner or other-worker files were touched:

- **Six new real scope regression methods (7 → 13)** exercise explicit-host parent/suffix confusion, IPv4 and bracketed IPv6 CIDR right-neighbor membership, a deterministic 64-address global-IP boundary series, exact normalized denied host identity, and repeated denial after replacing untrusted grants across both authorization and lab-mode flags. All target identities are synthetic literals; tests prevent DNS/socket/HTTP and `Authorization.is_current` calls on non-members.
- All denied decisions now require **exact** `ScopeDecision` type, Python `bool` false, **exact `ScopeReason` enum type** (not a string that happens to compare equal), and a real canonical normalized host string; invalid identities retain `None` for normalized host.
- Mutation controls increased from **four → nine**: baseline unsafe grant-substitution, invalid-target rescue, premature grant inspection, spoofed label authority, plus IPv4 CIDR-neighbor admission, subdomain wildcard admission, denied-identity rebinding, string-enum reason substitution and structural proxy decision substitution. Every intentionally fail-open mutation must be caught by the matching real security method via **AssertionError**, never through an unrelated exception or an `expectedFailure` marker.
- A **named 13-case manifest** is checked before running mutators. Previously, replacing a security regression with an unrelated test while preserving the count could falsely satisfy the `testsRun == 13` criterion. A genuine disposable test patch explicitly preserves the total at 13 while substituting an unrelated stub; the new manifest correctly rejects it. The original suite is then restored and accepted. Two independent mutation-quality tests cover the exact method list and the substitution witness.

**Executed connected authorized zSSH, Python 3.14.4** (latest tested code HEAD `21cf3441788cc7c1f567ee512289b3f6d8522db3`): **13/13** genuine negative scope methods, **35/35** Git/CI/mutation-quality methods, **9/9** deliberately broken policies detected; source-history gate `REVIEW_ONLY/exit 3` across **51 linear commits** and the same seven wholly new owned paths; clean disposable checkout and no target I/O. On preceding source HEAD `709348e430c8f323277b3ef3b6cec6f72edca2cd`, 86/86 genuine original producer integrations passed; unchanged canonical full mainline suite remained **five existing #301/#1535 failures**, 23 deliberately expected unresolved source REDs among 1,283 methods. **Do not re-label this as green original CI.**

**Independent exact-head hosted evidence for earlier 49-commit code HEAD `709348e...`:** [dedicated #39069092913](https://github.com/Zennay/Lightup/actions/runs/39069092913) **SUCCESS 2/2** on Python3.11/3.14; [owner composition #39069093033](https://github.com/Zennay/Lightup/actions/runs/39069093033) **SUCCESS 2/2** — each Python version **1,303 ordinary unit results OK with 33 intentional expected source failures and 86 original integrations OK**. Original [hosted preflight #39069093155](https://github.com/Zennay/Lightup/actions/runs/39069093155) **FAILED** in both Python versions, with one genuine previously-known #301 expired authorization fixture failure and 23 intentionally expected source REDs each. Latest manifest-code HEAD CI runs are separate, not automatically covered by this earlier proof.

All work remains **INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD**. A green negative oracle is NOT a positive real grant proof or test of source-owner fixes. Needed before release: source-owner integration, verified independent client/operator consent, action-time revocation, independent security/privacy review, true ordinary full-green exact-approved SHA hosted + permanently registered named VPS CI, explicit HUMAN GO. **No merge, release, dispatch, live permit, target scan or deployment.**

## Stop conditions

No existing `src/lightup` sources, `tests/test_scope.py`, shared workflows, state/database, activation, execution, target workers, deployment or peer-worker files are modified. Scope #364 and existing PR #1263 remain independent. A green negative unit suite **is not** evidence of usable positive authority, authenticated two-party consent, at-use revocation, independent security/privacy review, passing full exact-head hosted plus registered VPS CI or HUMAN GO.

**Never merge, deploy, activate, scan, issue grants, dispatch handlers, or release solely on this contract.**
