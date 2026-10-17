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

## W24–W26 — offline deny-chain integration and strict ordinary PASS (2026-10-17)

Expanded the exact original issue #1563 **negative-only, non-authorizing** acceptance across the installed **scope → planner → inactive permit-gate** chain, without modifying `src/lightup/**` or activating any handler.

### New executable contract (three genuine additional methods; 13 → 16)

1. `Planner.build` must produce an `AssessmentPlan` of exact type with `scope.allowed is False`, empty `capability_ids` and literal `execution_enabled is False` for undeclared hostname, IPv4 network-neighbor and IPv6 prefix-neighbor inputs. `get_capabilities` is a patched, observed sentinel and **must not be called**. The original target identity, labels and grant object remain unchanged.
2. `ActivationGate.issue` must raise `PermissionError` **before** calling `token_urlsafe` for all three activation modes (`PLAN_ONLY`, `LAB_ONLY`, `AUTHORIZED`), both public authorization-configuration settings, all four **fictional** grant cases and all three undeclared identities. A patched `token_urlsafe` is an inert spy returning a dummy value, not a real permit; no token or grant is issued.
3. Blank/invalid target identities likewise stop both planner discovery and permit-token creation, independent of grant and activation mode, with exact `INVALID_TARGET`.

Scope-side network and `Authorization.is_current` entry points are patched and forbidden on all nonmember inputs, as before. This exercises **only the offline negative denial path** of existing code; it does not test successful authorization, authorize a target, invoke a handler, or create a real grant/permit.

### Real unsafe-fix mutation sensitivity

The previously nine dedicated `ScopePolicy.decide` mutants are preserved, plus **five new downstream mutants**: capabilities on a denied plan, premature capability discovery, `execution_enabled=True` for a denied plan, missing permit denial, and token allocation before scope check. The broken implementation is installed briefly through `unittest.mock.patch` and required to fail by matching **real assertion**, with no unexpected errors or `expectedFailure` credit. The temporary invalid-output mutants were narrowed to their intended pure-scope fixtures so that downstream exceptions cannot produce misleading mutation credit.

`REQUIRED_TEST_METHODS` now explicitly pins **all 16 named** security methods, not merely the test count. Two new metadata tests enforce five independent downstream mutation entries and restored source identities.

A further **real fail-closed bug** in the acceptance harness was reproduced and fixed: `unittest.TestResult.wasSuccessful()` treats an `expectedFailure` or `skip` as green, even when a named security method is silently disabled. New `baseline_is_strictly_green` requires 16 ordinarily successful tests and zero failures, errors, skips, expectedFailures or unexpected successes. Three additional regressions exercise fake result objects and **genuine decorated named methods**, proving a count-preserving `expectedFailure` or `skip` is HOLD, never a green baseline.

### Observed evidence and unresolved gates

Connected permitted zSSH against exact code-head `ed2fd95b3391893d64b188068d48c509c8f9f369` on isolated disposable checkout:
- **16/16** scope/plan/permit negative real tests PASS.
- **40/40** Git/CI/integrity synthetic methods PASS, including actual `expectedFailure` and `skip` false-green reproductions.
- **14/14** deliberate fail-open source mutations rejected via matching assertion failures; all original methods restored.
- **86/86** real producer integration tests PASS; **all six** original `check_safety_canaries.py` states correct.
- The ordinary uncomposed full suite on earlier immediately preceding code-head `6dc86cc0472baf45ab3f22a6a195426beb59a1c2` still had **five pre-existing #301/#1535 real failures** and **23 deliberately expected source REDs** (1,290 tests). These defects belong to separate source owners and remain unresolved. Do not greenwash it.
- Immutable-branch compare on code-head: **59 commits ahead/0 behind, exactly 7 completely added-only issue-owned paths**, no modification to source, other workers or runners. Dedicated GitHub-hosted Python3.11/3.14 [#39070099133](https://github.com/Zennay/Lightup/actions/runs/39070099133) SUCCESS 2/2. The independent composition and canonical original CI are separate; initial statuses were pending and require a fresh exact-head check.

**Release posture stays INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** A deny-chain proof does not validate genuine independent client and operator consent, revocation-at-use, positive authorization, source-owner fixes, privacy/security, or permanent registered named-VPS CI. No merge, production scan, permit, handler, deployment, shared-runner mutation or release. Explicit human GO remains required.

## W28–W30 — 730-case subtest integrity, mutation early-denial accounting (2026-10-17)

**Root cause reproduced in a real disposable zSSH checkout:** the named `unittest` method manifest covers 16 security methods, but **730** individual `subTest` cases. Replacing the *entire* 256-case `test_generated_global_ipv4_nonmembers_do_not_gain_scope` implementation with a superficially passing **single-subcase** method preserves all 16 discovered names, `testsRun == 16` and `wasSuccessful() is True`. The original genuine prior source-head `c105711...` still returned **`baseline_green=True`**. With the new source, exactly the same in-memory test substitution returns `baseline_green=False` and observes only **475/730** cases, so the acceptance process stops with HOLD instead of reporting false green. Nothing was written to source files during that comparison.

### Material changes, confined to two previously owned files

- `scripts/scope_1563_membership_mutation_proof_20261017.py` now runs the real original 16-case suite with a `CoverageResult` subclass of `unittest.TextTestResult`. The result records *attempted and passed* `subTest` callbacks per named method, with an immutable-in-practice literal expected-count dictionary totaling **730**. The ordinary-green acceptance gate requires the exact map of **all 16 named methods**, exactly **730 passing subtests**, no nonordinary `expectedFailure` or `skip`, no errors and no false-positive discovery. The original named-method manifest remains independently enforced.
- Deliberately broken policy mutation runs also need complete attempted-subcase coverage **except** when a real security assertion fails early inside that same named method: premature failure can correctly prevent later *nested* subtests. Partial matrices in **unaffected methods** or unexplained skipped tests are HOLD. All 14 existing deliberate mutants must still produce matching real AssertionErrors with no unexpected errors or expectedFailure shortcuts.
- `tests/test_scope_1563_exact_tree_boundary_20261017.py` includes **eight** new independent ordinary QA methods (40 → 48): exact all-730 coverage, count-preserving subcase reassignment, real single-subcase method swap, missing result instrumentation, mutation skip/partial-count rejection, real full-coverage fail-open mutation, correctly handled early assertion truncation and proof that truncation in an unaffected security test is rejected.

### Observed proof, limitations and remaining HOLD

On the connected permitted zSSH VPS, Python 3.14.4, isolated exact code HEAD `684ba233cadcbcb65007fd96ca14ebf744c7dae0`: **16/16** real scope/planner/permit-denial tests PASS, **48/48** own git/test-integrity QA tests PASS, all **14/14** deliberate fail-open mutant categories assertion-detected, unchanged cleanup (clean worktree, temporary checkout deleted). Direct independent GitHub compare to immutable `main` `e73b7445c87ad239bdb03c50a99078ef93163b02`: **66 add-only commits, zero behind, exactly the same seven new issue-owned paths, zero original source, runner or other-worker file changes**. Dedicated hosted [Python3.11/3.14 #39070790299](https://github.com/Zennay/Lightup/actions/runs/39070790299) was **SUCCESS 2/2** on this code HEAD. Original base full unit CI remains blocked by separately owned #301/#1535 fixture and registry-history source issues; independent composed/normal hosted results require exact-final-head checks. The permanent registered named VPS runner still requires its separate owner #1144, not worked around here.

**Non-authorizing limit:** these checks only prove *offline negative scope membership and downstream denial*. They do not establish valid real client/operator consent, source-owner production authorization, live action-time revocation, privacy/security certification, full normal-green original hosted or registered named VPS CI, or HUMAN GO. Phase remains **INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD**. No merge, release, handler, real permit/grant, security scan, deployment or runner intervention.

## W31 — trustworthy unittest failure identity, not forged `str(_SubTest)` (2026-10-17)

A genuine `unittest._SubTest` displays both its owning test method **and printable parameters** in `str(case)`. The prior mutation reviewer accepted `expected_test_prefix in str(case)`, so a failure belonging to an unrelated method could be **misattributed** if printed parameters contained a target security method name. The reviewer now resolves the original `case.test_case._testMethodName` (or direct test-case method identity) and **only** attributes a deliberate assertion to that actual method. This same canonical helper is used to authorize reduced nested-subtest counts only on the truly failing security method; fake display strings do not affect the accounting.

Two additional genuine offline QA methods explicitly forge a case whose printed string names `test_invalid_target...` while its real method is unrelated (**HOLD**), then verify that actual `unittest._SubTest` failures are bound to their real parent method. On connected authorized zSSH, **exact source HEAD `4b9e7232956c247c48f1fb378756336dcdf91f37`**: **16/16** membership/planner/permit tests PASS, **50/50** independent Git/CI/mutation-quality test methods PASS, and **14/14** unsafe mutations correctly assertion-detected, with clean disposable checkout. The baseline still requires **730/730** completed ordinary passing subcases across all 16 named methods. No real grant/permit, active target, source owner, shared runner, scan or deploy modified. Latest official dual-Python hosted exact-head proof is checked separately after this documentation commit.

**HOLD unchanged:** INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. Original source-owner #301/#1535 defects, client/operator authentication, at-use revocation, independent security/privacy signoff, original full-green hosted and registered named-VPS CI, explicit HUMAN GO are not solved by these offline tests. Never merge or deploy solely on these receipts.

## W32–W34 — exact subcase identity fingerprints and same-count greenwashing reproduction (2026-10-17)

**Audited real security-evidence gap** in #1563's own offline harness: the previous `CoverageResult` tracked only the count of each subTest. A method that repeats **one unlisted public IP** 256 times across the four grant-label variants can keep *all 16 named methods*, *all 730 subcase counts*, zero `unittest` failures and appear green, while silently discarding 63 of the 64 distinct /28-neighbor boundary IP inputs. Exact source behavior was reproduced on a disposable authorized connected zSSH checkout:

- Run the identical 256-case duplicate-input test patch against prior committed harness at `19acf9a07e8cfb2088de472693a21fab6cb801ef`: **`testsRun=16`, `ordinary_pass=True`, `subcases=730`, `safety_baseline_green=True`**. The old gate is genuinely fooled.
- Repeat unchanged patch against new harness at code HEAD `9d4cc40db1a6fae67d5b37e6b218b45e78e9682d`: **`testsRun=16`, `ordinary_pass=True`, `subcases=730`, but `safety_baseline_green=False`**. The same-count duplicate test is **HOLD**.

### Actual shipped design, entirely within three already owned #1563 files

- All 16 real named methods now emit disambiguated `subTest` parameter identities: the two “unrelated declared host/network” methods previously omitted the 4-way grant label, causing only 6 unique parameter tuples among 24 cases each. Explicit `grant` labels now make **all 730 baseline case parameter tuples independently distinct**.
- The read-only mutation/acceptance harness derives a stable canonical JSON token from the actual `unittest._SubTest.params`, with sorted keys, ASCII escaping and no nonfinite floats; no target I/O or grant is performed. A **static, explicit manifest of 16 SHA-256 digests**, one for each expected set of actual inputs, pins all 730 case identities. Both counts and exact case-fingerprints must match for a genuine baseline PASS. Count-preserving substitutions, duplicates and malformed/unserializable parameters fail closed.
- During the deliberate fail-open mutation runs the original test identities must still be unchanged for every **fully executed** method; assertion-triggered legitimate nested early exits are permitted only in an actually assertion-failing parent method, following the independently proven W29 rules.
- Four additional independent QA regressions cover 16 fixed SHA-256 baselines, full per-method distinctness, a real 256-of-256 equal-count fixture substitution, and an unrelated mutation-run case-identity substitution. The same core 14 fail-open safety mutants remain required to fail by matching genuine security assertions.

**Actual permitted zSSH on code HEAD `9d4cc40db1a6fae67d5b37e6b218b45e78e9682d`**: **16/16** real negative scope/planner/permit tests PASS; **54/54** own Git-history/CI/subtest-integrity tests PASS; **14/14** deliberately unsafe mutations assertion-detected; clean disposable checkout. No production files, real grant or live network targets involved. Exact immutable-tree and hosted dual-Python results must be checked separately on the final documentation SHA.

**This is an offline evidence quality improvement, NOT a positive consent/permit or general LightUp release gate clearance.** Fase **INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD**. Still requires real independently authenticated client+operator consent with at-use revocation, source-owner repairs #301/#1535, normal original fully green exact approved SHA hosted CI AND permanently registered named VPS, privacy/security approval and explicit HUMAN GO. No merge, real scan, handler, grant, permit, deployment, shared runner change or release.

## Stop conditions

No existing `src/lightup` sources, `tests/test_scope.py`, shared workflows, state/database, activation, execution, target workers, deployment or peer-worker files are modified. Scope #364 and existing PR #1263 remain independent. A green negative unit suite **is not** evidence of usable positive authority, authenticated two-party consent, at-use revocation, independent security/privacy review, passing full exact-head hosted plus registered VPS CI or HUMAN GO.

**Never merge, deploy, activate, scan, issue grants, dispatch handlers, or release solely on this contract.**
