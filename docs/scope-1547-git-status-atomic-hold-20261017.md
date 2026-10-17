# Scope #1547 — exact synthetic Git status stream HOLD acceptance

## CURRENT VERIFIED STATUS — 17 October 2026 · W13 (supersedes historical RED entries below)

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** The previously failing original source-owner newline status parser **has now been independently fixed** on separately owned draft #1538 at exact SHA `f9358ac4d21ca722e0ce1dc3d885aa45024fa9ba`: its original `_STATUS_CODE.match()` was changed to exact `.fullmatch()` and new native source regressions were added for four newline corruptions. This source owner repair is *not* our commit or a release.

### New mandatory original source proof, above and beyond earlier synthetic receipt tests
- Added independent *source-owner* strict test for **all 256 single-byte status tokens** (exactly A/M/D/T accepted, all other values denied with `GitChangeError`) and **202 valid three-digit R000..R100 / C000..C100 similarity codes**, plus malformed shortened/out-of-range/newline variants. Combined with the previous nine malformed source contracts, the current actual source owner SHA now passes mandatory source grammar tests.
- Added a genuinely disposable local **no-hook/no-remote** Git repository integrating real Git `diff --name-status -M -z` bytes with the *two independently implemented* parsers. Four actual Git A/D/M/R records parse with precisely the same status/path identities and count; a late synthetic LF-corrupt record causes both to reject the entire stream. Git fixture never targets any real infrastructure.
- Own latest actual VPS old pinned source suite: **29 test methods OK (six intentional pinned-original-source expectedFailures; four optional source-owner skip methods)**; separate real current owner strict gate: **four methods ordinary PASS with `LIGHTUP_SCOPE1547_REQUIRE_SOURCE_FIX=1`**, no legacy expectedFailures.

### Actual combined code and exact CI evidence
- Permitted zSSH **full Python 3.14 unit discovery: 1,305/1,305 ordinary PASS**, zero skip, zero expected source failure, in isolated disposable checkout with **only actual owner #1538 repaired `git_changes.py` SHA `f9358ac4...` and independently owned #1536 warning report blob `f8b915...`** overlaid locally. No hand-made regex replacement needed. Both files restored afterward and source/own temp checkouts clean. This remains *uncommitted local composability* of two separately owned fixes, not published integrated release SHA.
- [Exact own GitHub-hosted CI run #39029577957](https://github.com/Zennay/Lightup/actions/runs/39029577957): **COMPLETED SUCCESS all 4/4 jobs**, Python3.11 and Python3.14 synthetic reviewer **2/2** and Python3.11 and Python3.14 actual live-branch original source acceptance **2/2** on verified owner SHA `f9358ac4d21ca722e0ce1dc3d885aa45024fa9ba`. Historical earlier red runs are accurately recorded below but are superseded by this newer source fix and proof.
- [Exact own GitHub-hosted full offline preflight run #39029577956](https://github.com/Zennay/Lightup/actions/runs/39029577956): **COMPLETED SUCCESS all 4/4 jobs** (Python 3.11/3.14 unit; 3.11/3.14 original producer integrations). All are GitHub-hosted, **NOT** permanently registered named VPS runner proof.
- [Current named permanent runner LightUp CI run #39029577978](https://github.com/Zennay/Lightup/actions/runs/39029577978) still **QUEUED/unproven**. No runner bypass, deploy, merge, or real target access.

**NON-AUTHORIZING HOLD REMAINS:** original owner branch is still a draft; independent security and privacy review, real separately authenticated client/operator consent and revocation at use, exact approved integrated source/release SHA hosted + **permanently registered named VPS** CI, and explicit HUMAN GO remain mandatory. Passing source grammar review does NOT grant permission for scans, grants, handler dispatch, merges, deploys, or releases.

---


**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. Do not merge, deploy, scan targets, authorize grants or dispatch handlers.**

## Original source-owner finding
Original draft PR #1538, exact pinned SHA c37b909907fc7291cb28b2f37a78db7f2fea2855:
- Mgarbage NUL src/a.py NUL silently classified as M.
- Rnotanumber NUL old.py NUL new.py NUL classified as R.
- Q NUL src/a.py NUL accepted by parser, then unknown status silently skipped.
- Missing final NUL accepted for name-status and numstat.
These are synthetic corrupt records, not a claim that normal Git produces them. This is a change-review integrity gap, not evidence of an authorization bypass.

## Independent delivery
scripts/review_scope_git_status_synthetic_1547.py is a stdlib-only offline stdin JSON reviewer, not imported or wired into the application. Accepts exact canonical ASCII JSON (schema = lightup.scope1547.synthetic_name_status.v1; name_status_b64 = strict canonical base64), at most 64 records and 32 KiB of raw status data. Only canonical A/M/D/T statuses and R/C with decimal similarity 0..100 are allowed. Reject unknown scores, missing NUL, malformed/duplicate statuses or paths, invalid UTF-8, aliases, traversal and unbounded input.

Valid fictional bytes produce REVIEW_ONLY exit 3; rejected bytes HOLD exit 2; never return success exit 0. The receipt gives no paths and ALWAYS sets authorized/client_consent/operator_consent/grant/scan/handler_dispatch/merge/deploy/release = false plus not_authorization=true. No Git subprocess or network is called by the CLI. This is NOT a proof of data provenance or Git authenticity.

## Repeatable test evidence
Run: PYTHONPATH=src:tests python3 -I -S -B -m unittest discover -s tests -p test_scope_1547_synthetic_git_status.py -v

On connected permitted zSSH vps-bb300bba, Python3.14.4, exact branch f96b4274fd735db1d403c1e1b5ed4e9325ba3925: 15 tests executed, 10 ordinary PASS, 5 intentional original-source expectedFailures, zero unexpected. The tests use a disposable no-hook/no-remote local Git fixture for real R100 -z output and synthetic malformed/canonical inputs, and check the non-authorizing privacy-minimal CLI result. The expectedFailures must turn into mandatory passes only after the actual #1538 owner fixes the parser.

## Non-overlap and release controls
Scope #1547 is status grammar only. #1541 owns exact Git path identity; #1545 owns patch byte identity; #1543 owns configurable inferred verdict policy; #1538 retains ownership of src/lightup/git_changes.py. This branch changes only wholly new tests, docs, standalone CLI and optionally an independent hosted-only CI workflow; no original owner or other-worker file is edited.

Release HOLD pending actual source-owner fix, independent privacy/security review, real separate authenticated client/operator consent with at-use revocation, full approved exact-SHA hosted and permanently registered named VPS CI and explicit HUMAN GO. No merge, deploy, live targets/scans/grants/handlers or release.

## October 17 W5-W8: strict Git grammar, transport and source-owner acceptance

The pinned original owner `c37b9099...` still has the five original source defects as deliberately visible expected failures. **The source owner separately fixed the status parser on open draft PR #1538 at SHA `19dcd928e4410ed6d9fb56dc992434d69a48c3a0`**. An independently cloned, clean, unmodified copy of that exact SHA passed all five original strict rejection cases and three ordinary valid status controls. The owner PR is still draft; this is not a mainline production repair or release.

### Real RED -> GREEN improvements in only our own branch
- Originally the standalone fictional reviewer accepted abbreviated `R1`, `R99`, `C50`, which **do not match Git's zero-padded three-digit rename/copy score format** or the revised owner parser. New tests first failed; the bounded synthetic parser now accepts exactly `R000..R100` / `C000..C100` and rejects abbreviated/oversized forms, preserving the real no-hook/no-remote `R100` Git rename positive fixture.
- The previous CLI could accept a valid JSON *prefix* before reading later fragments, and could return `REVIEW_ONLY` even if stdout had accepted only a partial write. Tests failed first; complete bounded reads and exact receipt-write length checks now fail closed. A good source split into 93 one-byte reads still yields REVIEW_ONLY, pathological 257 fragments and nonbyte stdin read values HOLD. Never a success/exit0 or live authority.
- Added another real disposable local Git repository for add/modify/delete `-z` output, now accepted without network/hooks/targets.
- GitHub-hosted CI originally failed when the default PR merge ref picked up source-owner edits to `src/lightup/git_changes.py` and `tests/test_change_review.py` not owned by us. Own hosted-only workflow now fetches and tests **the exact PR head** (`github.event.pull_request.head.sha`) rather than GitHub's synthetic moving merge commit. Pinned parent and four-additive-owned-path diff are still mandatory. No shared CI, other-worker source, installed runners or deployment touched.

### Strict owner source test, without changing any owner branch
The existing five `expectedFailure` cases are retained **only for our pinned original source ancestor**. One additional **opt-in** `StrictSourceOwnerGate` acceptance verifies all five original malformed status/terminator defects and three valid controls. Default runs skip the future-source gate rather than claiming a production fix.

- Pinned original #1547 source, explicit `LIGHTUP_SCOPE1547_REQUIRE_SOURCE_FIX=1`: **five genuine failing subtests** (expected RED before source owner repair).
- Separate disposable copy of our branch, locally overlaid only with the actual #1538 owner's one `src/lightup/git_changes.py` file from clean SHA `19dcd928...`: **all five strict rejections + three positives passed**. Also 14 standalone synthetic methods + 86 original producer-integrations + 29 change-review + 9 GitHub-change suites passed. The temporary file overlay was restored, both owner and own source checkouts remained clean. This is local source-fix composability, **not a published combined release commit**.
- Run the opt-in strict source acceptance independently on a reviewed updated source checkout: `LIGHTUP_SCOPE1547_REQUIRE_SOURCE_FIX=1 PYTHONPATH=src:tests python3 -S -B -m unittest test_scope_1547_synthetic_git_status.StrictSourceOwnerGate -v`.

**Truth boundary:** Own standalone review remains independent, inferred and non-authorizing. Five original expectedFailures remain on the pinned old source; latest owner draft has an independently demonstrated fix. Hosted exact-head success does not prove full permanent named VPS runner CI or real human/operator/client authorization. DRAFT/HOLD, no merge/deploy/scans/grants/handlers.

## W9: automatic source RED -> mandatory GREEN and genuine three-branch local composition

The five historical owner-contract methods now use an explicit *source-grammar-aware* decorator, not an unconditional expectedFailure: when the unmodified pinned original owner does **not** contain its strict `_STATUS_CODE` and NUL-record parser, the five cases remain visible expected RED; on actual repaired source, **the same five must PASS normally**, or the suite fails. This addresses a real CI false-red on GitHub's moving PR merge ref: a previously repaired owner produced five *unexpected successes* under the old unconditional decorator.

- Own immutable pinned old source: **20 test methods OK (five original expectedFailures, one opt-in strict skip)**.
- Disposable local checkout using only the owner #1538 repaired `src/lightup/git_changes.py` blob (source SHA `19dcd928e4410ed6d9fb56dc992434d69a48c3a0`): **20 methods ordinary OK (one optional strict skip)**. Separately forced strict gate on same owner blob **all five malformed record cases plus three valid controls PASS**.
- Additional separate temporary combination on own tested source SHA `4a5d7e5dd6ec6091411b1bda7b8ef713e21cdbb2`: **only** the already independently owned #1536 `src/lightup/capability_registry_history_report.py` blob from SHA `f8b91596d48f318cb75050b70ccbf5a50d2cd106` **plus** the original owner #1538 fixed Git parser from SHA `19dcd928...` were copied **locally and uncommitted**. Whole VPS Python3.14 offline unittest discovery **1,296/1,296 OK, one intentional opt-in strict skip**. No unexpected source REDs remained. One benign test fixture HTTP server BrokenPipe line was printed despite suite success. Both temp source files were restored; original branch and disposable worktrees clean.
- The actual GitHub branch still contains **only four originally new owned paths**. Nothing from either owner source fix was committed or copied into a GitHub branch; no permanent runner, policy/authority or deployment changed.

**Separate release gates** are unchanged: source-owner integration decision and exact approved combined SHA, independent privacy/security review, authenticated distinct client and operator consent and at-use revocation, complete exact-SHA hosted plus *permanently registered named VPS* CI, and explicit HUMAN GO. These offline tests are strong compatibility evidence **not** authorization/merging permission. Remain DRAFT/HOLD.


## W10 — source owner regex end-anchor audit, actual newline RED and exhaustive score corpus

On original source-owner draft #1538 exact SHA 19dcd928e4410ed6d9fb56dc992434d69a48c3a0, the status regex uses re.match with ^ and $. In Python, $ can also match immediately before a final newline, so synthetic corrupt NUL-delimited status tokens M+LF, A+LF, R100+LF and C001+LF are all accepted and classified as ordinary changed files in inferred offline review. Connected zSSH read-only Python3.14.4 independently reproduced all four cases on this exact unmodified owner checkout. A carriage-return followed by LF is rejected. This is review-integrity risk, NOT a demonstrated authorization bypass.

Our own strictly fictional parser already rejects those four tokens. Its tests now exercise newline-negative cases, including actual stdin/CLI HOLD exit 2. The original historical parser source has five acknowledged expectedFailure contract cases; this adds a sixth original-source expectedFailure on the pinned old branch. An explicit opt-in source-owner strict test proves FOUR real failing newline subcases on the newer source owner, while its earlier five source fixes are independently GREEN. The source owner must fix the four residual newline cases.

Independently tested a repair oracle in-memory only on unchanged source owner: replace the status matcher temporarily with a compiled full-string pattern anchored with backslash-A and backslash-Z. Four malformed tokens then HOLD and three genuine M/R001/R100 controls continue to parse; exiting the test restores the exact original matcher. Recommended source-owner review is to use fullmatch or the strict backslash-Z anchor. No production/source-owner file, branch or permanent runner was changed.

Added complete canonical Git similarity corpus: 202 positive synthetic status controls covering 101 R000..R100 + 101 C000..C100 scores, plus abbreviated, out-of-range and newline-corrupted cases that must HOLD. The CLI and git fixture remain offline and non-authorizing.

Actual connected zSSH own exact SHA 09e1072942c103a9822d5d4c7e477e016c0e62e6: 23 own test methods OK (six intended original-source expectedFailures, two opt-in strict-owner skips), 86 original producer-integration tests ordinary PASS, clean own worktree. Current owner strict test on a disposable own checkout overlaid temporarily with exactly original owner 19dcd Git parser: FOUR genuine FAIL until owner applies end-anchor repair. The in-memory exact end-anchor oracle passed and restored original matcher without touching any saved source.

**RELEASE HOLD:** distinct authenticated client/operator consent with at-use revocation, independent privacy/security, original source-owner correction and approval, complete hosted and permanently registered named VPS CI on approved combined exact SHA, explicit HUMAN GO. No merge/deploy/scans/grants/handlers/release.

## W11 — separated *failing* hosted owner gate, exhaustive synthetic boundaries, independently composed 1,303-test strict PASS

**Source owner remains separately responsible for its own repair.** The current #1538 owner SHA `19dcd928e4410ed6d9fb56dc992434d69a48c3a0` still accepts four newline-suffixed synthetic status tokens due to the Python regex dollar end-anchor. No original source, other worker branch, shared workflow, permanent runner or release controls were changed in this lane.

### New genuinely fail-closed GitHub-hosted source-owner acceptance
Own `.github/workflows/scope-1547-git-status-offline.yml` now runs a **separate** `source-owner-acceptance` job after both standalone Python3.11 and Python3.14 jobs complete. It checks out **our own exact PR head**, reads the original owner branch SHA (`refs/remotes/origin/claude/lightup-leap`), proves ancestry from the pinned original source owner, copies only own source/tests/standalone synthetic CLI to an ephemeral temp directory, and overlays exactly the current owner `src/lightup/git_changes.py` blob via `git show` (no `git worktree`, Git filters, hooks, source branch push, target scanning or runtime wiring). It invokes the mandatory actual-owner nine-case source gate with `LIGHTUP_SCOPE1547_REQUIRE_SOURCE_FIX=1`. Python3.14-only on GitHub-hosted Ubuntu; **never the permanent named VPS runner**.

Actual [hosted W11 RED #39028375411](https://github.com/Zennay/Lightup/actions/runs/39028375411): two own matrix jobs completed **SUCCESS**, distinct owner-source acceptance job **FAIL**. Raw log proves exact owner SHA `19dcd928...` and **exactly four authentic failing LF token cases** (`M`, `A`, `R100`, `C001` with an inserted trailing LF); previous five owner grammar/NUL fixes now pass. This is INTENTIONAL and MUST NOT be reported as 'full workflow green'. The green own code matrix is a different statement.

Latest [own W11 extended-hosted #39028607470](https://github.com/Zennay/Lightup/actions/runs/39028607470) likewise proves standalone Python3.11 + 3.14 **2/2 SUCCESS**, separate source-owner acceptance **FAIL**. The accompanying [complete offline hosted preflight #39028607462](https://github.com/Zennay/Lightup/actions/runs/39028607462) is **COMPLETED SUCCESS 4/4** (two unit + two actual offline producer-integrations). These are hosted checks, not permanent named VPS proof.

### Actual additional behavior and tests
- The sixth historical expectedFailure (LF status alias) is now automatically promoted to an ordinary mandatory regression on a genuinely or partially repaired owner parser, rather than producing an 'unexpected success' and making an actual source fix look like failure. The original pinned old source still reports six intended REDs; a disposable copy with current #1538 owner's five fixes reports only the one truthful remaining LF expected RED. Partial repairs are mandatory ordinary red, not accepted as done.
- The fictional standalone parser has tests for **all 256 possible single-byte status tokens** (A/M/D/T permit review-only, all 252 others HOLD), **all 202 legal three-digit Git R/C similarity scores**, and short/ambiguous similarity forms, late corrupt status after a good prefix, status-token newline, real no-hook/no-remote Git add/modify/delete and rename fixture, malformed fragmented stdin, swallowed stdin OSError and short/failed stdout output. End-to-end late corrupt CLI batch returns HOLD/exit2 and never includes any of the fictional paths in the privacy-minimal receipt. No authority flags can become true.
- Connected zSSH own latest test code: **27 own methods OK**, six deliberately pinned-old-source expectedFailures, two opt-in source-owner skips; **86 producer integrations + 29 change-review + 9 GitHub-change ordinary PASS**. Clean own branch.

### Reproduced strict fully-green patch composition (isolated temporary files only)
From our current own isolated branch plus only separately owned #1536 Python3.14 registry report blob (`f8b91596...`) and latest actual owner #1538 Git parser blob (`19dcd928...`), an isolated allowed zSSH clone was temporarily patched with exactly one character-class anchoring change in *that disposable source blob only* (`$` end-anchor replaced by strict `\Z`). `LIGHTUP_SCOPE1547_REQUIRE_SOURCE_FIX=1` with **all ordinary and strict source-owner gates enabled**, full Python3.14 unittest discovery executed **1,303/1,303 PASS, exit0, zero expected source failures, zero skips**. Existing CLI/system-fixture stderr includes an intermittent harmless BrokenPipeError after success, not a unit failure. Both temporary source files were restored, both own and disposable working trees clean. This proves an independently reproducible remediation and test compatibility, **NOT** a reviewed/published combined release SHA and NOT owner approval.

**DRAFT/HOLD** until #1538 owner independently accepts/commits the LF fix, security/privacy review, distinct real authenticated client/operator consent with live at-use revocation, complete hosted plus permanently registered named VPS runner CI on the exact approved combined SHA, and explicit human GO. No merge, deployment, target scanning, grants, handler dispatch or release.

## W12 — source-owner review gate now checks BOTH supported Python versions

The independently failing source-owner contract is now an actual GitHub-hosted **Python 3.11 + Python 3.14 matrix**, with `fail-fast: false`, separate from the existing two standalone green hosted jobs. Every owner gate invocation reads the original owner branch SHA by verified Git ref, overlays only the raw source owner blob in a disposable temp checkout, and executes the nine-case strict parser acceptance (five previously fixed defects + four outstanding LF status aliases). As long as the owner has not fixed the LF alias, **both supported source-owner jobs must remain RED**; that is the correct fail-closed result, not an infrastructure failure. Once the owner independently fixes it, a re-run should show normal PASS, without any release authority automatically granted. No permanent named VPS runner or shared CI workflow is used.

Exact final own SHA, hosted job IDs and run conclusions must be independently verified before claiming their result in Notion or this PR; prior fully exercised strict patch in temporary zSSH clone still passed **1,303/1,303 tests with both existing owner blobs and the one-line newline repair**, no skips/expected failures, all restored after execution. Release remains **DRAFT/HOLD**.
