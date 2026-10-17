# Scope #1547 — exact synthetic Git status stream HOLD acceptance

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
