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
