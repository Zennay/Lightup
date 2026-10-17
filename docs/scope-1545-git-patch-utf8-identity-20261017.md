# LightUp issue #1545 — original Git patch byte identity, synthetic offline REVIEW/HOLD

**INCUBATE M3/M7 — PLAN/LAB ONLY — DRAFT/HOLD. NO MERGE / DEPLOY /
REAL TARGETS / SCANS / GRANTS / HANDLERS / RELEASE.**

## Original source defect witnessed, not repaired here

Source-owner [draft PR #1538](https://github.com/Zennay/Lightup/pull/1538)
at exact pinned commit 26dd88d33c8735658ae819c7e017b2f36493a039
introduced the inferred, non-authorizing Git change review. In
src/lightup/git_changes.py, _git(...) converts original bytes to UTF-8
using errors="replace" before assigning the review's patch field. A
no-network/no-hook temporary Git repository with a synthetic changed
Python file containing raw 0xFF proves git diff really contains 0xFF, while
collect_git_range() returns a patch with U+FFFD instead. Good UTF-8 source
content (e.g. a café comment) remains intact.

This is not identical to [issue #1541](https://github.com/Zennay/Lightup/issues/1541)
and [draft #1542](https://github.com/Zennay/Lightup/pull/1542), which own
**file path identity**. Here only original *patch text bytes* are in scope.
No authorization bypass is claimed. A lossy inferred report cannot attest
exact original changed source bytes or be used as a release credential.

The synthetic original-source expectedFailure deliberately remains RED until
the original #1538 source owner strictly rejects ambiguous patch bytes before
review. This branch does not patch any production or owner file.

## Isolated deliverable and use

Owner-isolated branch: chatgpt/scope-1545-patch-utf8-identity-20261017.
Pinned base: 26dd88d33c8735658ae819c7e017b2f36493a039.

Only new files under distinctive 1545 names:
- scripts/review_scope_patch_bytes_offline_1545.py
- tests/test_scope_1545_patch_bytes_offline_20261017.py
- docs/scope-1545-git-patch-utf8-identity-20261017.md
- .github/workflows/scope1545-patch-bytes.yml (own hosted acceptance only)

The standalone **opt-in synthetic** CLI accepts a canonical ASCII JSON object
with exact keys schema/patches, where each patch has exact path_id, patch_b64,
and sha256 lowercase hex keys. Each path_id is an opaque fictional ID; **never
supply customer paths, secrets, target data or unauthenticated consent**.

Fictional JSON payload example shape (replace BODY and SHA with the exact
base64 and SHA-256 of the **same** synthetic unified diff):

    {
      "patches":[{"patch_b64":"BODY","path_id":"fixture_1","sha256":"SHA"}],
      "schema":"lightup.scope.synthetic_patch_bytes.v1"
    }

The actual accepted wire format is strict canonical JSON in sorted-key compact
ASCII form without whitespace, not the indented example above. It admits at
most 16 independent fictional patches, 32 KiB each, 128 KiB total decoded,
192 KiB input, 64 hunks per patch, 8192 bytes per changed line. Base64 must
be canonical and SHA-256 must match. Original bytes must be strictly valid
UTF-8 and contain no U+FFFD, bidi/invisible controls, carriage returns,
terminal control escape, or Unicode line separators. Unified diff hunks must
have complete, ordered line counts and at least one real addition/deletion.
The exact recognized no-newline sentinel is supported; malformed or repeated
markers are refused. Input errors, short stdout writes, duplicate keys,
wrong types, noncanonical JSON or any ambiguous identity -> generic HOLD.

Code never imports or calls Git, LightUp, socket/network or subprocess,
never inspects targets, and never validates real authorization. Valid
synthetic review returns only REVIEW_ONLY with exit **3**. All other inputs
produce HOLD exit **2**. **Zero is never a success status**. Nine flags for
authorization, separate customer/operator consent, scan, grants, dispatch,
merge, deploy and release remain literally false regardless of status.
A malformed input's content is never included in an output receipt.

## Execution evidence and independent controls

Connected permitted zSSH on actual vps-bb300bba, Python 3.14.4:

    python3 -W error::SyntaxWarning -I -S -B -m unittest discover \
      -s tests -p test_scope_1545_patch_bytes_offline_20261017.py -q

Initial own tests: 21 methods, 20 ordinary PASS, 1 expected source-owner RED.
Extra no-change hunk canary initially produced three actual FAIL before own
parser correction: now **22 methods = 21 ordinary PASS and one intentionally
outstanding expectedFailure**. This is not evidence that #1538 is fixed.

Owner-side tests, GitHub-hosted Python 3.11/3.14, the complete original
repository suite, and permanent named registered self-hosted VPS workflow
require separate exact SHA verification. The contained hosted workflow only
runs own offline synthetic tests and selected original source-owner controls
on hosted infrastructure. It does not run or imply successful permanent VPS
CI or actual authorization.

## Owner handoff and release fence

For the **original source owner**: run exact raw-byte Git diff collection,
reject undecodable textual patch evidence before producing hypotheses,
prefer strict decoding without replacement, and ensure synthetic clean,
Unicode, binary/incomplete coverage cases are separately tested. Never
mistake an inferred PASS for a security attestation. A valid original source
repair must turn the outstanding source canary into ordinary GREEN while
preserving existing review and Git-path behavior.

For **release**: independent owner integration review, source correctness,
real separately authenticated client and operator approval, live at-use
revocation, privacy/security review, complete approved-exact-head hosted and
permanently registered VPS CI, plus explicit HUMAN GO remain mandatory.
No merges, deployments, scans, target activity or grants from this lane.

## Owner baseline advanced independently while acceptance remained isolated

The original owner PR #1538 independently advanced from pinned SHA
26dd88d3 to 112868100d21 during this worker iteration and modified source
paths belonging solely to that owner. Read-only inspection of the newer
source still showed lossy UTF-8 patch decoding; nothing was edited or copied
from the owner's new commit. Hosted acceptance deliberately checks out the
**head.sha of this independently owned draft PR**, not GitHub's synthetic PR
merge ref, and verifies four *only-new* paths relative to pinned exact owner
baseline. Therefore a parallel owner branch advance cannot silently insert
other workers' code into this branch's purported exact-head acceptance.
This does not prove the owner branch at any later release head is repaired.

## Hosted exact-HEAD completed evidence and runner runtime upkeep

GitHub own exact-source SHA 3e17f8be3d38f8e9506cb46b569e598005c3332e:
[hosted run #39023764451](https://github.com/Zennay/Lightup/actions/runs/39023764451)
COMPLETED SUCCESS for **both** actual hosted jobs, Python 3.11 job
117370593517 and Python 3.14 job 117370593678. Original raw logs independently
verified exact commit checkout, four-additive-paths assertion, 22 own methods
(21 ordinary PASS and one intentionally unremediated original-source
expectedFailure), plus 26 original change review and 9 GitHub-change unit
cases **per interpreter**. This only proves opt-in hosted checks, not an
owner source repair or named VPS runner. Entire original hosted preflight
and self-hosted permanent runner are separately held gates.

The original logs also warned Node.js 20 is deprecated in checkout@v4 and
setup-python@v5. A subsequent entirely owner-isolated commit upgrades this
standalone workflow to checkout@v5 and setup-python@v6 (Node.js 24-based),
without modifying any other project workflows. The new exact-head hosted
result must be checked separately rather than claiming the former head's
success as proof of this updated workflow.

## W5 — disposable original-source strict repair rehearsal (no owner file changed)

Two additional source-integrated tests run against actual independent synthetic
Git commits without remotes or hooks. In a temporary `unittest.mock.patch`
context only, replacing `_git`'s codec with strict UTF-8 decoding and
rethrowing undecodable text as `GitChangeError` denies an invalid `0xff` patch
before returning any inferred evidence; an ordinary `café naïve` UTF-8
patch retains its full text and passes the synthetic strict reviewer. Both
contexts explicitly assert the installed `_git` callable is restored after
the test. Original `src/lightup/git_changes.py` is unchanged on disk and in
GitHub. A regression in this owner-suggested behavior fails the tests.

Latest isolated Python 3.14.4 zSSH proof: **25 test methods**, **24 ordinary
PASS + one deliberately unresolved original source expectedFailure**. New
hosted evidence belongs only to whichever *final exact SHA* passes in GitHub
Actions; earlier green hosted runs refer to superseded code SHA, not this W5
repair rehearsal. Remains completely DRAFT/HOLD without source-owner merge.

## W7 — ambiguous Unicode patch-content RED-to-GREEN (own CLI only)

The original self-contained fictional patch reviewer accepted additional
visually invisible Unicode as legitimate changed source. Newly introduced
real negative cases initially produced **12 failing subtests**: combining
grapheme joiner, both variation selectors, Braille blank, four Hangul filler
forms, non-breaking space, figure space, narrow no-break space, and combining
acute accent. The original production/source-owner code was NOT edited.

Only the isolated opt-in validator was hardened with exact NFC canonicality,
nonspacing/enclosing mark and atypical separator rejection, and explicit
visually blank Braille/Hangul fillers. Existing positive controls including
fully visible precomposed `café`, Japanese and composed Korean remain reviewable
as fictional REVIEW_ONLY exit 3; all 12 negative subcases now return HOLD
exit 2 with fixed false consent/grant/scan/dispatch/merge/release flags.

Connected permitted zSSH actual Python 3.14.4: **27 test methods executed;
26 ordinary PASS + 1 deliberately unchanged original-source expectedFailure**.
The 12 initial red subtest failures and the green rerun are both evidenced in
the same isolated checkout. No live targets, scanners, network or permissions.
Host-based CI at the updated final commit must be checked independently.

## W8 — canonical Git hunk numeric representation

An independent negative matrix showed the isolated fictional reviewer initially
accepted **six** noncanonical leading-zero hunk offset/count variants, allowing
several textual encodings to claim the same hunk geometry. All six were truly
RED before the fix. The offline validator now accepts exactly decimal `0` or
nonzero numbers beginning with `1`-`9` for every numeric hunk header field;
positive legitimate Git-generated hunk controls remain green. A further
**143 deliberately wrong** old/new count combinations now have regression
coverage to prevent inconsistent patch-body geometry from being silently
promoted to REVIEW_ONLY. The exact original Git source owner and other workers'
paths are untouched; no target I/O or authorization takes place.

At the updated owner-isolated HEAD, VPS Python3.14.4: **29 test methods**,
**28 ordinary PASS + one intentionally unresolved original-source expectedFailure**.
This is still not a release gate. The separate old-base full 1300-unit run
was attempted with an extended 150-second zSSH allowance and completed in
~61 seconds, with exactly **two known legacy registry-history Python3.14
native-I/O tripwire failures (`exit 92`)** that belong to independently owned
[#1535/#1536](https://github.com/Zennay/Lightup/pull/1536); not fixed here.
The current owner-isolated hosted Python 3.11/3.14 and complete preflight
[#39024580175](https://github.com/Zennay/Lightup/actions/runs/39024580175)
and [#39024580177](https://github.com/Zennay/Lightup/actions/runs/39024580177)
were green on the *previous* W7 SHA, not claimed for the new W8 SHA until
that exact commit has its own independent run evidence.

## W9 — real Git EOF marker source/semantic integrity, RED-to-GREEN

The fictional validator accepted **five actual negative Git hunk fixtures**
that falsely placed `\\ No newline at end of file` before further same-side
lines (3 failing subcases) or before a subsequent separate hunk (2 more).
Such a record cannot claim faithfully to describe the last line of the
underlying file. The checker now validates that the immediately preceding
`-`/`+`/context line is actually final on its affected hunk side, and
rejects any later hunk after an EOF marker. No Git configuration, source-owner
module, real file content, or execution capability was touched.

Separate independently committed positive controls use **real temporary
Git repositories without hooks, remote connections or external targets**:
a normal two-distant-hunk patch with complete context and another real
multi-hunk patch whose *last* hunk correctly carries the Git EOF marker are
both still admitted only as non-authorizing REVIEW_ONLY. Valid UTF-8 text and
unambiguous Git geometry were explicitly protected against regressions.

Current connected zSSH Python3.14.4: **33 test methods executed = 32 ordinary
PASS + 1 original-source expectedFailure**. Initial five negative subcases
were truly RED and are now GREEN. These isolated results and the corresponding
GitHub-hosted checks must remain separate from entire original unit and
permanent named VPS runner acceptance; no merge/release authority follows.
