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
