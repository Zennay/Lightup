# LightUp assessment-runtime — integrated lab-to-human-review workflow

**Status: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. No authorization, main merge or deployment.**

This separate composition branch takes the **unchanged source** of the original offline comparator [PR #1515](https://github.com/Zennay/Lightup/pull/1515) (pinned `bb107d32ef8ce89b7f4068ed065f91bc639ecee3`) and existing original private review [PR #1617](https://github.com/Zennay/Lightup/pull/1617) (pinned `5e5005ae5c56892b597262e8239658b316c768c4`) into the existing **held source-composed lab runtime** [PR #1618](https://github.com/Zennay/Lightup/pull/1618) (pinned `846dc48328ceceb0c796b77e334c5782614a0857`). No changes were made to original source-owner branches, executable policy, scanner, grants, QA suites or CI workflows.

## One command surface

From the checkout root, use `python3 scripts/lightup_review.py` to discover five offline activities:

| Action | What it does |
| --- | --- |
| `compare` | Compare original already-completed baseline and candidate benchmark cases; emit a source-confidential private ZIP, Review Desk JSON, HTML, or minimally redacted output. |
| `bundle` | Assemble 1–64 explicitly named completed original case JSON files into one original schema cohort. |
| `inspect` | Read-only structural inspection of one complete private or minimized human review ZIP. |
| `attach` | Bind genuine original local Review Desk saved human planning to the exact underlying source bytes; produce a complete annotated offline ZIP. |
| `handoff` | Minimize an already annotated review to an ordinal-only human follow-up ZIP, without original scenario identities or fingerprints. |

The dispatcher resolves the checkout's `src` automatically, so users **do not need to set PYTHONPATH**. Run from any directory with the full path to this script. A command with `--help` shows supported parameters. The original scripts and their identical source/result semantics are preserved; no new scoring rules or auth claims are introduced.

## From actual existing lab source to human review

The existing `lightup lab-assess` CLI from #1618 supports explicit **owned isolated lab** targets, file-restricted Studio catalogs, `--preview-only`, privacy-controlled owner-only 0600 result outputs, and `--artifact-format benchmark-case` for an actual *completed* lab evaluation. `--preview-only` is a no-execution dry preview and CANNOT produce a benchmark comparison source. Real target-capable work remains held and requires original independent lab scope/consent/execution policy.

For original previously completed private `{"record": {...}, "context": {...}}` files, the human workflow is **network-free**:

```sh
python3 scripts/lightup_review.py compare \
  /private/BASE-completed-case.json /private/NEXT-completed-case.json \
  --format review-pack --output /private/NEW-full-review.zip
python3 scripts/lightup_review.py inspect /private/NEW-full-review.zip
```

For a cohort, either provide two original cohort-array files with `--cohort`, or repeat `--baseline-case FILE` and `--candidate-case FILE` (up to 64 each) directly. An ordinal-only printable standalone HTML, minimized HTML/ZIP or Desk-compatible JSON is available with `--format html`, `redacted-html`, `redacted-pack`, or `desk-json`.

Extract the sensitive ZIP privately and open `index.html`, then `review-desk.html`. Import `review-desk.json` through the existing file picker. Human workstream, due-date and stage changes never change original metrics, execution controls, HOLD, or real authorization.

Continue source-bound human planning:

```sh
python3 scripts/lightup_review.py attach \
  /private/NEW-full-review.zip /private/ORIGINAL-browser-review-v2.json \
  --output /private/NEW-annotated-review.zip
python3 scripts/lightup_review.py inspect /private/NEW-annotated-review.zip
python3 scripts/lightup_review.py handoff /private/NEW-annotated-review.zip \
  --output /private/NEW-minimal-recipient.zip
```

The saved original browser review can only be attached when it matches the **exact** original source bytes and case metrics. The full annotated archive contains the original app plus source-bound human stages and a local follow-up screen. The minimized recipient packet intentionally excludes the source comparison file, original scenario IDs and raw source fingerprints; numeric aggregates or dates may still be sensitive.

**Privacy:** all source-rich exports and full ZIPs are private; they can contain identifying case information. SHA-256 is an *unsigned* integrity aid and cannot establish provenance, consent, ownership or trust. Output is always an exclusive new file with private 0600 permissions and complete fsync-before-publish behavior. Original product diagnostics deliberately return code 2 REVIEW_ONLY or 3 HOLD, never successful release code 0.

## Mandatory release dependencies

This product is **DRAFT/HOLD**. Do not merge to `main`, deploy or initiate new scans/target work until the original full exact-head hosted CI and permanent named VPS CI pass, source owners accept composition, independent privacy/security review signs off, separately authenticated client and operator approvals include actual action-time revocation where needed, and explicit HUMAN GO is recorded. The [current original scope integration #1619](https://github.com/Zennay/Lightup/pull/1619) has an unrelated existing hosted CI blocker; this composition does not omit, rerun or bypass CI. No QA, regression or testsuite code was written/executed while preparing this branch; only bytecode compilation and CLI help/source inspection.
