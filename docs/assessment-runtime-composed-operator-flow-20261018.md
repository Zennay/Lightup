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

## Original offline Lab Scenario Studio actually included

The composition now includes the **exact unmodified original** [Lab Scenario Studio PR #1595](https://github.com/Zennay/Lightup/pull/1595) pinned `52d54318075b1c8e93c559a9b2d365987c669ca3`, under its entire original `lab-design/` directory: source HTML/CSS/JS, CSP-pinned `standalone.html`, original fixture profile pack, native bridge, fixture catalog exporter, and original author guide. The existing composed `lightup lab-assess --catalog-file --scenario-id --target ... --preview-only` is the *separate* original #1618 CLI, not called by this browser.

The new **`assessment-workspace/standalone.html`** is a responsive static launch screen with local links to the original Studio and the original pinned human Review Desk, instructions for reviewing already-completed source records and privacy/authority reminders. It has a strict no-network/no-script CSP. You can open it directly from the checkout, or request its `file://` location without a web server:

    python3 scripts/lightup_review.py workspace

The dispatcher adds this **read-only `workspace`** action alongside `compare`, `bundle`, `inspect`, `attach` and `handoff`. It does not start a service or enumerate assets. Original native Studio catalog exports and fixture source declaration reading remain deliberately **design-only**. They do not create trusted benchmark results, run a fixture, grant consent or prove private-address ownership. The original source owner branches remain unchanged; the extra static entry page is a new integration-only file.

## Original Studio-to-benchmark Lineage Desk now in this checkout

Included **unchanged** original [scenario-to-comparison Lineage Desk PR #1597](https://github.com/Zennay/Lightup/pull/1597), pinned exact source `8dff91cb1f830eb6473b8755bbd187051ea9b072`, under its seven owned `assessment-lineage/` source files. It is a separate offline human app that reconciles 1–32 original PRIVATE Studio scenario memberships and 1–8 **already-completed** source-bound cohort comparisons. A case missing from either catalog or report remains HOLD and is not treated as repaired; unsigned original ground truth is a draft, not detection proof.

Open **`assessment-workspace/standalone.html`** and select **Original Scenario Lineage Desk**; manually import the original `lab-design/standalone.html` exported catalog and 1–8 comparator results. To produce one original private cohort result in this very same checkout:

```sh
python3 scripts/lightup_review.py compare /private/BASE-cohort.json /private/NEXT-cohort.json \
  --cohort --format desk-json --output /private/NEW-private-comparison.json
```

The Lineage Desk uses the original comparator `scenario_id` values **privately for in-memory reconciliation** and never exports them in anonymous aggregate handoff. Its optional owner-private `assessment-lineage/private_workroom.py` can combine explicit existing private catalog + comparison JSON files into one private local HTML; it never calls the lab runner. This is an **existing original app directly combined into the same source checkout**, not an invented evaluation or new trust/release gate. The separate original [#1597](https://github.com/Zennay/Lightup/pull/1597) and [#1595](https://github.com/Zennay/Lightup/pull/1595) owners remain unmodified.

## Original candidate matrix for multiple completed lab comparisons

The composition now includes unchanged [original offline Candidate Matrix #1592](https://github.com/Zennay/Lightup/pull/1592), pinned source commit `393af8a9c7c8a6ff827ce0092ffa2436f5aab061` and its complete six-file `assessment-candidates/` product. Open `assessment-workspace/standalone.html` then **Candidate Matrix**, or open the original `assessment-candidates/standalone.html` directly. Import **2–12 previously completed** compatible canonical cohort comparison JSON files generated from the installed original #1515 comparator. The original app checks baseline and scenario membership consistency, shows the original reported 15-metric tradeoffs and anonymous human casework priorities. It never executes a candidate, chooses a safe model, changes source observations or grants release permission. The original candidate owner and its branch remain untouched.

Use the same central offline entry point for preparing the source files:

```sh
python3 scripts/lightup_review.py compare /private/BASE.json /private/CANDIDATE-A.json \
  --cohort --format desk-json --output /private/NEW-candidate-A-review.json
python3 scripts/lightup_review.py compare /private/BASE.json /private/CANDIDATE-B.json \
  --cohort --format desk-json --output /private/NEW-candidate-B-review.json
```

These are **local** source-comparison operations only, producing original unsigned REVIEW_ONLY/HOLD JSON. The Matrix UI imports the files explicitly and does not contact any target or provider. Its visual filters and human planning stages can never substitute for source-owner, security/privacy, consent or CI acceptance.
