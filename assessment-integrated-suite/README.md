# LightUp integrated PRIVATE assessment handoff

**Incubate M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD**. This is an integrated **source-only release candidate**, not an authorization, active scanner, security finding certification or production deploy.

## What is really integrated

This branch carries the original held lab inspector/CLI from #1610, original PRIVATE briefing from #1672, select-only evidence dossiers from #1679, HUMAN retention desk from #1683 and source-minimal disclosure reviewer from #1685. Each original contributor branch remains unchanged. The new suite under this directory **uses** the original native lab inspector and briefing/disclosure producers; it does not duplicate their validators or collect evidence.

The operator can take **already-produced** original PRIVATE lab JSON, generate both original-source-admitted PRIVATE disclosure review and optional detailed finding-level PRIVATE briefing with **one command**, and receive an offline entry page linking the original generated artifacts plus **five actual existing offline HUMAN browser workrooms**. This joins previously isolated product capabilities without scanning.

## Run completely locally in a trusted checkout

Prepare a separate, empty or existing **owner-owned mode 0700** parent folder *outside the repository*. Never use a repository or a public web root for customer data.

~~~sh
install -d -m 700 /path/to/PRIVATE-only-parent
python3 assessment-integrated-suite/suite.py catalog

# PRIVATE disclosure for one or more already-produced original lab artifacts
python3 assessment-integrated-suite/suite.py prepare \
  --source /private/original-lab-a.json \
  --source /private/original-lab-b.json \
  --private-parent /path/to/PRIVATE-only-parent

# Also include the original detailed PRIVATE findings briefing and its worksheet
python3 assessment-integrated-suite/suite.py prepare \
  --source /private/original-lab-a.json \
  --private-parent /path/to/PRIVATE-only-parent \
  --brief
~~~

**Return code 2 means REVIEW_ONLY product was prepared**, not an error requiring retry and not a PASS signal. **Return code 3 means HOLD** and normal failed preparations remove their own newly created private output tree. Sources must each be non-symlink local files of 1–8 MiB; at most 12 unique source files. Optional `--brief` applies only to the first source and requires original briefing's strict source contract. Do not send live targets or arbitrary URLs to the launcher.

On success, the CLI prints a unique local `PRIVATE-lightup-kit-*/OPEN-PRIVATE.html` path. Open that file locally in a trusted offline browser; do not serve through HTTP. The CSP-protected scriptless entry page links:
- Original **PRIVATE** detailed findings briefing, original HUMAN worksheet and unsigned manifest (when `--brief` selected).
- Original **PRIVATE** disclosure review, source-minimized unsigned receipt and small-cohort-suppressed PRIVATE counts.
- The previously committed, completely offline **HUMAN disclosure, retention and worksheet** studios (worksheet with `--brief`). They remain independent source-bound HUMAN-only UIs.

For select-only dossiers, use the physically integrated original `assessment-evidence-curation/console.py` after the original detailed briefing and worksheet are available. This new suite intentionally does not duplicate or reinterpret original source-declaration matching, HUMAN admission, AES-GCM decryption, or original result classification.

## Privacy / integrity behavior

- Runs only the two **fixed, original local file-only producers** with argument-vector subprocesses; no shell, host resolution or arbitrary script target.
- Uses the original `lightup.lab_inspect.inspect_artifact()` as required by disclosure. Missing/invalid original inspector is HOLD; there is no fallback decoder.
- Insists on an existing owner-controlled no-group/no-other directory **outside the repository**; creates unique mode 0700 private output and mode 0600 copied workrooms/entry page.
- Source bytes are **not copied** into the package; the detailed briefing deliberately includes original PRIVATE finding details, and resulting HTML/receipts/counted cohorts should all be treated as PRIVATE.
- An incomplete normal preparation removes only its newly created package. Unexpected process termination can leave a PRIVATE incomplete 0700 directory, which must be reviewed and securely handled by its custodian. The package does **not** delete or modify original source.
- No browser is opened automatically, no external handoff/publish is performed, no model or tool execution, scanning, grant creation, assessment request, retest or deletions.

## Release and authority gates

No merge to `main`, runtime deployment or real target activity. Original exact-head GitHub-hosted and **permanently registered named VPS CI**, source-owner approval, independent security/privacy/browser review, #177/#182/#829 remediation, separate **current authenticated client and operator consent**, action-time revocation, and explicit **HUMAN GO** remain prerequisites. This integration branch is DRAFT/HOLD even if it has no source conflicts. Original PR branches may continue advancing; this candidate refers to the frozen source heads recorded in its merge commits, not their future work. No QA/regression suites were written or executed for this integration.

## Continue directly into ORIGINAL select-only HUMAN evidence curation

Once `suite.py prepare --brief` produced a private kit, you can prepare the original
#1679 select-only HUMAN source-ordinal editor directly without assembling the
source, manifest and worksheet arguments manually:

~~~sh
python3 assessment-integrated-suite/curation.py \
  --source /private/original-lab-a.json \
  --original-kit /path/to/PRIVATE-only-parent/PRIVATE-lightup-kit-EXAMPLE \
  --private-parent /path/to/PRIVATE-only-parent
~~~

This foreground action invokes the **unchanged original**
`assessment-evidence-curation/curate.py prepare` to check the source, exact
original native manifest and worksheet. It produces an exclusive 0700 PRIVATE
folder with an offline entry page linking the original source-free selection
studio, complete HUMAN selection CSV, unsigned selection receipt and instructions.
It refuses a different source or unmatched original manifest/worksheet. No
findings are selected, published or disclosed automatically. Exit code 2 is
REVIEW_ONLY, 3 is HOLD, never authority to scan or release.

## Complete optional ORIGINAL selected-only evidence dossier (third stage)

After a human has privately edited and saved the original source-free selection
CSV from the HUMAN studio prepared by `curation.py`, it can be admitted by the
**unchanged original** `assessment-evidence-curation/curate.py publish` through
one explicit local command:

~~~sh
python3 assessment-integrated-suite/publish.py \
  --source /private/original-lab-a.json \
  --original-kit /private-parent/PRIVATE-lightup-kit-EXAMPLE \
  --curation-kit /private-parent/PRIVATE-lightup-curation-EXAMPLE \
  --selection /private/PRIVATE-human-selection.csv \
  --private-parent /private-parent
~~~

This third stage revalidates the exact original source, briefing manifest,
HUMAN worksheet, original selection receipt and full completed HUMAN selection
through original source code. It prepares a NEW owner-private 0700 local kit
containing **only the selected** original finding dossier, a **separate**
identifier-minimized PRIVATE HUMAN handoff, the original unsigned curation
receipt and source-free numeric counts. Present priority-group pages are linked
when the native source emits them. The original source/worksheet and browser
studio are never modified; no network publication is performed. Even the
minimal handoff is PRIVATE and may be disclosed only after independent real
owner/client/operator permission and privacy checks. Exit 2 = REVIEW_ONLY,
not approval. Exit 3 = HOLD and removes only the failed new kit.

## Original lab HUMAN review and follow-up scheduling available together

Two more independently held original product snapshots are physically integrated: PR #1639 original full offline lab review desk, and PR #1675 original PRIVATE source-bound follow-up calendar. Both self-contained browser apps are now linked and copied by `suite.py prepare` into the same owner-only PRIVATE kit; the apps are unchanged, no finding/target is auto-loaded or persisted, and no actual scheduled external task or customer instruction is created by the launcher. The offline calendar displays HUMAN-only proposals, not true consent, verified finding status or an authorization. Their original PR branches were never changed; release remains DRAFT/HOLD.

## Optional PRIVATE original-source A/B drift package (fourth native flow)

Compare two separately already-produced original lab JSON artifacts with the
**unchanged original** strict `assessment-briefing/compare.py` without invoking
any scanner, execution, evidence collection, browser fetch or model:

~~~sh
python3 assessment-integrated-suite/drift.py \
  --before /private/original-lab-a.json \
  --after /private/original-lab-b.json \
  --private-parent /path/to/PRIVATE-only-parent
~~~

The original native comparator requires two genuinely distinct source-byte
hashes/run IDs, the same declared scenario and matching source target set. If
those source prerequisites fail, the whole attempted new 0700 kit is removed
under ordinary failure conditions and the CLI returns HOLD (3). If admitted it
returns REVIEW_ONLY (2), produces the original scriptless PRIVATE exact-declared
A/B comparison, HUMAN follow-up CSV and unsigned source manifests with a local
CSP-restricted PRIVATE index. A removed finding is a declaration, **not** proof
that it was repaired, retested, or even correctly observed. Never distribute
source findings outside independently approved PRIVATE scope.

## Expanded native integration: complete offline learning, planning and HUMAN decisions

Five more original, separately held PRIVATE/isolated-lab source snapshots are physically
integrated without modifying their original owner branches. The suite's owner-private
offline kit now includes **ten self-contained original browser workrooms**:

- Original PRIVATE finding review, HUMAN worksheet, disclosure, retention and calendar;
- Original #1634 **lab launchpad** to prepare source-local isolated-lab endpoint plans
  without initiating any assessment or contacting targets;
- Original #1595 **scenario studio** to author hypothetical bounded lab scenarios;
- Original #1597 **benchmark lineage** to review source-declared scenario membership
  against existing completed benchmark reports without running evaluation;
- Original #1592 **candidate matrix** for HUMAN-only comparison of existing
  separately produced canonical lab comparison files;
- Original #1669 **multi-reviewer consensus**, including local PRIVATE encrypted
  reviewer workspace, explicit conflict handling and refusal to infer permission.

Each original one-file app is copied unchanged into the new owner-controlled kit,
with no external resource loading and no automatic source import. The package links
to every app from the same private scriptless landing page. All original rules for
source admission, original plan identity, HUMAN status and cryptographic data remain
the responsibility of the original owner module, not the suite wrapper. A launcher
link is not permission, verification, a PASS finding, or a production approval.

## NEW: one foreground PRIVATE operator console (no command assembly)

Run the new five-screen workflow navigator from a trusted interactive terminal:

~~~sh
python3 assessment-integrated-suite/console.py
~~~

The operator can prepare the original PRIVATE disclosure/briefing with ten original
offline browser workrooms; continue into original exact-source HUMAN finding
selection; complete the selected-only PRIVATE dossier after manually saving the
selection; review an independent original A/B lab source drift; or display the
private package locations produced **during this session only**.

All native processing uses only the four source-integrated standalone original
wrappers with subprocess argument vectors and no shell. No assessment execution,
grants, API, internet, browser auto-open, queuing, retained session history or
scheduled operations. Inputs and potentially sensitive paths are not logged to
Notion/GitHub. Full source details never appear in the console's error output.
Original source admission and owner-only PRIVATE parent checks remain mandatory.

The console never chooses HUMAN answers automatically; it refuses selection
publication until a human separately supplies the original completed selection
CSV and unmodified original source, briefing, and selection-kit files. A menu
success means only locally prepared REVIEW_ONLY private files. This is *not*
current customer consent, review signoff, or permission to deploy.

## Original PRIVATE multi-artifact archive, fully integrated without runtime-source conflict

The original source owner [#1625](https://github.com/Zennay/Lightup/pull/1625)
has a 14-file independent `assessment-archive/` and its exact immutable source
was added verbatim at SHA `880d59e0a996005dce174516358ca04a48d4633d`.
An attempt to merge its *entire* branch had overlapping original
`src/lightup/labrun.py` and lab CLI documentation; that merge was cleanly
aborted, and no already-owned runtime source changed.

The independent original code is now exposed by a new operator command:

~~~sh
python3 assessment-integrated-suite/archive_room.py \
  --source /private/original-a.json --source /private/original-b.json \
  --private-parent /private/owner-only-0700
~~~

Calls original `assessment-archive/archive.py capture`, then original `view`
PRIVATE and aggregate-only, then `share` PRIVATE aggregate counts. All input
files must be explicit original already-produced regular files (2–64); no
directory enumeration, implicit source scans or model invocation. The output
is a unique 0700 kit containing original byte-bound unsigned manifest, source
type summary, original PRIVATE exact-fingerprint HTML, and separate source-
minimized PRIVATE count HTML/JSON, plus offline scriptless entry page. Even
hash-free aggregates can reveal confidential cohorts: no automatic sharing.

## Original multi-agenda HUMAN collaboration portfolio

Original [#1630](https://github.com/Zennay/Lightup/pull/1630) complete independent
55-file `assessment-portfolio/` workroom was added verbatim at original
SHA `dea6c90cb7b42cdb718fa440efd04a09c5b5be37`, together with the
unchanged original archive dependency. Its entire parent branch also conflicts
with original held runtime source; no conflict-prone source code was merged.

~~~sh
python3 assessment-integrated-suite/portfolio_room.py \
  --agenda /private/original-human-agenda-a.json \
  --agenda /private/original-human-agenda-b.json \
  --as-of 2026-10-20 \
  --private-parent /private/owner-only-0700
~~~

Uses unchanged original `assessment-portfolio/portfolio.py`: validates 1–12
complete original PRIVATE HUMAN agenda JSON records against **the same declared
reference date**, then generates an original private ZIP containing the
existing HUMAN workload and capacity browser workrooms, plus separate strictly
aggregate HUMAN HTML and JSON views. Human capacity, stage and date are
**planning proposals**: no email, calendar automation, job dispatch,
authorization, customer notification or SLA certification. No raw original
agenda bytes are copied into the kit. A private counts-only output is *not*
a publishable public resource without current authentic owner/privacy approval.

The foreground `console.py` also offers these as options 6 and 7, shares only
in-process ephemeral paths, and still performs no scheduled/remote action.

All source-owner CI, scope/consent, independent review and explicit HUMAN GO
requirements remain mandatory; no main merge or production deployment.
