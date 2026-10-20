# LightUp integrated PRIVATE assessment handoff

**Incubate M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD**. This is an integrated **source-only release candidate**, not an authorization, active scanner, security finding certification or production deploy.

## What is really integrated

This branch carries the original held lab inspector/CLI from #1610, original PRIVATE briefing from #1672, select-only evidence dossiers from #1679, HUMAN retention desk from #1683 and source-minimal disclosure reviewer from #1685. Each original contributor branch remains unchanged. The new suite under this directory **uses** the original native lab inspector and briefing/disclosure producers; it does not duplicate their validators or collect evidence.

The operator can take **already-produced** original PRIVATE lab JSON, generate both original-source-admitted PRIVATE disclosure review and optional detailed finding-level PRIVATE briefing with **one command**, and receive an offline entry page linking the original generated artifacts plus **five actual existing offline HUMAN browser workrooms**. This joins previously isolated product capabilities without scanning.

## NEW: Owner-private assessment route board (native console option 40)

Run `python3 assessment-integrated-suite/console.py` in a trusted **interactive
foreground** terminal. After manually producing original offline workrooms,
choose **40**. Supply an EXISTING owner-only 0700 output parent outside the
checkout, an unused simple folder name, and explicitly type
`BUILD PRIVATE BOARD`. This writes only a new exclusive owner-private 0700
folder with `OPEN-PRIVATE.html` and `PRIVATE-ROUTE-SUMMARY.json`, both 0600.

Alternatively, **option 41** asks for an existing original 0600
`PRIVATE-SESSION.json` in a 0700 owner-only folder outside the checkout,
the output parent and a new folder. After the exact
`BOARD SAVED SESSION` confirmation, the pre-existing strict duplicate-key,
full original session-schema and all-literal-false authority reader admits
only the saved PATH-ONLY references. A separate in-memory session copy is
then used for the board: **the current live interactive session and previous
checkpoint are never overwritten**. The original source artifacts remain
unopened and every old file: bookmark is only a current local availability
observation, not saved trusted state.

The static, scriptless file: dashboard groups original workrooms by intake,
benchmarks, select-only evidence, human remediation and retention. Each row
shows **LOCAL PAGE PRESENT / REVIEW ONLY**, **NOT PREPARED**, or
**HOLD: PREVIOUS PATH UNAVAILABLE**, followed by a concrete manual next
action. It links only directly to already existing, owner-owned 0600 original
PRIVATE offline entry pages; never loads sources, passwords or notes, and
never runs a stage. The JSON is minimal: field names, status and all-false
authority flags, without paths, original evidence or client content. The
**HTML contains PRIVATE local file paths** in links and must remain on the
same trusted owner device. Deleting or moving a source after board creation
makes bookmarks stale; open the original workflow and re-admit original
bytes/authorization afresh. Presence of a page is **not** correctness,
readiness, approval or proof of identity. Existing review/CI/consent HOLD
still applies; never send or publish this board.

## NEW: original source-bound offline HUMAN browser editor

The existing native options **42 and 43** now produce a **fully interactive
owner-only 0600 `OPEN-PRIVATE.html`** alongside the original scriptless
`PRIVATE-READONLY.html`, strict owner-only CSV and JSON. This browser UI
uses one embedded SHA-256 CSP-pinned copy of the original committed
`human_queue_editor.js`; the **only** initial data is the native-generated
original exact-session-bound HUMAN queue. No hosted HTML, JavaScript, API,
external asset, cookies, localStorage, IndexedDB, service worker, fetch,
network request, scan, grant, release or upload is used.

Use the offline UI to search/filter the original workflow rows; deliberately
choose HUMAN stage/team and local follow-up date; edit a short private HUMAN
question; and download a **complete** exact-session-bound six-column CSV,
even when filters hide other rows. The editor also supports **up to 25
in-memory undo/redo snapshots** and confirmation-gated **bulk HOLD or
NEEDS_INPUT for only currently visible filtered rows**. A filtered bulk action
cannot assign a team, verify a finding, mark PASS or change hidden records.
When a saved CSV is imported, its original session binding and exact workflow
order are checked before replacing the draft; pre-existing edits can be
discarded only after a separate HUMAN confirmation. The CSV parser admits
canonical LF or CRLF while rejecting isolated CR and malformed quote syntax.

Export means only **download requested**; browsers can cancel downloads.
The editor therefore still shows unsaved HUMAN edits until the operator
manually confirms that the downloaded file truly exists in owner-only
0700 custody with 0600 file permissions. That local acknowledgement does
not prove the original source, HUMAN identity or permission. Any subsequent
HUMAN edit invalidates the old export acknowledgement; a fresh export and
native option 43 re-admission are required. All selections remain in browser memory
until deliberately downloaded. An existing original HUMAN CSV may be
reimported via a manual local file picker; strict quoted-CSV, exact workflow
order/session digest, stage/team/date/question rules are checked before
replacing current browser edits. Invalid input **does not partially change**
the open draft. The original native Python option 43 remains the independent
authoritative owner-only CSV parser and admission gate.

**Important:** browser downloads may receive operating-system default
permissions (for example 0644) and do not automatically go into owner-only
private custody. Before passing one to native option 43, move it into an
existing owner-only 0700 directory outside the repository and set its file
mode to 0600. The browser cannot establish permission on downloaded files,
or authenticate actual human identities, original sources or recipients.
The HTML file itself contains confidential `file:` links and any locally
restored HUMAN question text; keep the full original 0700 kit private.
The scriptless fallback remains available when running without JavaScript.

## NEW: owner-private manual assessment HUMAN work queue (options 42 and 43)

The native foreground console now generates a complete **manual** queue for
all original review-stage workrooms without touching any original sources.
Option **42** writes an exclusive 0700 folder under an existing owner-only
parent outside the repository. The 0600 `OPEN-PRIVATE.html` groups workflows
by original phase, shows local page availability and specific HUMAN next
actions. The 0600 `PRIVATE-HUMAN-QUEUE.csv` provides an editable five-field
workflow row: exact source-PATH snapshot digest, fixed workflow key, HUMAN
stage, HUMAN team, follow-up date and optional short question. Its 0600
`PRIVATE-HUMAN-QUEUE.json` is a source-free machine-readable status list.

HUMAN stages are **UNASSESSED**, **HOLD**, **NEEDS_INPUT**,
**HUMAN_REVIEW** and **HUMAN_FOLLOWUP** — none are permission, PASS or
completed security evidence. Optional team is Security, Privacy, Client
operations or Platform, follow-up date is real ISO YYYY-MM-DD and question is
240 characters maximum. HUMAN questions must not begin with CSV spreadsheet
formula prefixes, and no original source data, passwords, assessor identities
or real consent should be entered. Keep this CSV 0600 in an owner-only 0700
directory, never email/share it.

Choosing an output folder for either option **42** or **43** does not
mutate the currently held console path references: this preserves the
original PATH-only digest when operators store revisions under a different
owner-only directory.

Option **43** admits a manually edited ORIGINAL queue CSV only against the
**same unchanged console PATH reference snapshot** (SHA-256 is an unsigned
local equality marker, NOT proof of source-byte identity or authentication).
It rejects reordered/deleted/duplicate keys, digest drift, unknown stages,
unknown teams, invalid dates, formula-like questions, size and privacy mode
violations *before* allocating a replacement; success creates a NEW PRIVATE
folder, leaving the old CSV and session unchanged. Existing original source
admission, authenticated consent/revocation-at-use, independent review and
HUMAN GO gates are never bypassed. No schedule is actually booked and no
contact, scan, retest or notification is sent.

## NEW: strictly recipient-team-filtered HUMAN task deck (option 44)

After a HUMAN manually completes and saves an owner-only 0600
`PRIVATE-HUMAN-QUEUE.csv`, console **option 44** selects exactly ONE of
Security, Privacy, Client operations or Platform. The original queue reader
revalidates the complete fixed workflow key order and exact unchanged
PATH-session snapshot before making a new owner-only 0700 folder with
`OPEN-PRIVATE.html`, `PRIVATE-TEAM-TASKS.csv`, and
`PRIVATE-TEAM-RECEIPT.json`, all 0600. These show **only tasks assigned
to that team**; other teams' questions, actual original file paths, snapshot
path hashes, and original lab/recipient bytes are not reproduced. There is
no auto-send. Only after a separate genuine authenticated recipient/channel
and privacy review may a HUMAN decide how to handle this still-PRIVATE file.
A team dropdown cannot establish identity or consent. No PASS or grant.

## NEW: PRIVATE HUMAN work-queue revision timeline (option 45)

Option **45** reads **2–8 distinct existing owner-only 0600 HUMAN queue
CSV revisions**, all re-admitted against the **same unchanged current
PATH-ONLY console snapshot** and exact fixed workflow order. The user
declares the order; no timestamp, authority, review completion, actual source
change or validated fix is inferred. An exclusive 0700 folder contains a
scriptless 0600 historical HTML, private machine-readable JSON and minimal
CSV. The report shows per-workflow HUMAN status/team/deadline changes and
whether question presence/text changed; it intentionally **omits all
confidential HUMAN question text**, original source bytes, saved machine paths
and snapshot path digest. Unmodified original input CSVs remain untouched.
This is HUMAN planning continuity only, not a security or privacy approval.

## NEW: direct original native CLI for a full HUMAN workpack

The existing source-owned `assessment-integrated-suite/suite.py` now also
supports **`human-workpack`** as a foreground native subcommand, rather
than requiring an interactive console menu for local operators. It requires
the original strict owner-only 0600 saved `PRIVATE-SESSION.json`, an
existing owner-only 0700 output parent outside the checkout, a unique
unused workpack folder, an explicit operator-declared review date and
**exact** `--human-confirm 'BUILD PRIVATE WORKPACK'`. The prior
`--human-csv` is optional and, when supplied, remains subject to the
full original strict source-PATH-bound CSV admission; without it all
workflow rows begin unassessed and unassigned. No current console session
is mutated. Existing `suite.py prepare` and `suite.py catalog` remain
unchanged in execution behavior.

~~~sh
python3 assessment-integrated-suite/suite.py human-workpack \
  --private-session /existing-owner-only/PRIVATE-SESSION.json \
  --private-parent /existing-owner-only/output-parent \
  --folder private-initial-human-workpack \
  --review-date 2026-10-20 \
  --human-confirm 'BUILD PRIVATE WORKPACK'
~~~

This is an **illustrative command**, not an actual created workpack or a
request to use any real client source. The native command returns status
`2` only when the PRIVATE local REVIEW_ONLY output has been prepared,
`3` for HOLD; neither code means PASS. No offline workpack is sent or
scheduled, no network/model/target operation is executed and current
authenticated client/operator consent and explicit HUMAN GO remain absent.
If a strict saved session or private folder is unavailable, the command
fails closed. Do not run it as an unattended scheduler.

## NEW: live offline HUMAN attention and team-capacity dashboard

The original locally generated interactive HUMAN Queue Studio now includes
a **live, in-memory HUMAN attention board** alongside editable work items.
The user manually selects an optional review date: there is NO implicit
browser-clock read or real appointment. As the user edits a HUMAN row,
the browser immediately recalculates counts for HOLD/needs-input, original
referenced workroom unavailable, before selected date, selected day, next
seven declared days, missing HUMAN team and remaining items. It also
counts manually staged work per team. The new **HUMAN attention filter**
can be combined with existing text/stage/team filters; CSV export always
includes every original workflow in its exact order regardless of filters.

The same locally declared statuses feed the browser preview; it remains
unverified HUMAN coordination and **cannot** turn a local file bookmark
into source authenticity, a validated severity, scheduled task, actual
HUMAN identity, approved scope, consent, grant or scan. The native static
priority desk (option 47) is still a separate owner-private snapshot made
only after native strict CSV admission. Browser preview does NOT modify that
snapshot, revalidate original client files or schedule anything.

## NEW: review imported CSV changes and route multiple HUMAN tasks

The original interactive HUMAN browser Studio now presents a **per-field
change preview** before replacing an existing HUMAN draft with another
exact-session-bound CSV. The prompt lists changed workflow titles (at most
eight), counts changed stage/team/due-date fields, and only **counts**
changed PRIVATE question fields (never question text). A rejected preview
changes no local HUMAN decision or original on-disk file, and an overlapping
local edit or newer import invalidates any earlier pending import.

A second bulk option assigns one explicitly selected team (Security,
Privacy, Client operations or Platform) to **only visible, already-staged**
HUMAN queue rows. Visible `UNASSESSED` and all hidden workflows remain
unchanged. The assignment requires an additional HUMAN confirmation,
can be undone locally and never creates an authenticated HUMAN identity,
recipient notification, real responsibility transfer or assessment grant.
Both actions preserve exact original CSV row order and source-PATH binding;
native owner-only admission is still required on the resulting download.

## NEW: restart HUMAN Queue Studio from an ORIGINAL saved session (46)

Native foreground menu **46** admits an ORIGINAL owner-only 0600
`PRIVATE-SESSION.json` using the **unchanged strict** source-native session
reader. A separate in-memory copy restores all PATH-only fields and binds
`saved_session` to the original saved checkpoint, as the existing console
option 38 would, **without replacing a single field in the current live
console**. Choose optionally an earlier exact-checkpoint owner-only 0600
HUMAN queue CSV: all original workflow keys, full fixed column schema,
original PATH digest, HUMAN dates, stages, teams and question constraints
are re-admitted before a **new** exclusive 0700 output kit is created.
The output is the complete interactive CSP-pinned `OPEN-PRIVATE.html`, the
scriptless fallback, the original verified CSV revision and minimal JSON.

For reliable continuity, use menu **37 to save** the original private
session, then menu **42 to create** the HUMAN queue from that session
before closing the console; menu 46 can independently recreate its original
PATH context after restart. If you deliberately changed any referenced
session field after saving and before generating the old CSV, its digest
must fail closed: save a fresh checkpoint, manually reopen original files
through native admission, and prepare a new queue. Old CSV/source paths are
never silently relinked to an unrelated session. No source file or target
is read, scanned, sent or authorized by this operation.

## NEW: offline HUMAN attention / declared-date workload desk (47)

From one original owner-private 0600 HUMAN queue CSV and the **unchanged
current session PATH digest**, native menu **47** constructs an exclusive
0700 source-free PRIVATE HUMAN priority dashboard. The operator supplies
an explicit review date (canonical YYYY-MM-DD); this is **not** a live
calendar query or proof of timing. Every original fixed workflow row is
placed into exactly one category: HUMAN HOLD/NEEDS INPUT, original offline
workroom absent, past declared follow-up date, same declared date, next
seven declared days, unassigned HUMAN team, or other.
The report also totals HUMAN stage assignments by team.

Outputs are owner-only 0600 `OPEN-PRIVATE.html`, minimal
`PRIVATE-PRIORITIES.csv`, and `PRIVATE-PRIORITIES.json`. They deliberately
exclude HUMAN question text, all original local source filenames/paths and
source-PATH digest values; the statuses and human-assigned dates still
constitute PRIVATE planning metadata. Source/PATH/owner-only CSV admission
is performed by the original unmodified strict reader before output.
No calendar appointment, reviewer identity, source integrity, scope
approval, security verdict, notification, scan, grant, target, retest,
deletion or external distribution is created.

## Native PRIVATE HUMAN source integrity and missing-original handling

The original strict local CSV reader now rechecks the **opened descriptor**
against the original owner-only 0600 `lstat`: device/inode, owner UID,
regular-file mode, single link, size and after-read metadata must still
match before accepting HUMAN rows. If the original CSV was swapped,
re-permissioned or otherwise modified in the original open/read window,
the complete native import fails closed and no HUMAN workpack is published.
This does not prove external client source identity, but prevents silently
admitting a different or newly exposed local HUMAN CSV.

The native HUMAN priorities now surface a previously referenced original
PRIVATE workroom whose page is unavailable as missing **even before**
any manual HUMAN status was assigned. An entirely never-prepared workroom
is still distinguished from a previously referenced missing workroom.
Human-declared HOLD/NEEDS INPUT remains the highest triage category.

## NEW: integrated PRIVATE HUMAN Assessment Workpack (option 48)

The **original native console option 48** combines previously separated
source-bound PRIVATE HUMAN products into **one actually usable offline local
workpack**, instead of requiring separate manual console sessions.
For a NEW HUMAN workpack leave the original CSV prompt **blank**:
the native current session seeds every original workflow as `UNASSESSED`,
with no team, due date, question, grant or security approval. No separate
console option 42 is needed. Alternatively, supply an existing original
0600 HUMAN CSV, which still requires the strict original schema, row order
and exact current session-PATH digest. Both deliberately confirmed routes
produce one **new** 0700 folder outside the checkout with a 0600 scriptless
`OPEN-PRIVATE.html` index linking only to its own child views:

* `queue/OPEN-PRIVATE.html`: original interactive HUMAN Studio for all
  workflow keys, with complete CSV export and native source-bound reimport;
  `queue/PRIVATE-READONLY.html` remains scriptless.
* `priorities/OPEN-PRIVATE.html`: original source-free HUMAN attention and
  team workload report for the explicitly declared local review date.
* `team-security`, `team-privacy`, `team-client-operations`,
  `team-platform`: **only for teams with actual manually assigned tasks**,
  each using the original native minimum-necessary private team desk.
* Original source-free `PRIVATE-WORKPACK-RECEIPT.json`: numbers, team labels
  and view names only. No original client source, local machine source
  paths, HUMAN question text or unsigned session path digest.

Original `route_queue`, `human_priorities` and `route_team` builders are
reused directly; the workpack does **not** replace any source owner logic,
skip the existing HUMAN CSV admission, weaken owner-only 0700/0600 modes,
authenticate a real HUMAN identity or execute a target. All views of one
complete workpack now use the **same owner-private pinned 0600
`PINNED-HUMAN-QUEUE.csv`** written into its new 0700 folder: the initial
original CSV is checked under the strict native owner-only file gate,
re-read and compared to the pinned strict-admitted view before publication.
Any mismatch aborts the entire NEW workpack; all original CSV files remain
unchanged. The pinned file contains confidential **HUMAN question text and
planning selections**, not original client source artifacts. Treat the
entire workpack as PRIVATE; never distribute the pinned file. This prevents
the team worklists and overview from silently reflecting different CSV
versions when an operator edits the original during composition. A failed assembly
removes **only its new never-before-existing incomplete output folder**,
leaving all originals and older HUMAN workrooms intact. All pages remain
PRIVATE. Nothing is sent, scheduled, approved or released.

## NEW: complete saved-session PRIVATE HUMAN workpack (option 49)

Menu **49** is the continuation of the integrated full HUMAN workpack,
rather than an independent new storage format. The operator deliberately
provides a trusted original 0600 `PRIVATE-SESSION.json`, an existing
owner-only output parent, review date and unused workpack name. The
original HUMAN queue CSV is **optional**: blank seeds an all-`UNASSESSED`
workpack from the restored native PATH context. Supplied original 0600
CSV files still require the exact restored-session digest and native gates. The original strict session
reader returns PATH-only fields; those are installed in an **isolated
in-memory copy only**, and its `saved_session` property is then pointed
to that original checkpoint, matching the original native post-save
operator context. The original integrated workpack builder still fully
re-admits the unchanged CSV session digest, fixed HUMAN workflow fields
and all source-free output privacy gates. On success, the operator gets
a complete new 0700 locally indexed HUMAN workpack with a full offline
browser editor, priorities and matching team decks. On any HOLD the
current active console, original saved session, CSV and previous workpacks
remain unmodified. A prior HUMAN CSV generated before checkpoint save
may have a different PATH-only digest; that is **HOLD**, not an invitation
to override the original saved-session admission. This route grants no
security authority, authenticated client/operator consent or execution.

## NEW: exact-session offline workpack progress desk (option 50 + native CLI)

This independent native workflow compares **2–8 already-created owner-only
0700 HUMAN workpack folders** in an explicitly operator-declared order. It
requires the original strict saved 0600 PATH-only session, then re-admits
each exact owner-private pinned 0600 HUMAN CSV against **one unchanged
original session fingerprint**. Each original unsigned workpack receipt
must be canonical, consistent with the actual pinned HUMAN stage counts,
and explicitly all-false authority; duplicate or symlinked workpack
directories, altered session keys, malformed CSV, public custody or
ambiguous original inputs produce HOLD with no published report.

The new **console option 50** loads the checkpoint only into an isolated
in-memory session, leaving the live console entirely unchanged. Or run:

~~~sh
python3 assessment-integrated-suite/suite.py workpack-progress \
  --private-session /private/saved/PRIVATE-SESSION.json \
  --workpack /private/workpack-one \
  --workpack /private/workpack-two \
  --private-parent /private/owner-only \
  --folder private-human-progress \
  --human-confirm 'BUILD PRIVATE PROGRESS'
~~~

A newly created owner-only 0700 result contains 0600
`OPEN-PRIVATE.html`, `PRIVATE-HUMAN-PROGRESS.json` and
`PRIVATE-HUMAN-TRANSITIONS.csv`. The offline browser gives complete
UNASSESSED/HOLD/NEEDS_INPUT, HUMAN_REVIEW and HUMAN_FOLLOWUP counts and
team workload per declared snapshot, then highlights changed original
workflow stage/team/declared follow-up and whether a PRIVATE question
changed **without copying its text**. A second latest-snapshot HUMAN
attention board shows all still-declared HOLD/NEEDS_INPUT workflows and
how many consecutive selected original workpacks they remain marked for
attention; the extra 0600 `PRIVATE-HUMAN-ATTENTION.csv` allows a local
manual HUMAN handoff without original filenames, source paths, hashes,
questions, or any implied chronological elapsed time. Even original local filenames,
directory paths and SHA digests stay out of this output. Dates are
**human declarations**, not genuine chronology, due dates, client
appointments, investigation results, authenticated evidence or consent.
The existing original owner/private read guards and 0700/0600 write guards
are reused; no tests/QA or actual scans, grants, scheduling, dispatch or
deployment are part of this workflow.

## NEW: offline interactive HUMAN Progress Cockpit

The original native `workpack-progress` and console 50 now produce a real
offline HTML **Progress Cockpit** rather than only a static report. It shows
the first-vs-latest state of **every** original HUMAN workflow, counts for
the manually selected latest snapshot, all assigned-team workload and
historical declared transitions. Search by original workflow key/title or
declared review date; filter by exact HUMAN stage, team, still-declared
attention or changed-since-first, and reset without ever mutating a row.
The latest HUMAN HOLD/NEEDS_INPUT streaks are displayed separately.

This browser interface is rendered **only** from previously re-admitted
native owner-private workpack snapshots and contains no private question text,
original file paths, original source names, source bytes or SHA. Its one
inline JavaScript is CSP SHA256-pinned, `connect-src 'none'`,
`form-action 'none'`, with no fetch, storage, library, network, HTML
source ingestion, export or scanning. Operators without JavaScript open
`PRIVATE-SCRIPTLESS.html` within the same new owner-private 0700 workroom.
All generated HTML is 0600. Navigation and filtering are PRIVATE
administrative conveniences, not evidence authentication or security GO.

## NEW: continue an existing HUMAN assessment workpack (console 51)

An operator can deliberately start a **new full original browser-editable workpack**
without losing previously assigned HUMAN stages, teams, proposed follow-up
dates and confidential HUMAN questions. The new workpack is generated entirely
from the **single pinned private CSV descriptor snapshot** of an existing
owner-only 0700 original workpack; no reconstructed user input or silent stage
transition. Its original 0600 receipt and 0600 CSV are admitted against a
strict restored saved-session PATH snapshot (not against a remembered filename).
The original receipt is bounded, opened with NOFOLLOW, read once with full
descriptor identity, rejects duplicate keys and noncanonical literal
false-authority flags, and its team/card counts are independently checked
against exact original pinned rows. The previous workpack cannot be the new
output parent, and neither old workpack nor current console is modified.

Use foreground **console option 51** or the native CLI:

~~~sh
python3 assessment-integrated-suite/suite.py workpack-continue \
  --private-session /private/saved/PRIVATE-SESSION.json \
  --from-workpack /private/original-human-workpack \
  --private-parent /private/owner-only \
  --folder next-human-workpack \
  --review-date 2026-10-21 \
  --human-confirm 'CONTINUE PRIVATE WORKPACK'
~~~

The new date is **only a human-entered reference**, not evidence of elapsed
time, an appointment or an actual security deadline. Output includes a fresh
original interactive HUMAN queue Studio, scriptless summary, declared-date
priority review, original team-restricted HUMAN task decks and pinned 0600
CSV/JSON receipt in a new 0700 directory. Operators still need to export,
locally re-admit and deliberately review subsequent edits. No client/private
source opened, no scan, grant, external scheduling, authenticated reviewer
identity, security verdict or release is implied.

## Portable 15-original-studio software kit v15

[Offline LightUp Assessment Toolkit v15](LightUp-Assessment-Offline-Toolkit-v15.zip)
is a separate newly built SOFTWARE-ONLY companion with the same 15
original offline browser studios plus an updated offline navigation
guide reflecting the native owner-private workpack progression workflow.
No original source/private HUMAN CSV, saved session, generated workpack,
native Python program, private note, authentic consent or assessment
authorization is included. The native option 50 and CLI require a trusted
local checkout with original owner-private input artifacts. This ZIP
cannot be deployed as an assessment service or treated as a signed release.

## Portable 15-original-studio software kit v14

[Portable source-only LightUp Assessment Offline Toolkit v14](LightUp-Assessment-Offline-Toolkit-v14.zip)
contains 15 **unchanged** original offline HTML studios and the updated
software-only operator guide covering native PRIVATE HUMAN console
options 42-49, direct unassessed first-use workpack creation,
strictly bound local CSV admission, live HUMAN attention and team capacity
and the new confirmed `suite.py human-workpack` foreground CLI command.
All original client-/session-specific HUMAN workpacks remain
**native-only**, NEVER embedded in the portable software-only ZIP.
Its source-only ZIP manifest is unsigned and does not authenticate release.
Build artifact size: **250,180 bytes**; unsigned SHA-256:
`19d0bef509cc72f81e6749cb90d8d9d107a604069b0839608dc3da7fa269b6f7`.
The native-only route board (options 40/41) is deliberately NOT shipped
inside this browser-only ZIP: its file: bookmarks necessarily reference real
original owner-private workroom paths. The ZIP contains no PRIVATE client
files, HUMAN outcomes, notebook, source-specific receipts or session paths.

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

## Native original entry-page path admission

The integrated console now refuses to advertise a native `OPEN LOCALLY:`
path unless it is the original `OPEN-PRIVATE.html` **directly inside one**
owner-only 0700 kit folder under the exact manually chosen existing owner-only
0700 `--private-parent`. The original page must be a regular single-linked
owner-owned 0600 file of bounded size, never a symbolic link, outside the
checkout. A native producer claiming an unrelated, public, missing or redirected
HTML file becomes HOLD **without updating current session package references**.
No stdout paths are treated as proof of source authenticity, client consent,
original code trust, authorization, remediation or release. Existing outputs
remain untouched on HOLD; only a direct valid original return is bookmarked.

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

## Ready-to-use complete software-only offline download — 11 original apps

**[LightUp-Assessment-Offline-Toolkit.zip](LightUp-Assessment-Offline-Toolkit.zip)**
is a real portable 205 KiB ZIP committed alongside its deterministic native
[source bundler](package_offline.py). This is a complete browser-only
**software** distribution of eleven unmodified original one-file apps: no
client/source data, scanner, credentials, grants, workers, server, Python
runtime, executable installation step or internet access included.

Unpack into a **new, owner-private local directory**, open `START-HERE.html`
locally in a modern offline browser, then use each original app's local file
chooser for any separately approved PRIVATE source file. The branded accessible
local cockpit organizes original research/review, isolated-lab preparation,
benchmark analysis and HUMAN group decisions into four clearly named sections.
The included `README.txt` and `manifest.json` carry the exact original
source paths, unsigned SHA-256 for every included original app, byte size,
literal REVIEW_ONLY and only-false permission declarations.

The original HTML contents are never rewritten by the packager. The public ZIP
contains **no PRIVATE original sources**. All future HUMAN or source data
imported locally remains outside the distribution. The hash manifest is for
local file identity, **not** producer attestation, verified finding, client
consent, authorization or release. Current hosted/VPS exact-head CI,
source-owner and independent security/privacy/browser review and real consent
are still absent as release evidence. This portable product is **DRAFT/HOLD**
even though the static software is immediately available to download.

Rebuild on a trusted checkout, only when making a new owner-reviewed release:

~~~sh
python3 assessment-integrated-suite/package_offline.py \
  --output /path/to/NEW-software-only-kit.zip
~~~

The output must not already exist. This command reads a fixed source-only list
and cannot invoke any scan, model, network, customer ingestion or auto-publish.

## Offline original lab benchmark comparison, scenario/cohort HUMAN workroom

The original #1513 source owner [PR #1515](https://github.com/Zennay/Lightup/pull/1515)
at immutable `bb107d32ef8ce89b7f4068ed065f91bc639ecee3` is physically
integrated: four untouched assessment comparison library modules, three
original CLI scripts and their original docs. No upstream tests, workflows,
runtime dispatch, scope authorization or owner PR branches modified.

~~~sh
python3 assessment-integrated-suite/benchmark_room.py \
  --kind cohort \
  --before /private/previous-cohort.json \
  --after /private/new-cohort.json \
  --private-parent /private/owner-0700
~~~

Select `--kind single` for a single existing original lab evaluation or
`--kind scored` for 1-64 original paired ground-truth lab scenarios.
Source files are bounded to original CLI limits (65,536 bytes per single,
262,144 per cohort), opened read-only without symlinks. Original source
descriptors are reused in the unchanged offline CLI child, rather than
reopening possibly swapped source paths.

For a structurally admitted original lab comparison, produces a NEW
0700 PRIVATE workroom with 0600 original per-metric HTML report, source-byte
SHA-bound unsigned PRIVATE comparison JSON, ordinal-only numeric HUMAN CSV
and a scriptless CSP-limited local index. It highlights original metric
regressions, per-scenario baseline/candidate/delta and displays explicit
REVIEW_ONLY or HOLD. Original byte details, original input files and
target URLs are not copied into the packet; HTML still contains PRIVATE
original scenario identifiers, never suitable for public sharing.

An actual adverse original comparator result remains **HOLD (exit 3)**,
but creates the private human report; unsupported, incomplete, invalid or
ambiguous input stays generic HOLD without publication. Only a
non-regressed ORIGINAL comparison yields REVIEW_ONLY (exit 2) and that
never means PASS, authentic ground truth, client/operator authorization,
source ownership, release, verified remediation or deployment.
`console.py` offers this as menu option **8**.

No network, scan, models, grants, handlers, retest or execution. Separate
source-owner + independent privacy/security/browser review, existing
exact-head hosted/permanently registered named VPS CI, original #177/#182/#829,
current separate authenticated client/operator consent with action-time
revocation and explicit HUMAN GO remain mandatory. DRAFT/HOLD.

## Canonical original cohort export + complete multi-revision HUMAN trajectory

A single `benchmark_room.py --kind cohort` or `--kind scored` now also
exports `PRIVATE-original-canonical-cohort.json`: the **exact unchanged
original #1513 native cohort output shape**, with no wrapper-only keys.
It is directly accepted by existing independently held #1592 Candidate
Studio and #1584 Lab Trajectory Studio. Exact original baseline/candidate
SHA-256 bindings and operator-facing local markup remain only in the
separate PRIVATE handoff files; neither pollutes the canonical format.

A complete new workflow composes **3–12 source-declared candidate cohorts**
against one *identical* already-produced lab baseline, using only the
unchanged source-owner CLI comparator:

~~~sh
python3 assessment-integrated-suite/trajectory.py \
  --kind cohort \
  --baseline /private/original-baseline-cohort.json \
  --candidate /private/first-original-candidate-cohort.json \
  --candidate /private/second-original-candidate-cohort.json \
  --candidate /private/third-original-candidate-cohort.json \
  --private-parent /private/owner-0700
~~~

Use `--kind scored` for the original ground-truth scenario cohort comparison.
The native engine individually validates exact lab source, unchanged
scenario/metric baselines, canonical metrics, authority flags and correct
adverse-change HOLD semantics. A changed original baseline hash, repeated
candidate original bytes, malformed scenario, missing cohort or unsupported
source refuses the **whole** preparation, not a misleading partial trend.

A successful original-source admission produces one *new* 0700 PRIVATE
folder with 3–12 numbered canonical original-source-compatible cohort JSON
files, SHA/position/status PRIVATE unsigned receipt and scriptless index.
The complete original standalone **Lab Trajectory** and **Candidate Matrix**
apps are copied unchanged into the kit. Open the HTML locally, then
manually import the numbered canonical JSONs with the original apps'
file chooser. User-chosen candidate ordering is not independently verified
chronology. Regression HOLD still produces a PRIVATE HUMAN-only report and
remains exit code 3; admitted source-declared non-adverse comparison is
REVIEW_ONLY (2), never PASS.

The interactive `console.py` exposes this as option 9. Neither the
interactive original browser tools nor the new native orchestration scan,
schedule, execute, grant, retest, call models, authenticate customer
identity or externally publish data. Strict original full-project hosted +
permanently named VPS CI, original source-owner, independent security/privacy/
browser review, actual separate client and operator consent including
revocation at use and explicit HUMAN GO are still necessary before any
production merge/deploy. DRAFT/HOLD.

## Original 2–8 HUMAN reviewer packet reconciliation (complete PRIVATE handoff)

Existing original [PR #1669](https://github.com/Zennay/Lightup/pull/1669)
already provides an immutable offline consensus algorithm and full encrypted
browser workroom. The source was physically integrated unchanged earlier in
this candidate. New `reviewer_room.py` now makes the entire original workflow
usable from the same native suite and `console.py` menu option **10**:

~~~sh
python3 assessment-integrated-suite/reviewer_room.py \
  --plan /private/original-human-reviewer-a.json \
  --plan /private/original-human-reviewer-b.json \
  --private-parent /private/owner-0700
~~~

The original owner code requires 2–8 distinct valid original PRIVATE HUMAN
plan files, identical original source-bound row identities and canonical
human-only enum proposals, rejecting forged/duplicate/changed input. Builds a
unique new owner-0700 PRIVATE workroom with unchanged original:
`private-conflicts.html`, `private-resolver.html`,
`private-resolutions.json`, `anonymous-counts.json`, and **only when all
HUMAN conflicts resolved** the original `private-merged-original-plan.json`.
The complete original offline encrypted Reviewer Studio is copied alongside.
A scriptless private local index explains exactly which files to open.

Unresolved HUMAN conflict remains a meaningful `HOLD` (exit 3), not an
accepted default choice. Complete HUMAN proposal returns REVIEW_ONLY (exit 2)
and is **not** authenticated reviewer identity, verified security finding,
consent, source signature, grant, release or authorisation. When a person
manually completes the original conflict packet, they can run again with
`--resolutions /private/completed-original-resolutions.json` and the **same
original reviewer files in the same order**; original source independently
revalidates all SHA/row/choice bindings before emitting a new proposed packet.
Original source and other workers remain untouched.

No model, network, scan, evidence collection, retest, external sharing,
background job or customer grant. This is an offline DRAFT/HOLD candidate
subject to immutable-head CI, source-owner and independent security/privacy/
browser approvals, genuine separate client/operator consent (action-time
revocation), #177/#182/#829 and explicit HUMAN GO before any release.

## Source-bound HUMAN review returns for actual adverse original metrics

The native original benchmark outputs now also include
`PRIVATE-human-benchmark-followup.csv`: each **source-declared adverse**
metric row carries both unsigned exact original input byte SHA-256 identities,
the original scenario *ordinal only*, the canonical metric name and blank
human stage/group/question/blocker fields. Nothing is assigned or decided
automatically. For no original adverse observations the file has only its
header, never invented findings or an automatic PASS.

The 3–12-candidate trajectory kit similarly contains
`PRIVATE-human-trajectory-followup.csv` with source-original baseline and
candidate SHA-256, human-selected candidate position, original scenario
ordinal, adverse metric count and wholly blank HUMAN follow-up columns.
No original names, target URLs, evidence, source filenames, private notes
or authorization are introduced into this separate PRIVATE CSV. The
underlying complete original metric reports still require owner-approved
PRIVATE handling. File SHA-256 labels bind bytes but do not attest owner,
truth, permission or original chronology. Neither worksheet changes any
original benchmark or authentic review system. Source is DRAFT/HOLD.

## New original #1575 HUMAN Benchmark Review Desk, unified CLI → browser

Original held #1575 [PR #1576](https://github.com/Zennay/Lightup/pull/1576)
at exact original HEAD `bb5c2299d3697781db7093aaea79ed418f1cc07c`
was physically added as six unchanged existing product/doc files under
`assessment-review/` and `docs/assessment-review-desk.md`. No other
worker sources, QA suites, gates or authorization were modified.

The native `benchmark_room.py` now creates the original canonical single
or cohort JSON **plus an immediately available complete original HUMAN
Benchmark Review Desk HTML**. Choose that original canonical JSON locally
in its file chooser to triage adverse source-declared metrics, prepare HUMAN
follow-ups, and export native PRIVATE review handoffs. The `trajectory.py`
private multi-revision kit also includes the complete original Review Desk.
Nothing automatically approves, schedules, authenticates or scans anything.

**New software-only standalone ZIP V2:**
[LightUp-Assessment-Offline-Toolkit-v2.zip](LightUp-Assessment-Offline-Toolkit-v2.zip)
bundles **12 complete unchanged original local HTML studios**, a generated
scriptless 4-section launchpad, the original source-byte SHA inventory and
operator cautions. Native `package_offline.py` was updated to reflect the
actual included tool count dynamically. The **prior 11-app V1 ZIP remains
unchanged**, so users can still open earlier software snapshots.

The new V2 ZIP does not contain original assessment data, passwords, grant
materials, targets, scanners or executable native benchmark processors.
A SHA-256 checksum is unsigned file identity only. The whole composed source,
native HUMAN workflows and browser suite remain held pending original
source-owner signoff, independent privacy/security/browser review, original
exact-head CI and permanent named VPS CI, #177/#182/#829, actual separate
current client and operator authorization with at-use revocation and HUMAN GO.

## Original PRIVATE source continuity and notes integration · 20 Oct 2026

Integrated without changing original owner PR heads: Workspace Ledger
[#1694](https://github.com/Zennay/Lightup/pull/1694) frozen at
`65bbd88ee85bc50c9d8330893d5f4d9fa66193c8`, and credential-masked
Assessment Notes [#1691](https://github.com/Zennay/Lightup/pull/1691) frozen
at `2d0ad48a87474d49957e8ccd5622260133ba9d2f`. The latter contains
original #672 Basic/Proxy-Authorization redaction source. None is released.

The already existing foreground `console.py` now offers **15 local-only
workflows**, including five new integrated original-source actions:

1. Capture up to 12 already-produced PRIVATE kit directories in an immutable
   owner-private original byte ledger, with optional prior-snapshot delta.
   Missing or changed files require fresh HUMAN review; never a finding fix.
2. Reopen an original `ledger.json`, which rechecks every referenced source
   byte before carrying forward HUMAN discussion. No new snapshot is made.
3. Finalize a source-bound original ledger with locally completed HUMAN CSV;
   original native admission writes a separate PRIVATE HOLD-only packet.
4. Prepare 1–12 owner-private UTF-8 notes using the original credential masker;
   original parser creates a PRIVATE HUMAN editor, source-bound identity,
   and pattern-masked copies only, never a claim that all secrets are absent.
5. Finalize locally completed original-bound HUMAN note decisions into a new
   PRIVATE packet. Even INTERNAL_REVIEW_ONLY does not authorize disclosure.

Use interactive `python3 assessment-integrated-suite/console.py` options
11–15; or original-wrapped CLI commands, all foreground, without shell:

~~~sh
python3 assessment-integrated-suite/human_handoffs.py ledger-capture --kit /private/kit-a --kit /private/kit-b --private-parent /private/output
python3 assessment-integrated-suite/human_handoffs.py ledger-reopen --ledger /private/output/PRIVATE-lightup-ledger-ID/ledger.json
python3 assessment-integrated-suite/human_handoffs.py ledger-finalize --ledger /private/output/PRIVATE-lightup-ledger-ID/ledger.json --plan /private/HUMAN-review.csv --private-parent /private/output
python3 assessment-integrated-suite/human_handoffs.py notes-prepare --source /private/note.txt --private-parent /private/output
python3 assessment-integrated-suite/human_handoffs.py notes-finalize --original-kit /private/output/PRIVATE-lightup-notes-ID --decisions /private/PRIVATE-HUMAN-decisions-completed.csv --private-parent /private/output
~~~

Wrapper checks exact expected result contracts and owner-only entry files,
limits input and subprocess output and never prints private native stderr.
Original per-source validation remains the source of truth. Success exit 2
means PRIVATE REVIEW_ONLY; 3 means HUMAN HOLD or a refusal, not PASS.

The software-only offline toolkit additionally includes original Workspace
Ledger `standalone.html` as its 13th studio. The credential-masked notes
editor is generated only after native source admission (no fabricated data).
Neither copied software nor a SHA/hash is a verified author or release proof.
No input sources, customer notes, scans, targets, grants, model calls, service,
network transfer, external publication, deletion or background jobs are added.

**Hard release boundary remains:** Incubate M3/M7 PLAN/LAB ONLY, DRAFT/HOLD;
no main merge or production deploy without exact-head original GitHub-hosted
and registered named VPS CI, source-owner, independent privacy/security/browser
approval, #177/#182/#829, current separate authenticated client/operator
consent with action-time revocation, and explicit HUMAN GO.

## Original PRIVATE assessment → HUMAN remediation workflow (20 October)

Integrated exactly the original 17-file `assessment-remediation/` source from
[held owner PR #1628](https://github.com/Zennay/Lightup/pull/1628), pinned at
`ab3ee5002ef78d7d4cb909faddab4522c8790485`, and its missing unchanged
`scripts/lightup_review.py` comparator. A complete repository merge was aborted
because original labrun.py and lab CLI documentation conflict with current
integrated work. This strictly source-only import preserves the original owner
branch and shared runtime/auth/scanner/consent files unchanged.

The existing operator console now exposes **20** private, foreground workflows:

- **16**: given already-completed ORIGINAL canonical lab comparison JSON and
  separately authenticated original five-column client finding CSV, create
  owner-private exact-source-bound manual finding mapping, private human
  briefing and follow-up. Optional confidential room ZIP stays local.
- **17**: given two original completed lab cohorts and separate original client
  findings, invoke the original offline comparator before native mapping;
  never create/fabricate a benchmark result from targets or models.
- **18**: prepare a privately scoped manual-human team handoff and matching
  offline review room from unchanged original source-bound links.
- **19**: admit one returned HUMAN annotation with its exact original team
  scope/baseline and produce a separate private before/after packet.
- **20**: reconcile 2–12 disjoint original team assignments and returned
  annotations against unchanged original source identities. All conflicts,
  overlaps, source drift or malformed returns HOLD before human merge.

Equivalent explicit native commands use `remediation_handoff.py bridge/cohorts`
and `remediation_team.py prepare/receive/reconcile`, both in
`assessment-integrated-suite/`. Inputs and private outputs are strictly local;
all original native admission, source/row/metric classification and confidential
publication remain in original scripts, not copied into adapters.

The browser-only offline software ZIP now includes **15 original HTML studios**,
including the original lab→finding Mapping Studio and human Team Room. It does
not include private assessment data or grant authority. The native 20-function
console and human publisher require an appropriate trusted checkout and actual
original PRIVATE source files; the browser ZIP alone does not validate them.

Human links are NOT evidence of shared client/engagement identity, verified fix,
authenticated team sender, current consent, lawful recipient or permission.
No scan, tool, model, network, grant, broker, retest, deletion, external
sharing or deployment is executed. The independent original source-owner,
privacy/security/browser review, exact-head hosted + permanently registered
VPS CI, #177/#182/#829, separately authenticated client and operator consent
with action-time revocation and explicit HUMAN GO remain mandatory release
gates. Posture stays Incubate M3/M7 PLAN/LAB ONLY DRAFT/HOLD.

## One-command PRIVATE HUMAN casebook and exact-source ledger (20 Oct)

New `remediation_casebook.py` composes the original local lab→human remediation
producer and unchanged original `assessment-workspace-ledger/ledger.py`. This
is one complete foreground user workflow, NOT an assessment, external
handoff, authorization, fix verification, scan, or privacy/security approval.

**Console options 21/22:** Choose an already completed original canonical lab
comparison JSON (21), or two separately completed original baseline/candidate
lab cohorts (22), plus the separately authenticated original five-column client
findings CSV. Optionally supply previously completed original source-bound HUMAN
links; otherwise start with an empty manual original review. The console creates
one new 0700 owner-only original private assessment workroom (with unchanged
original Mapping Studio), delegates source validation and exclusive private
publication to the original producer, then separately captures exactly those
workspace file bytes in the original 0700 private HUMAN ledger with CSV and
offline review studio. A new owner-only scriptless `START-HERE.html` links both
unchanged originals without exposing original source names, findings or paths.
It never sends a packet, authenticates recipients, or assumes external consent.

CLI, from a trusted checkout, with preexisting owner-only 0700 output parent:

~~~sh
python3 assessment-integrated-suite/remediation_casebook.py --comparison /private/completed-canonical.json --findings-csv /private/original-client-findings.csv --private-parent /private/owner-output --prefix first-case
python3 assessment-integrated-suite/remediation_casebook.py --baseline /private/completed-baseline.json --candidate /private/completed-candidate.json --findings-csv /private/original-client-findings.csv --private-parent /private/owner-output --prefix cohort-case
~~~

The original private HUMAN result remains REVIEW_ONLY (2) or adverse-source
HOLD (3); no PASS, authenticated source ownership or verified fix. If a later
stage refuses, completed source-native private receipts are intentionally
left for local owner inspection, not silently deleted. The software-only ZIP
includes a description but no original client sources or native runtime.
Original hosted + permanently registered named-VPS CI, owner, independent
security/privacy/browser review, #177/#182/#829, genuine separate current
authenticated client/operator consent with revocation-at-use and explicit
HUMAN GO are still required before any main merge/deploy or real target action.

## Original PRIVATE evidence curation and HUMAN recipient replies (20 Oct)

The entire original source from held owner [PR #1679](https://github.com/Zennay/Lightup/pull/1679)
is **already present unchanged** under `assessment-evidence-curation/`.
The integrated [original_evidence.py](original_evidence.py) and
[original_evidence_reply.py](original_evidence_reply.py) now delegate only to
that source, with bounded foreground output, exclusive NEW 0700 owner-private
folders OUTSIDE the checkout, original publisher 0600 files, strict original
REVIEW_ONLY receipt admission and no private content echoed to the terminal.
The 31-action [operator console](console.py) adds nine complete local steps:

- **23:** admit existing original lab JSON, matching original PRIVATE manifest
  and exact seven-column HUMAN CSV; produce source-minimized selection studio,
  template and unsigned exact-original preparation receipt. The generated UI
  uses original ordinal, source-reported severity and evidence count only.
- **24:** re-admit same original bytes, matching preparation receipt and a
  separately completed HUMAN selection CSV; publish a **selected-only original
  PRIVATE evidence dossier**, per-priority HUMAN review questions, source-
  minimized but still PRIVATE recipient questions and small counts.
- **25:** view 2–12 separately saved source-bound HUMAN selection revisions.
  Their supplied order is a HUMAN ordering, not verified timestamps.
- **26:** make one consolidated privately held interactive HUMAN selection
  review, with unsigned source binding, unverified recipient work proposals.
- **27/28:** create an exact-source PRIVATE recipient question workroom, then
  separately re-admit a returned HUMAN response with the unchanged original
  selection, source and response binding; no recipient is contacted by LightUp.
- **29/30:** create a local PRIVATE sender triage browser from original reply,
  then re-admit sender HUMAN routing and proposed next actions; no actual
  technical remediation/retest or identity proof is performed.
- **31:** create the next HUMAN question selection proposal from the exact
  original returned recipient response and sender triage. Never dispatch it.

All operations explicitly request **REVIEW ONLY**. Confidential human questions,
original target details, and manually returned replies may disclose clients:
these outputs are not anonymous or approved to send. Never treat a source label,
unsigned hash, encryption, HUMAN answer, absence from selection, proposed
closure or HUMAN priority as verified security fact or permission. Original
current authenticated client/operator consent and real recipient approval,
with action-time revocation, remain distinct. These are strictly local source
review tools: no scanner, target work, model, grant, network, delete, retest or
external transmission occurs. Original independent owner, privacy/security/
browser and CI/VPS reviews, #177/#182/#829 and explicit HUMAN GO still apply.

The 15-studio **browser-only** source ZIP is not advertised as including these
native or source-specific generated selection/recipient studios: those are
created privately from the actual original source by the native workflow.
The portable software ZIP does NOT contain client records, any generated
source-bound HUMAN selection UI, or a native executable.

## Source-native PRIVATE disclosure + retention HUMAN desk (20 October)

The original held `assessment-disclosure-preflight/` and
`assessment-retention-desk/` are already present, unchanged. New native
[disclosure_handoff.py](disclosure_handoff.py) and
[retention_handoff.py](retention_handoff.py) exclusively delegate admission
and output publication to these original owner components.

**Console actions 32–34** complete an offline private disclosure workflow.
32 accepts 1–12 previously recorded original PRIVATE lab JSON sources and
creates a new 0700 workroom containing original source-free PRIVATE preflight,
original small-cohort-suppressed counts, unsigned source-free HUMAN receipt,
original HUMAN CSV template, and unchanged offline browser review editor.
`OPEN-PRIVATE.html` links these owner-private 0600 products without embedding
client names, targets, evidence, or source paths. 33 uses the exact unchanged
original receipt plus HUMAN-edited CSV to generate an original private
scriptless HUMAN report in a different new workroom. 34 instead prepares a
PRIVATE HUMAN-stage counts CSV using original minimum-cohort suppression,
with a strict selectable floor of 5–12. Counts remain PRIVATE and never
certify anonymity or permission to disclose. Browser encrypted continuity
remains available independently; the native wrapper never asks for passwords.

**Console actions 35–36** compare original saved PRIVATE HUMAN retention
plans. Original `history.py` renders a 2–12-plan ordered HUMAN history and
original `drift.py` compares two source sets with human custodian, sensitivity,
and hold proposal changes. They neither apply a proposal nor delete a file.
An absent record cannot prove actual deletion, remediation, consent, or
verified source ownership. Original native report exit 0 is mapped to the
operator-only REVIEW_ONLY exit 2 only after exact source receipt + 0600 file.

All operations use original local source validation, exclusive outputs inside
new owner-private 0700 folders, and user-confirmed `REVIEW ONLY`. No scanner,
model, grant, active target, send, real fix, retest, deletion, or external
release. Existing required original hosted/named-VPS CI, owner acceptance,
independent privacy/security/browser reviews, #177/#182/#829, current
separately authenticated client/operator consent with action-time revocation,
and explicit HUMAN GO are unchanged. Project remains Incubate M3/M7 PLAN/LAB
ONLY DRAFT/HOLD. No QA/regression/test suites written or executed.

## Resumable PRIVATE operator workspace (20 October)

**New operator actions 37–39** solve the previous limitation: 36 separate
source-native workflows had to be re-entered after the terminal closed.
The native implementation is [private_session.py](private_session.py),
[session_console.py](session_console.py) and
[session_history.py](session_history.py). These features NEVER run a source
producer automatically and never collect the actual original PRIVATE lab
source, findings, answers, credentials, passwords or HUMAN notes.

- **37 Save PRIVATE:** Choose an **existing** 0700 owner-only directory
  outside the checkout, an unused unique folder name and explicitly type
  `SAVE PRIVATE`. A new 0700 workroom contains `PRIVATE-SESSION.json` (0600)
  with a strict allowlist of all current operator **path references only**,
  literal-false authority flags and `REVIEW_ONLY` status. Also creates a
  scriptless, network-denying `OPEN-PRIVATE.html` with local `file:` bookmarks
  to **existing** source-owner-produced PRIVATE HTML workrooms. Unavailable
  or non-private original pages are not linked. No copied PRIVATE evidence.
- **38 Restore PRIVATE:** Select that original owner-only 0600 JSON from
  its 0700 folder and explicitly type `RESTORE PRIVATE`. All expected path
  fields and literal-false authority flags are re-admitted atomically, with
  refusal for altered schemas, duplicate JSON members, wrong owner/mode,
  hardlinks, changed bytes and unsafe/bounded paths. Only **entered local
  path references** are restored; no original inputs are opened, validated,
  executed, shared or trusted. Any subsequent original operation still
  re-admits source and requires its own separate explicit HUMAN action.
- **39 Compare saved workspaces:** Choose 2–8 distinct original PRIVATE
  operator session JSONs in **operator-declared order**, a different unused
  private output folder and type `REVIEW ONLY`. Creates a new 0600 scriptless
  `OPEN-PRIVATE.html` showing which path fields were added, cleared or changed
  and links to source-owned PRIVATE launcher pages where still available.
  It omits actual paths, source bytes and private content. Its ordering is
  not verified time, and the same path does not prove unchanged source bytes.

**Confidentiality:** The 0600 PRIVATE-SESSION.json still contains path names,
which can reveal clients, engagements or devices even though there are no
source contents. Keep both JSON and launcher strictly on a trusted local
approved device, do not sync/upload/email them. These files are intentionally
plaintext; operator-supplied filesystem privacy is a prerequisite, not an
assertion of cryptographic security or genuine identity authentication.
Browser link traversal is a local manual action, never a target instruction.

Source code is portable and has no runtime dependency beyond Python 3 on
an approved PRIVATE host. The portable HTML-only ZIP does not contain
resumable operator sessions, since those are intentionally generated locally
for explicitly entered PRIVATE paths. Previous session snapshots are never
overwritten and nothing in these features confers original owner/client/
operator consent or HUMAN GO. Original CI/security/privacy/browser and
#177/#182/#829 HOLD gates remain mandatory, as do revocation-at-use and
original separate authenticated client/operator authorization. No testsuites,
scans, grants, retests, recipient transmission or unattended tasks created.
