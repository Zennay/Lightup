## Latest portable software bundle — v28

[Download the integrated offline toolkit v28](LightUp-Assessment-Offline-Toolkit-v28.zip) ·
[Detached SHA-256 reference](LightUp-Assessment-Offline-Toolkit-v28.zip.sha256)

Unsigned ZIP SHA-256: 4695daed6f5809dabfc3c73894e7ba3d0228453d8761834001328363c6708d86.

The v28 manifest uses schema v2 and binds byte lengths and SHA-256 for all 19
browser studio HTML pages, two local support JS assets, launcher, README and
operator guide. It integrates the current candidate-matrix scriptless HTML,
aggregate JSON schema v5 and long-form PRIVATE HUMAN round-history CSV.

Verify without extracting files through the integrated suite:
python3 assessment-integrated-suite/suite.py verify-kit --package assessment-integrated-suite/LightUp-Assessment-Offline-Toolkit-v28.zip --sha256-file assessment-integrated-suite/LightUp-Assessment-Offline-Toolkit-v28.zip.sha256

The standalone verifier accepts the same optional checksum inputs:
python3 assessment-integrated-suite/verify_offline.py --package assessment-integrated-suite/LightUp-Assessment-Offline-Toolkit-v28.zip --sha256-file assessment-integrated-suite/LightUp-Assessment-Offline-Toolkit-v28.zip.sha256

Use `--expected-sha256` instead when the expected digest came from a separately
trusted channel. The detached sidecar is published in the same repository and
is not an independent trust anchor.

To detect a stale software bundle against a particular local checkout, run
from that checkout's root and add `--source-root .`:

    python3 assessment-integrated-suite/suite.py verify-kit --package assessment-integrated-suite/LightUp-Assessment-Offline-Toolkit-v28.zip --source-root .
    python3 assessment-integrated-suite/verify_offline.py --package assessment-integrated-suite/LightUp-Assessment-Offline-Toolkit-v28.zip --source-root .

This optional mode compares every source-bound software entry with its declared
relative source path in the explicitly selected checkout and fails closed on
missing, unsafe, changed or mismatched files. It does not extract the ZIP.
Generated launcher/guide assets are still covered by package inventory checks,
not by checkout source parity. A matching checkout proves byte parity only,
not authorship, provenance, consent or authorization. The package is unsigned,
REVIEW_ONLY and not a deployment artifact.

## Compare two verified offline toolkit versions

The integrated `verify-kit` command and standalone verifier can compare a candidate
software ZIP against an earlier local ZIP without extracting either package. Both
archives must pass the existing bounded inventory and byte-integrity checks first.
The report lists added, removed and changed software entries by their safe relative
source path, plus changes to fixed package-support assets. It prints no client
records and writes no report file.

```bash
python3 assessment-integrated-suite/suite.py verify-kit \
  --package assessment-integrated-suite/LightUp-Assessment-Offline-Toolkit-v28.zip \
  --compare-package /private/releases/LightUp-Assessment-Offline-Toolkit-v27.zip
```

The standalone equivalent is:

```bash
python3 assessment-integrated-suite/verify_offline.py \
  --package assessment-integrated-suite/LightUp-Assessment-Offline-Toolkit-v28.zip \
  --compare-package /private/releases/LightUp-Assessment-Offline-Toolkit-v27.zip
```

Optional `--expected-sha256`, `--sha256-file`, and `--source-root` apply to the
candidate `--package`; the comparison baseline is still checked against its own
internal manifest. A valid manifest or a digest stored beside the same ZIP does not
authenticate who created it or where it came from. This is a local inventory diff,
not a release approval, source-owner review or authorization to use the kit.

## Native path safety

The native suite and the standalone native ZIP verifier reject an existing
symbolic link anywhere in the path chain for source files, private output
parents, saved HUMAN sessions/workpacks, and software-package or digest-sidecar
inputs. This is a fail-closed preflight: use ordinary directories and regular
files, with private output parents owned by the current user and restricted to
mode 0700. A symlink refusal does not inspect or change the linked target.
This check is not a race-free guarantee against a concurrent filesystem change,
and does not establish source authenticity, authorization, consent or release
readiness.

## Previous portable software bundle — v27

[Download the source-only offline toolkit v27](LightUp-Assessment-Offline-Toolkit-v27.zip) ·
[Detached SHA-256 reference](LightUp-Assessment-Offline-Toolkit-v27.zip.sha256)

Unsigned ZIP SHA-256: dc012bed8d0e58d9bd8bbb33320de327f0db859848ed8c8e5f68d799318028f3.

**Snapshot note:** v27 is the previous packaged snapshot. The current v28 archive above integrates the current candidate-matrix source and aggregate JSON schema v5. Both bundles remain unsigned and REVIEW_ONLY.

The v27 manifest is explicitly versioned as schema v2 and includes the complete
unsigned byte inventory for all studio/support files, launcher, README and
operator guide. The native verifier reads legacy v1 bundles (v25), the extended
v1 manifest in v26, and current v2 bundles. Legacy v1 bundles do not hash their
generated launcher or README internally; pass an expected whole-ZIP SHA-256
from a separately trusted source when required.

Verify v27 without extracting files, using the committed convenience sidecar:
python3 assessment-integrated-suite/suite.py verify-kit --package assessment-integrated-suite/LightUp-Assessment-Offline-Toolkit-v27.zip --sha256-file assessment-integrated-suite/LightUp-Assessment-Offline-Toolkit-v27.zip.sha256

Or provide an expected digest explicitly from a trusted separate channel:
python3 assessment-integrated-suite/suite.py verify-kit --package assessment-integrated-suite/LightUp-Assessment-Offline-Toolkit-v27.zip --expected-sha256 dc012bed8d0e58d9bd8bbb33320de327f0db859848ed8c8e5f68d799318028f3

## Previous portable software bundle — v26

[Download the source-only offline toolkit v26](LightUp-Assessment-Offline-Toolkit-v26.zip) ·
[Detached SHA-256 reference](LightUp-Assessment-Offline-Toolkit-v26.zip.sha256)

Unsigned ZIP SHA-256: 69144a5f751af3090b6371fc3270a4c636730a7ee80a48d668328aa94d4d31bd.

The current assessment-runtime branch produces a software-only ZIP with a
source-free START-HERE.html launcher and 19 independently opened offline
browser studio HTML pages plus two adjacent local support JavaScript files.
Native Python, original assessment results, customer data, targets and reviewer
notes are not bundled. Every studio remains REVIEW_ONLY / DRAFT/HOLD.

The v26 ZIP's unsigned manifest.json binds exact byte lengths and SHA-256
digests for every studio/support asset, the launcher, README.txt and the
operator guide. It explicitly excludes its own hash. To verify a locally
downloaded package without extracting files, use the native checkout tool:
python3 assessment-integrated-suite/verify_offline.py --package assessment-integrated-suite/LightUp-Assessment-Offline-Toolkit-v26.zip --expected-sha256 69144a5f751af3090b6371fc3270a4c636730a7ee80a48d668328aa94d4d31bd

The same verifier is available from the native suite command:
python3 assessment-integrated-suite/suite.py verify-kit --package assessment-integrated-suite/LightUp-Assessment-Offline-Toolkit-v26.zip --expected-sha256 69144a5f751af3090b6371fc3270a4c636730a7ee80a48d668328aa94d4d31bd

VERIFIED LOCAL INTEGRITY ONLY confirms the archive inventory and bytes match
the unsigned manifest. It does not authenticate author, origin, source truth,
consent, authorization, findings, remediation or release. The verifier is a
native companion and is intentionally not included in the browser-only ZIP.
The detached SHA file is published beside the ZIP for convenient byte comparison.
Because both are in the same repository, the sidecar is not an independent trust
anchor. Obtain the expected digest through a separately trusted channel when
that distinction matters. The package is private, unsigned and not a deployment artifact.

# LightUp integrated PRIVATE assessment handoff

## 21 October · Explicit HUMAN continuation from original Attention revisions (80–81)

The complete new original-source-bound product is [attention_decision.py](attention_decision.py),
with interactive console companion [attention_decision_console.py](attention_decision_console.py).
It lets an operator explicitly select the proposed role and proposed HUMAN follow-up
for every one of the twenty original actions from **independently reopened** original
HUMAN Attention revision receipts (not from unauthenticated browser-only drafts).

**Procedure:** First prepare a full original PRIVATE revision portfolio with native
action **78**. Copy its `PRIVATE-EDITABLE-HUMAN-CHOICES.csv` to a separate NEW owner-private
0600 input file, outside the saved portfolio, and edit the two selection-number
columns (role_from_revision and followup_from_revision). Both fields start at
**0 = WITHHOLD**, producing UNASSIGNED / UNCLASSIFIED; an explicit selected
number 1–8 copies ONLY the corresponding fixed HUMAN proposal category
from that declared revision. Native **80** reopens the original 1–8
72/73 Lab Route receipts, 2–8 original 76/77 HUMAN Attention receipts,
and the original 78 portfolio. It then re-admits the strict edited
twenty-row original-action CSV and creates a separate 0700 PRIVATE output
room with six 0600 files: original edited choices, new browser-compatible
full v2 source-free HUMAN draft, selected-choice CSV, scriptless offline
HTML summary, anonymous decision counts JSON and unsigned SHA file receipt.

Native **81** reopens the same original source receipts and exact saved
HUMAN output bytes. The new source-free v2 proposal can be opened
in the existing [HUMAN Attention Workboard](human-lab-attention-standalone.html)
after the user reloads the same original source-free discussion rounds
in the same selected order and confirms the import.

Example foreground native CLI for an approved offline local checkout:

```bash
python3 assessment-integrated-suite/attention_decision.py create \
  --route-rooms /PRIVATE/original-route-1 /PRIVATE/original-route-2 \
  --attention-rooms /PRIVATE/attention-receipt-1 /PRIVATE/attention-receipt-2 \
  --history-room /PRIVATE/attention-revision-portfolio-1 \
  --edited-choices /PRIVATE/new-input/HUMAN-choices.csv \
  --private-parent /PRIVATE --folder human-continuation-1

python3 assessment-integrated-suite/attention_decision.py reopen \
  --route-rooms /PRIVATE/original-route-1 /PRIVATE/original-route-2 \
  --attention-rooms /PRIVATE/attention-receipt-1 /PRIVATE/attention-receipt-2 \
  --history-room /PRIVATE/attention-revision-portfolio-1 \
  --edited-choices /PRIVATE/new-input/HUMAN-choices.csv \
  --saved-room /PRIVATE/human-continuation-1
```

This operation creates only local HUMAN *proposals*. No actual recipient,
role assignment, execution, scanning, grant, client approval, finding,
verified identity, transmission or deployment is created. The original
M3/M7 Incubate / PLAN-LAB ONLY / DRAFT-HOLD, source-owner and independent
security/privacy/browser review, permanent named VPS and hosted exact-head
CI, #177/#182/#829, separately current authenticated client and operator
consent with revocation-at-use, and explicit HUMAN GO remain mandatory
before any main merge or live use. Native 80/81 are not shipped in the
browser-only software ZIP.



## 21 October · Complete native HUMAN Attention revision portfolio (console 78–79)

**New operator-facing product**: [attention_history.py](attention_history.py)
and [interactive console companion](attention_history_console.py) let an
original local owner compare **2–8 independently saved PRIVATE HUMAN
Attention proposal receipts** with a common 1–8 original native HUMAN
Route source-free receipts. Each revision is separately reopened with
the existing \`attention_receipt.reopen\`, which reopens every original
\`lab_route_handoff\` receipt and verifies its exact saved original
self-report bytes and 0600 outputs. A source-free role/follow-up revision
cannot be imported on its own.

**Run native console options:**

- **78** — enter 1–8 original 72/73 HUMAN Route receipt room paths,
  then 2–8 **distinct saved 76/77 HUMAN Attention receipt rooms**
  in the chosen comparison order. Select a **new** output room in an
  existing owner-only 0700 PRIVATE parent outside the checkout; type
  \`CREATE HUMAN REVISION PORTFOLIO\` to publish a PRIVATE all-source-bound
  product (all generated files 0600).
- **79** — enter the same original Route rooms and same original Attention
  rooms in the same order, plus that saved portfolio output room. It
  strictly reopens **every original PRIVATE receipt and every output
  byte**; missing or additional files or changed source become HOLD.
- Optional directly through local CLI:

\`\`\`bash
python3 assessment-integrated-suite/attention_history.py create \
  --route-rooms /PRIVATE/original-route-1 /PRIVATE/original-route-2 \
  --attention-rooms /PRIVATE/attention-receipt-1 /PRIVATE/attention-receipt-2 \
  --private-parent /PRIVATE --folder attention-revision-portfolio-1

python3 assessment-integrated-suite/attention_history.py reopen \
  --route-rooms /PRIVATE/original-route-1 /PRIVATE/original-route-2 \
  --attention-rooms /PRIVATE/attention-receipt-1 /PRIVATE/attention-receipt-2 \
  --saved-room /PRIVATE/attention-revision-portfolio-1
\`\`\`

**Seven new directly usable output files** in one PRIVATE 0700 room:

1. \`OPEN-PRIVATE.html\`: scriptless, local interactive-free readable
   portfolio showing all original five HUMAN stages, the last
   operator-chosen twenty-action proposal, and every cell that changed.
2. \`PRIVATE-HUMAN-ATTENTION-MATRIX.csv\`: **all original twenty actions
   and every selected revision's fixed role/follow-up choices**.
3. \`PRIVATE-HUMAN-ATTENTION-CHANGES.csv\`: the changed role/follow-up
   proposal cells with from/to fixed categories and manual revision number.
4. \`PRIVATE-HUMAN-ATTENTION-HISTORY.json\`: complete source-free
   fixed-schema revision digests, five-stage NEEDS_INPUT / unassigned /
   untriaged summary and exact changed proposal markers.
5. \`PRIVATE-LATEST-HUMAN-ATTENTION.json\`: unchanged original source-free
   v2 proposal bytes from the **last manually selected** attention receipt.
   This can be re-opened in the existing [offline Attention Workboard](human-lab-attention-standalone.html)
   after selecting the same original 1–8 source-free HUMAN discussion reports.
6. \`PRIVATE-EDITABLE-HUMAN-CHOICES.csv\`: a 20-row, withhold-by-default
   selection worksheet for explicit role/follow-up choices (both initially
   0). Copy it into NEW 0600 private input OUTSIDE the saved original
   receipt before editing.
7. \`PRIVATE-RECEIPT.json\`: unsigned exact-file SHA-256/length inventory,
   preserving source-free upstream original attention receipt digests.

**Meaning:** the file order is chosen by a HUMAN operator and never
establishes actual dates, identity or chronology. Fixed role categories
are **proposals only**, never assignment, responsibility transfer,
recipient dispatch or security findings. Source-free inputs contain no
customer targets, secrets, original audit data or reviewer personal names.
There is NO original assessment execution, real scan, consent, privilege
grant, scheduling, external request or deployment.

Native features 76–81 are deliberately **NOT** packaged as executable
Python inside the browser-only software ZIP. Both original and new
source paths stay owned by this existing integrated PR, not by other
held companion PR owners. LightUp remains Incubate M3/M7 PLAN/LAB ONLY
DRAFT/HOLD; all original CI, independent owner/security/privacy/browser
reviews, #177/#182/#829 and separate authenticated current client and
operator consent with revocation-at-use plus explicit HUMAN GO remain
gates before main merge or any real assessment.



## 21 October · Native PRIVATE HUMAN Attention custody (console 76–77)

**Delivered integration** of the existing [source-free HUMAN Attention browser](human-lab-attention-standalone.html)
with the **original** saved, owner-private HUMAN Lab Route receipts from
native console options 72–73. The product is [attention_receipt.py](attention_receipt.py)
and its [interactive console companion](attention_receipt_console.py), both
native-only, NOT included in the browser-software-only ZIP.

Unlike a browser-only proposal, the native receiver opens **all original
1–8 PRIVATE Lab Route receipt rooms** in the deliberate order selected by
the operator. Each saved room is reopened by the existing original
\`lab_route_handoff.reopen()\` function, including its strict original
20-action schema and exact original input / generated output bytes.
The 0600 \`LightUp-PRIVATE-HUMAN-Attention.json\` browser proposal is then
admitted using duplicate-key-safe native JSON parsing and complete
v2 exact-field admission:

- It must match every native original source-free marker profile in the
  same manually selected order, all 20 original action ordinals, every
  last status and actual declared transition count.
- It may contain only fixed role and follow-up enum values, bounded
  original 0600 bytes and all literal false authority fields.
- All input and output must live under owner-only 0700 directories,
  outside the original checkout; the native output is a new exclusive
  0700 PRIVATE room with seven 0600 files: unchanged original
  proposal bytes, canonical received JSON, complete CSV, scriptless
  CSP-restricted original action HTML, a NEW grouped HUMAN proposed-role
  cockpit HTML, anonymous source-free role/count JSON and an unsigned
  receipt. The grouped role board retains all twenty original action
  ordinals, including UNASSIGNED, but it does not assign anyone.
  No original source room is mutated.
- Native **77** re-admits the same browser proposal, every original
  native self-report receipt room and **every** saved output byte.
  A missing, changed or unexpected file is HOLD. Neither successful
  replay nor SHA-256 proves real actor identity, a genuine review,
  security improvement or release permission.

**Console use on an approved, local original checkout:** run
\`python3 assessment-integrated-suite/console.py\` and select
**76 (receive)** or **77 (reopen)**. Both prompt for manually ordered
original 0700 receipt rooms, the original owner-private 0600 browser
attention JSON, and output destination. Option 76 additionally
requires the exact HUMAN confirmation
\`RECEIVE HUMAN ATTENTION ONLY\`.

For non-interactive, foreground local usage:

\`\`\`bash
python3 assessment-integrated-suite/attention_receipt.py receive \
  --attention /PRIVATE/input/LightUp-PRIVATE-HUMAN-Attention.json \
  --rooms /PRIVATE/original-route-receipt-1 /PRIVATE/original-route-receipt-2 \
  --private-parent /PRIVATE --folder attention-receipt-1

python3 assessment-integrated-suite/attention_receipt.py reopen \
  --attention /PRIVATE/input/LightUp-PRIVATE-HUMAN-Attention.json \
  --rooms /PRIVATE/original-route-receipt-1 /PRIVATE/original-route-receipt-2 \
  --saved-room /PRIVATE/attention-receipt-1
\`\`\`

These commands are **illustrative local paths** and require actual
previously completed 72/73 native receipt rooms. They do NOT execute
network calls, targets, models, scanners, grants, assessments or dispatch.
Return code 2 is deliberately the original REVIEW_ONLY acceptance,
**not** PASS or approval; HOLD returns 3. The unsigned source-byte
receipts establish only byte consistency of *untrusted HUMAN
self-report* inputs, not authentic client/operator consent. The order
of receipt rooms remains a HUMAN assumption, never proven chronology.

**Release remains DRAFT/HOLD:** Notion Incubate M3/M7 PLAN/LAB ONLY;
original exact-head hosted + permanent named VPS CI, source-owner and
independent security/privacy/browser reviews, open #177/#182/#829,
actually separately authenticated current client and operator
consent with revocation at use, and explicit HUMAN GO are mandatory.
No main merge or live work has been authorized.



## NEW · Source-free HUMAN Lab Attention Workboard (21 October 2026)

**Complete offline product:** [one-file HUMAN Attention Workboard](human-lab-attention-standalone.html)
or the original [paired HTML](human-lab-attention.html)
and adjacent [JavaScript](human-lab-attention.js).
The single-file edition includes the same source code as a SHA-256-CSP
pinned inline script and works without adjacent JavaScript.
This is installed via the original native `suite.py` workroom navigator
and included by `package_offline.py` in the next software-only offline kit.

For standalone source-only regeneration on an approved local checkout:

```bash
python3 assessment-integrated-suite/build_attention_standalone.py \
  --output /EXISTING-OWNER-PRIVATE-0700-DIRECTORY/LightUp-HUMAN-Attention.html
```

The builder refuses existing paths, group/world-accessible output parents
or source/CSP drift and uses a new 0600 file outside the source tree.
The unsigned SHA-256 is **not** publisher identity, verified source or
consent. The original software-only kit builder independently refuses a
checked-in standalone if it differs from its exact original HTML/JS.
A new portable ZIP has **not** been claimed by this update.

The independent browser product accepts **1–8 manually ordered** source-free
`human-lab-route` JSON self-reports. Each is bounded to **24 KiB** and
must match the exact original twenty-position action list (52–71), fixed
four discussion markers and all false authority flags. Repeated JSON
object keys (including escaped decoded duplicates), nested ambiguous
keys, unexpected source/authority claims, repeated identical rounds,
incorrect order and oversized documents are rejected **atomically**.
A refused import leaves any previous in-memory workboard intact.

**Operator workflow:**
1. On a trusted local device, open `human-lab-route-standalone.html` or
   its original two-file equivalent. Export a complete source-free HUMAN
   discussion self-report to owner-private local storage.
2. Open `human-lab-attention.html` with `human-lab-attention.js` **beside
   it**. Select 1–8 such source-free self-reports in the order in which
   you want them discussed. This chooser order is explicitly NOT
   authenticated chronology, nor a history of real work.
3. Inspect fixed action status, transition count and five phase summaries.
   Filter current needs-input, non-discussed, changed/repeated or locally
   untriaged actions; manually propose a fixed role and follow-up category.
   The visible-only bulk action proposes **request original input** solely
   on originally marked NEEDS_INPUT, after HUMAN confirmation.
4. Export an **unsigned complete** twenty-row HUMAN attention JSON, CSV,
   or a **scriptless, CSP-restricted printable HTML** brief. All filtered
   original steps remain in every complete export, and no freeform
   client/source data is ever loaded.

**New: exact-marker-bound resume.** Complete JSON proposal exports now use
`lightup.private.human-lab-attention.v2` and include source-free
fixed-enum marker signatures of each operator-selected round. Open the
**same 1–8 original source-free HUMAN route files in the same manually
chosen order**, then use **Reopen source-matched HUMAN proposal (JSON)**.
The browser strictly rejects unknown schema, duplicate decoded JSON keys,
wrong original 20-row sequence, unknown reviewer/follow-up category,
authority claims, changed round markers/transition counts or wrong
source-free round count before applying any selections. Only after a
HUMAN confirmation will all twenty role/follow-up proposals be restored
as one in-memory operation. Legacy unsigned v1 proposals without these
profiles are not silently promoted. This only checks fixed HUMAN marker
continuity, not source file authenticity, actor identity or chronology.

The role and follow-up selectors are **proposal annotations only**:
unassigned/unclassified by default; no identity, real recipient,
deadline, priority claim, assignment, notification, external request
or action-time consent is established. No input is persistently stored
by the browser. No original lab result, tenant record, finding, scan,
grant, provider/model, server, network, auth session, reviewer identity,
source-note text or private path is accessed.

**Strict release posture:** LightUp remains Incubate M3/M7 · PLAN/LAB ONLY
· DRAFT/HOLD. These self-reports are not original source receipts or
proof of authentic HUMAN review. The original source-owner, independent
security/privacy/browser reviews, exact-head hosted + permanently named
VPS CI, genuine separate current client/operator consent with action-time
revocation, #177/#182/#829 and explicit HUMAN GO remain mandatory before
any main merge, live deployment or real-target assessment.


## NEW · One-file offline HUMAN Lab Route Desk (21 October 2026)

The full [standalone HUMAN Lab Route Desk](human-lab-route-standalone.html)
is a **single HTML file**: no adjacent `human-lab-route.js` file required.
It retains all twenty original source-free HUMAN discussion statuses (52–71),
local plan import/export, side-by-side comparison, 2–8 manually ordered HUMAN
rounds, next-round proposals, filters and print-only HUMAN briefings.
There is no network, browser persistence, original evidence ingestion, target
contact, scan, grant, source verification, recipient dispatch or activation.

The standalone file is generated from the **existing** two-file editor without
forking its logic. Its inline script is SHA-256 pinned in a restrictive
Content Security Policy; `default-src 'none'` and `connect-src 'none'` remain.
This is an unsigned *software-byte* restriction, **not** an authenticated
publisher signature, verification of actual review or permission to scan.

To rebuild locally from an approved checkout using Python stdlib (no QA or
network involved):

```bash
python3 assessment-integrated-suite/build_route_standalone.py \
  --output /YOUR-EXISTING-PRIVATE-DIRECTORY/LightUp-HUMAN-Route.html
```

The destination must already exist and the file must **not** exist. The
builder exclusively creates a 0600 local HTML, refuses source/CSP drift,
never overwrites existing output and prints its unsigned SHA-256. If there is
a syntax/source drift error, treat the output as HOLD; do not bypass the
native original validators. Operators can also use the original
[HTML + adjacent JS](human-lab-route.html) unchanged.

`package_offline.py` now packages BOTH options in the next software-only
offline kit. It byte-compares the checked-in standalone against a fresh
source-derived build **before packaging** and fails closed if they disagree.
The linked standalone HTML and updated packager are committed to this
DRAFT/HOLD PR; **no new ZIP release is claimed by this section**.

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** Source-owner and
independent security/privacy/browser review, exact-head hosted and named
permanent VPS CI, current separate authenticated client/operator consent
with action-time revocation, #177/#182/#829 and explicit HUMAN GO remain
prerequisites to any main merge/live release. A discussion marker never
proves execution, finding closure or authorization.


## Offline LAB Desk improvement: strict browser input + useful HUMAN triage (21 Oct)

The previously shipped browser-only HUMAN Lab Route Desk now offers
**separate compare-without-import**, side-by-side action-by-action
current/proposed status display, and a **changed-only source-free CSV**
for HUMAN discussions. A previous local JSON can still be imported,
but *all* 20 source-free entries are first admitted under the exact
native-compatible schema and strict action order, then a complete
per-action before/after preview and explicit human confirmation are
required before any existing in-memory state is replaced.

This update closes the earlier browser-side ambiguity: ordinary
`JSON.parse` silently accepts repeated JSON property names. The
local parser now detects repeated decoded keys even when a key uses
JSON Unicode escapes, including recursively nested `authority`
and each `steps` object. It refuses files exceeding 24 KiB, nesting
beyond 32 containers, unexpected source/authority claims, changed
action IDs, missing fields, or states outside the four HUMAN-only
discussion tokens. The native receiver remains the **independent
required** final private byte admission and no browser import grants
a permission, fixes an issue or proves current review.

The HUMAN Desk also includes instant search for original action number
or title, fixed-state filter, stage-local visible counts, and explicit
confirmation-gated bulk **Needs original input** / **Discussing**
actions for **visible rows only**. There is no bulk approval,
`DISCUSSED`/PASS, grant, dispatch, model, target connection,
source import or persistence. Hidden actions remain in every
complete JSON/CSV export; a changed input or rejected import clears
any stale side-by-side preview. The exported changed-only CSV is a
local HUMAN discussion note, not a source receipt. The independent
native review, present client/operator consent, release and original
mandatory exact-head CI gates remain unchanged.


## LATEST · Portable original HUMAN Lab offline Toolkit v21 · 21 October 2026

[**Download committed v21 software-only ZIP**](LightUp-Assessment-Offline-Toolkit-v21.zip)
([exact committed binary](https://github.com/Zennay/Lightup/commit/f35fdf9169445633afaefdf5724099cfa09f42fe)):
**262304 bytes**, 16 offline HTML HUMAN/lab workrooms with one adjacent
local JavaScript asset and original source-free manifest, README and guide.
Unsigned SHA-256 `113561a28bafc7bd18b4318a51367569043c0dd53317a667fd7f1568e1e9b26a`.
This hash is NOT a signature, authorization or a customer-source receipt.
The actual ZIP byte blob was independently verified against local Git
object `97649e723a5163acad8630cc81d2d27e9d6a4511` before an exact-parent,
non-force GitHub commit to the existing original PR. The prior v20 ZIP remains
historical; **v21 is the current browser-only software package**.

The new accompanying **native-only** original source checkout provides
actions **72 receive, 73 reopen, 74 compare HUMAN rounds, and 75 reopen
the complete saved original HUMAN change history**. Action 75 re-admits
all original owner-private input rooms, regenerates the scriptless
timeline, unresolved HUMAN attention/status stage view and JSON/CSV output,
then refuses any changed, missing or extra saved byte. These are
SOURCE-FREE, HUMAN self-report custody tools, not approved assessments,
identity proof, actual fixes, grant, scan, dispatch, consent or release.
Native Python is deliberately excluded from the portable ZIP.

**REVIEW_ONLY / DRAFT/HOLD — INCUBATE M3/M7 PLAN/LAB ONLY.**
No main merge or deployment; original exact-head named VPS+hosted CI,
source-owner/independent security/privacy/browser review, current separate
authenticated client/operator consent with action-time revocation, and
explicit HUMAN GO remain mandatory.


## CURRENT · Portable offline HUMAN toolkit v20 · 21 October 2026

[**Open/download complete source-only offline ZIP v20**](LightUp-Assessment-Offline-Toolkit-v20.zip)
— **262150 bytes**, **16 offline HTML workrooms and one adjacent local
JavaScript asset**, plus README, guide and unsigned software-only manifest.
The exact archive is [committed to this existing PR](https://github.com/Zennay/Lightup/commit/2a560ca9cd0696d6284386d710571fefbb36559a).
Unsigned ZIP SHA-256: `a3c9f5d2f4a30d54c691500d499f805d6d7ab95834fc41eed07b92c83023f56b`.
Checksums are for byte integrity only, NOT software signing,
source authentication, consent, review, or release permission.

The bundle includes a complete local-human Lab Route Desk
(`studios/human-lab-route.html` and adjacent `studios/human-lab-route.js`)
for twenty original actions (52–71), plus the fifteen other original
offline HTML HUMAN workrooms. The new **native-only** standalone receiver
and interactive console actions 72–74 receive the JSON exported by that
browser, reopen all saved private bytes, and compare up to eight
operator-ordered review rounds, with latest HUMAN attention and phase
counts. Those native Python actions are deliberately *not* in the
browser-only ZIP; use the original approved code checkout.
Review state is never verified task execution or security remediation.

Keep downloaded local files and all generated PRIVATE reports off public
servers. No original customer source, scan, grant, authorized target,
consent, live model, task dispatch, production release or user identity
is included. All original mandatory gates remain DRAFT/HOLD.


## NEW · Native HUMAN Lab self-report custody, exact receipt and history (options 72–75)

**Actual original installed code:** [`lab_route_handoff.py`](lab_route_handoff.py)
and [`lab_route_handoff_console.py`](lab_route_handoff_console.py).
Existing actions **1–71 remain unchanged**; the integrated foreground
`console.py` now offers **72 receive**, **73 reopen**,
**74 compare HUMAN discussion rounds**, and **75 reopen exact history**. These are an isolated completion
of the previously delivered source-free browser plan, **not**
original lab-source verification, an assessment executor, or a release.

**Browser-to-native workflow:** save
[`human-lab-route.html`](human-lab-route.html) with adjacent
[`human-lab-route.js`](human-lab-route.js), mark local HUMAN
discussion statuses, then explicitly request JSON export. Copy the
downloaded file into an existing **0700 owner-only directory**, with
**0600 file** permissions, OUTSIDE any source checkout. Start
`python3 assessment-integrated-suite/console.py` on the approved
local system and choose **72**; provide the absolute private JSON
path, a separate owner-only 0700 destination and a new unique
folder name. Confirm with exactly `RECEIVE HUMAN SELF REPORT`.
The original source-free twenty-option self-report must match
the strict original schema, order, fixed stage tokens, literal
boolean false authority fields, and size at most 24576 bytes.
Duplicate JSON properties at ANY depth are refused. No partial
artifacts are emitted on preflight failure. The output is a
new **0700 PRIVATE** room with an original **0600** self-report,
a canonical full JSON copy, complete CSV, script-free HTML
and a distinct unsigned SHA-256 byte receipt.

**73:** Read-only exact re-admission of all previously written
original private bytes, regenerated from the saved original
browser self-report; missing, changed or unexpected files HOLD.
A matching unsigned receipt is only byte continuity, NEVER
real actor authentication or external source authenticity.
**74:** choose 2–8 saved original HUMAN receipt room paths in
explicit MANUAL order; each is fully re-admitted. In a NEW
owner-private room obtain a scriptless HUMAN change timeline,
counts-per-self-reported-round JSON and complete CSV of changed
option markers. It also produces a current **HUMAN attention board**,
per-stage NEEDS_INPUT / Discussing / Not reviewed / Discussed-only counts,
and a separate complete `PRIVATE-HUMAN-ATTENTION.csv` with original
fixed action captions and the number of consecutive OPERATOR-ORDERED
rounds holding the same declared status. These are human discussion
prompts, not verified task age, ownership, deadlines or actual fixes.
The chosen order is NOT a proven timeline and a
status change is NOT an assessment or verified remediation.

**75:** read-only **full history reopening** requires the same 2–8 original
HUMAN receipt rooms and the saved PRIVATE history room. It rebuilds
all source-free derived HTML/JSON/CSV and the history receipt from
original private inputs; even one altered source/output byte forces HOLD.
History output cannot reside inside original input rooms. The receipt
never establishes verified chronology, authentic actors or remediation.

For direct opt-in use outside the operator menu:
`python3 assessment-integrated-suite/lab_route_handoff.py receive --self-report /PRIVATE/input.json --private-parent /PRIVATE --folder receipt-1`;
`python3 assessment-integrated-suite/lab_route_handoff.py reopen --room /PRIVATE/receipt-1`;
`python3 assessment-integrated-suite/lab_route_handoff.py history --rooms /PRIVATE/receipt-1 /PRIVATE/receipt-2 --private-parent /PRIVATE --folder history-1`.
To reopen that history without modifying the original files:
`python3 assessment-integrated-suite/lab_route_handoff.py reopen-history --rooms /PRIVATE/receipt-1 /PRIVATE/receipt-2 --history-room /PRIVATE/history-1`.
Paths are examples ONLY, and must already be owner-private on the
operator's local filesystem. No original customer record or true
scan, consent, grant, release or HUMAN GO is created or inferred.
These native-only features are deliberately excluded from the
source-only portable HTML/JS ZIP; they require an approved
original checkout and manual private custody. No QA/test suites
were added or invoked.


## NEW · Source-free offline HUMAN Lab Route Desk (20 original actions)

[Open the portable HUMAN Lab Route Desk](human-lab-route.html) beside
[its local JavaScript](human-lab-route.js). This is a usable, accessible,
private **discussion workplan**, not a scan or an execution interface.
The same two assets are copied together under `workrooms/` in the native
PRIVATE Assessment Kit and `studios/` in the portable software-only ZIP.
They must remain **next to each other** for the local browser UI to run.
No internet, browser storage, cookies, server, source-file import, grant,
model, scanner, task dispatch or remote action is used.

**Practical operator workflow:** from an approved original checkout run
`python3 assessment-integrated-suite/console.py`, enter **LAB** for the
5-stage source-bound operator guide, and pick a numeric 52–71 action **only
when its original source and private output requirements exist**. Use
the browser Route Desk to mark *discussion-only* states: Not reviewed,
Discussing, Needs original input, or Discussed only. The desk never
infers completion, source authenticity, consent or release from these.
Original native output lives in independent 0700/0600 directories.
Browser self-report files contain only 20 numeric action IDs, four fixed
status literals and all false authority flags — no source paths, target
IDs, private questions or freeform input.

Export the local **self-report JSON** for later bounded local import or
the minimal **CSV** for a human meeting. After browser download, check
that the output was actually saved in private custody; downloads can
fail or be cancelled. The complete JSON importer rejects oversize files,
missing/reordered action IDs, unknown state values, unexpected fields
and claimed authority before replacing in-memory markers, then requires
explicit human confirmation. No old state is silently persisted.

**Important distinction:** Discussed only ≠ original workflow executed
≠ verified finding ≠ human review signoff ≠ authentic client/operator
authorization. Native original action 57 / subsequent HUMAN finalization
remains separate, and the original release gates remain HOLD. This
offline workstation and its unsigned discussion export must never be
used as evidence of actual scan, approval, vulnerability closure or
permission to touch a target. Do not upload private source files.


## New offline software-only Toolkit v17 · native Lab HUMAN guide

[Open source-only Toolkit v17](LightUp-Assessment-Offline-Toolkit-v17.zip).
The ZIP contains **15 unchanged original offline browser studios**,
a locally navigable entry, README, a newly bundled complete
[Lab Planning → source-bound HUMAN review guide](LAB-PLANNING.md),
and a byte-digest manifest for both original software and guide.
No private generated HUMAN decisions, source packets, local session,
customer evidence or native Python executable is included. Native
console actions **52–58** and strict original source-owner review still
require an authorized trusted checkout and owner-only 0700/0600 custody.
This is unsigned original software, **not** authenticated release/consent.


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

## NEW: original Lab HUMAN review history and team feedback (console 59–61)

See [the complete PRIVATE original Lab HUMAN operator journey](LAB-HUMAN-CONTINUITY.md).
New **59** compares 2–8 distinct original finalized HUMAN review rooms against
the same original source-owning Lab Launchpad packets, showing exact declared
stage/team transitions, continuous HUMAN HOLD/NEEDS_INPUT and
private-question-changed flags, never original free-text question content or
lab URLs. New **60** prepares private **team-only** scriptless workrooms plus
separately editable source-bound 0600 HUMAN CSV per manually assigned team,
and a local operator-only directory. New **61** admits exactly one assigned
team's 0600 returned CSV after re-admitting the original Lab Launchpad
source/Studio, FINAL HUMAN rows and strict handoff manifest. Its full
PRIVATE HUMAN candidate may be manually reopened in existing **58** for
subsequent deliberate review; original FINAL state and other teams remain
unchanged. No recipient authenticated, no silent auto-merge, scan, grant,
incident verification, client permission, network, model, real appointment,
deployment, source-owner acceptance, independent privacy/security/browser
approval or HUMAN GO implied. Original 0700/0600 custody mandatory.

## NEW: original-policy Lab Launchpad integrated into the foreground console

**Original source-owner feature issue #1633 / PR #1634, without duplicating
or modifying its source files.** Original `assessment-launchpad/build.py`,
`reopen.py` and `compare.py` are directly available in the integrated
assessment operator console:

- **52 — PREPARE PRIVATE LAB PLAN**: choose an already exported original
  owner-only 0600 `targets.txt` with explicit literal isolated HTTP(S)
  addresses, optionally an original 0600 Studio catalog/selected scenario;
  select an existing 0700 PRIVATE parent and an unused folder. The wrapper
  delegates to the ORIGINAL `LabScenario` and `_admit_explicit_lab_url`
  checks before publishing exact original 0700/0600 source-bound Lab Launchpad
  artifacts and local scriptless HTML.
- **53 — REOPEN PRIVATE LAB PLAN**: original source owner reopens its packet
  with strict exact file/manifest hashes, original Studio source and original
  scope; only returns an owner-private original local preview. An unchanged
  hash is never proof of original customer permission.
- **54 — COMPARE PRIVATE LAB PLANS**: use the original source owner to
  re-admit both original offline proposals before creating its own separate
  PRIVATE human-only revision brief. A missing proposed URL is NOT proof of
  remediation, deletion, revocation or a changed client engagement.
- **55 — BUILD PRIVATE LAB PORTFOLIO**: new additive
  `lab_plan_portfolio.py` composes **3–8 original** original-owner-admitted
  packets in HUMAN-declared order. Every original packet's source files,
  Studio binding and scope policy are independently re-opened through
  the installed source owner reader; exact duplicate declared packet identities
  fail closed. The new independent 0700/0600 PRIVATE room offers a
  **scriptless interactive-details** HTML portfolio with every source
  proposal and adjacent added/absent/retained literal URL sets, plus
  `PRIVATE-LAB-PROPOSALS.json` and source-free
  `PRIVATE-ANONYMOUS-COUNTS.json`.

Native noninteractive entry points use
`python3 assessment-integrated-suite/lab_plans.py prepare|reopen|compare|portfolio`
and exact explicit `--human-confirm` strings. All original packet paths,
input files, output destinations and private Studio files must be owner-controlled
0700/0600 outside the repository; outputs cannot overwrite any prior room.
The original no-work preview command is merely TEXT in the original
Launchpad file; **never executed** by this integration. The original
source owner routines return review-only status 2, and admission/HOLD is 3;
the wrappers do not reinterpret that as authorized execution.

No DNS resolution, live targets, scans, model, provider requests, action-time
grants, permissions, real deployment, authenticated actor, risk ranking,
security findings or client-to-client identity join. Before anything active,
all original CI/independent source-owner/privacy/security/browser review,
#177/#182/#829, separate authenticated client and operator consent,
action-time revocation and explicit HUMAN GO still apply. DRAFT/HOLD,
INCUBATE M3/M7 PLAN/LAB ONLY.

## NEW: searchable original assessment console without scrolling 51 actions

The original interactive `console.py` has 51 native original workflows.
It now opens with a compact eight-category HUMAN navigator instead of
printing an overwhelming 51-line action list on every screen. All **original
numeric IDs and source owner handlers remain exactly unchanged**. Operators
can type a number directly, `ALL` to inspect every exact original action,
`?benchmark`, `?workpack`, `?private` or other bounded local substring
search and choose an exact matching action number, or `HELP` for an original
HUMAN workpack 37 → 49 → 50 → 51 walkthrough. None of these navigation
commands open original evidence or call an action: execution still requires
selecting one original numeric action and satisfying all its existing
confirmation, local owner-private source admission and review gates.
A blank prompt keeps the original no-action exit behavior.

## NEW: offline interactive HUMAN Progress Cockpit

The original native `workpack-progress` and console 50 now produce a real
offline HTML **Progress Cockpit** rather than only a static report. It shows
the first-vs-latest state of **every** original HUMAN workflow, counts for
the manually selected latest snapshot, all assigned-team workload and
historical declared transitions. Search by original workflow key/title or
declared review date; filter by exact HUMAN stage, team, still-declared
attention or changed-since-first, and reset without ever mutating a row.
The latest HUMAN HOLD/NEEDS_INPUT streaks are displayed separately.
The cockpit now also compares adjacent declared snapshots as a source-free
HUMAN stage/team movement matrix (newly marked, no-longer-marked and still
marked HOLD/NEEDS_INPUT, HUMAN question edits without question text).
The new owner-private 0600 `PRIVATE-HUMAN-STAGE-MOVEMENT.csv` supports
deliberate offline HUMAN coordination without opening original evidence.
Exact byte-identical copied snapshot/date pairs are rejected as repeated,
not double-counted HUMAN review moments. None of these counts proves a
real incident, a fix, a security result or genuine chronology.

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
against exact original pinned rows. New HUMAN workpacks also write a native
**v2 receipt** with the unsigned exact pinned 0600 CSV byte length and SHA-256.
Progress comparison and continuation require the pinned original bytes to
match the v2 declaration before using their HUMAN decisions. Pre-existing
original v1 workpacks remain explicitly readable under their original
weaker (session/row/count bound, but no receipt digest) acceptance contract;
they are never silently upgraded or called authenticated. The previous workpack cannot be the new
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

## Portable 15-original-studio software kit v16

[Offline LightUp Assessment Toolkit v16](LightUp-Assessment-Offline-Toolkit-v16.zip)
contains the original 15 unchanged standalone offline HUMAN browser studios
and a refreshed software-only operator guide. The new guided native 51-action
console, source-bound workpack continuation, v2 pinned CSV receipt integrity
and offline filtered PRIVATE Progress Cockpit are explicitly described but
**remain native-only**: no generated client data, original PRIVATE session,
private CSV/workpack, authentic grant, or executable native Python is in this
public browser software package. Unsigned local file digests cannot prove
release authenticity or operator/client consent.

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

The output and adjacent `.sha256` sidecar must not already exist. Before
the ZIP is retained, the builder runs the native offline verifier against the
completed archive and the same checkout's source-bound software files. Missing,
changed or stale source files cause HOLD and the incomplete output is removed.
It then creates an exclusive mode-0600 sha256sum sidecar. Verify the ZIP with
`--sha256-file /path/to/NEW-software-only-kit.zip.sha256`; a sidecar delivered
with its ZIP is a convenience copy, not an independent trust anchor. This is a
package-integrity step, not source authenticity or release approval. The command
reads a fixed source-only list and cannot invoke any scan, model, network,
customer ingestion or auto-publish.

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

## Original multi-team HUMAN Lab return → one complete PRIVATE candidate (option 62)

Instead of hand-merging separately reviewed team drafts, the operator can
now admit **1–4 distinct, original assigned HUMAN team** replies together.
First prepare the original FINAL HUMAN Lab result (option 57) and the original
source-bound team workroom (option 60). Edit each team's full seven-column
PRIVATE response CSV offline, stored owner-only 0600 in its own trusted room.
Then choose **option 62** or use the native command:

```bash
python3 assessment-integrated-suite/lab_review_team_batch.py \
  --packet ORIGINAL_LAUNCHPAD_0700 \
  --final-room ORIGINAL_FINAL_0700 \
  --handoff-room ORIGINAL_TEAM_HANDOFF_0700 \
  --team-return 'Security=/OWNER_PRIVATE/security.csv' \
  --team-return 'Privacy=/OWNER_PRIVATE/privacy.csv' \
  --private-parent ORIGINAL_PRIVATE_PARENT_0700 \
  --folder NEW-PRIVATE-HUMAN-BATCH \
  --human-confirm 'ADMIT MULTIPLE PRIVATE LAB TEAM RETURNS'
```

Strict original source admission reopens original Launchpad packets, source-bound
FINAL HUMAN result, complete original team handoff, original assigned team
CSV bytes and every separate response. Duplicate teams, unassigned teams,
missing/reordered rows, unbounded private questions or changed original source
identity cause a complete HOLD before output creation. A HUMAN batch is
**not** an independently authenticated recipient or reviewer.

One new exclusive 0700 room contains four owner-0600 artifacts:
`OPEN-PRIVATE.html` (scriptless stage/ordinal review without private questions),
`PRIVATE-HUMAN-CANDIDATE.csv` (the FULL original seven-column order with
only assigned selected team decisions replaced),
`PRIVATE-HUMAN-MULTITEAM-DIFF.csv` (ordinal/team/stage and private-question
change Boolean, no question content), and
`PRIVATE-HUMAN-MULTITEAM-RECEIPT.json` (private unsigned original source
fingerprint and all authority flags false). Unreturned teams remain unchanged:
**absence is not consent or approval. The PRIVATE HTML explicitly lists each originally assigned team without a response and its unchanged HUMAN task count; the unsigned PRIVATE receipt separately records these omitted team slots**. The native original HUMAN Studio
option 58 must be used for fresh manual finalization. No automatic task send,
scan, auth, lab action, grant, source approval or deploy occurs.

Incubate M3/M7 PLAN/LAB ONLY DRAFT/HOLD; original CI, independent security,
privacy, source-owner/browser review, real separately authenticated current
client/operator consent and at-action revocation, #177/#182/#829 and HUMAN GO
remain mandatory. No QA/tests/real client data.

## NEW: deliberately withhold returned team edits (option 62)

The original 1–4 team return import remains original-source-admitted. After each
complete PRIVATE CSV is selected, the foreground operator now chooses
**yes/no per team** whether to include that team's edits in the NEW unfinalized
HUMAN candidate. Default is **no**. A separate `--withhold-team 'Privacy'`
(repeatable) in native `lab_review_team_batch.py` implements the same
source-checked withholding. Every returned team is still admitted against
the exact original Launchpad source, finalized HUMAN review and original
team handoff. Refusing/withholding any team never waives source validation.

- **Included response:** existing original HUMAN team/source/ordinal positions
  are copied into a complete seven-column draft, without automatic FINALIZE.
- **Returned but withheld:** all original decisions remain unchanged in the
  candidate. The 0600 scriptless operator page visibly distinguishes withheld
  replies from teams that never returned; neither implies approval.
- **Not returned:** original rows remain unchanged, with no implied consent.

The output now contains an additional owner-0600
`PRIVATE-HUMAN-WITHHELD-DIFF.csv` of **source ordinal, HUMAN team, old/new
stage and private-question-changed Boolean only**. Human private question
text never enters the HTML or either diff. The PRIVATE receipt records the
deliberately withheld source team's counts separately, and exact SHA-256
of every created PRIVATE report byte. **These hashes are unsigned local
integrity checks and do not prove actor identity or authorization.**

## NEW: reopen saved original multi-team proposal, source-bound (option 63)

```bash
python3 assessment-integrated-suite/lab_review_team_batch_reopen.py \
  --packet ORIGINAL_LAUNCHPAD_0700 \
  --final-room ORIGINAL_FINAL_0700 \
  --handoff-room ORIGINAL_TEAM_HANDOFF_0700 \
  --batch-room EXISTING_MULTI_TEAM_BATCH_0700 \
  --human-confirm 'REOPEN ORIGINAL PRIVATE LAB TEAM BATCH'
```

The read-only offline original-source reopener checks the **unchanged original**
Launchpad packets, exact original FINAL HUMAN rows and team handoff again;
requires original owner-only 0700 directory and direct 0600 single-linked
files; rejects duplicate receipt JSON keys and wrong authority flags through
the existing original strict native receipt reader; admits all four existing
PRIVATE output file descriptors and SHA byte inventory. The complete candidate
CSV is revalidated against original source ordinals, team assignments and
HUMAN stage/question schema. It recomputes included original stage/question
changes, distinguishes deliberately withheld from never-returned teams, and
checks the stage/ordinal diff and receipt counts before printing a minimal
PRIVATE REVIEW_ONLY summary. Nothing is regenerated or silently finalized;
if the original source is missing or any receipt or output file changed, it
returns HOLD instead of claiming success.

No target, browser-network, model, scan, callback, credentials, grant, sending
or production activation. Existing M3/M7 PLAN/LAB ONLY DRAFT/HOLD, original
exact-head named-VPS + hosted CI, source-owner and independent security/
privacy/browser review, authenticated current separate client/operator
consent with revocation-at-use, #177/#182/#829 and explicit HUMAN GO gates
remain in force. No QA/regression/test suites have been added or run.

## NEW: source-rechecked multi-team HUMAN Lab proposal history (option 64)

When team replies arrive across several separate, not-yet-finalized private
operator rounds, choose foreground console **64** to compare **2–8 distinct
saved original PRIVATE multi-team batch rooms** in operator-specified order.
Every source and every saved room must still be available and pass the
**original** source-bound multi-team reopener (option 63). Unavailable, modified,
not privately owned or mismatched source files yield HOLD and no new history.

```bash
python3 assessment-integrated-suite/lab_review_team_batch_history.py \
  --packet ORIGINAL_LAUNCHPAD_0700 \
  --final-room ORIGINAL_FINAL_0700 \
  --handoff-room ORIGINAL_TEAM_HANDOFF_0700 \
  --batch-room ROUND_A_0700 --batch-room ROUND_B_0700 \
  --private-parent OWNER_PRIVATE_PARENT_0700 \
  --folder NEW-HUMAN-BATCH-HISTORY \
  --human-confirm 'BUILD PRIVATE LAB TEAM BATCH HISTORY'
```

The new exclusive 0700 folder contains an owner-0600
`OPEN-PRIVATE.html` scriptless HUMAN timeline of stage distributions,
**human team adopted/withheld/no-response transitions** (including each
originally assigned team with no reply in every saved round, not just
teams that responded in one of the rounds) and stage/question
changes per original ordinal, plus the source-minimized
`PRIVATE-HUMAN-BATCH-HISTORY.json` and
`PRIVATE-HUMAN-BATCH-CHANGES.csv` (ordinal/team/stage + Boolean only,
never private question text), and a distinct `PRIVATE-HUMAN-TEAM-TRANSITIONS.csv`
(operator positions, HUMAN team, previous/next manually declared inclusion
or withholding). All remain owner-0600 and unsigned.
No source URLs, client name, source paths,
SHA, credentials or original lab targets are copied into these reports.
Rounds are explicitly **operator-supplied positions**, not verified
real chronology or proof that a finding was resolved. Future human
finalization still requires unchanged original Studio, current authentic
source/consent and original mandatory review/CI/HUMAN GO gates.

This is a self-contained useful offline HUMAN workflow, **not** a release,
security attestation, activity timeline, automatic notification, client
approval, asset ownership proof or authority to scan. Existing Incubate
M3/M7 DRAFT/HOLD remains; no QA/regression/test suites authored or run.

## New original HUMAN Lab team **continuation** (console 65)

The previously shipped team batch (option 62) creates a private unfinalized
candidate from an unchanged ORIGINAL FINAL HUMAN review. Later arriving team
replies must **not** accidentally discard already saved decisions. The new
[original source-bound continuation](lab_review_team_continue.py) (operator
console **65**) uses the *complete previously saved private candidate* as
the starting point. It re-admits **the original packet source, FINAL HUMAN
result, original team handoff, original batch and every new returned team CSV**
before creating anything.

For each returned team, a HUMAN operator decides yes/no whether its entire
reply may enter a new unfinalized candidate (default **NO**). A reply that
would alter **any HUMAN stage or private question already changed in a previous
round** is **automatically withheld for its whole team**, even when marked yes.
Earlier decisions survive; no partial team adoption. Original team ordinals
and the complete seven-column HUMAN CSV order remain unchanged. Teams without
a fresh response also keep their previously saved decisions; **none is treated
as consent or implicit resolution**.

The continuation emits a **new** exclusive 0700 output room containing exactly
five new owner-0600 artifacts:

- `OPEN-PRIVATE.html`: original-ordinal/stage-only and team outcome/withheld
  conflict summary, CSP scriptless, no private question text.
- `PRIVATE-HUMAN-CONTINUED-CANDIDATE.csv`: complete original source-ordinal
  HUMAN candidate with earlier non-conflicting decisions preserved.
- `PRIVATE-HUMAN-CONTINUED-CHANGES.csv`: accepted new stage/ordinal changes
  plus private-question-changed Boolean, **no free text**.
- `PRIVATE-HUMAN-PROTECTED-CONFLICTS.csv`: deliberately withheld overlaps,
  again private-question Boolean only.
- `PRIVATE-HUMAN-CONTINUATION-RECEIPT.json`: all authority flags false,
  explicit source SHA **unsigned**, exact previous receipt and previous
  candidate SHA (unsigned local continuity checks), team disposition counts,
  mandatory manual finalize flag, and hashes of all private output bytes.

Standalone foreground CLI for the **first** continuation:

```bash
python3 assessment-integrated-suite/lab_review_team_continue.py \
  --packet ORIGINAL_PRIVATE_LAUNCHPAD_0700 \
  --final-room ORIGINAL_FINAL_HUMAN_0700 \
  --handoff-room ORIGINAL_TEAM_HANDOFF_0700 \
  --prior-batch EXISTING_SOURCE_BOUND_TEAM_BATCH_0700 \
  --team-return 'Security=/OWNER_PRIVATE/security-return.csv' \
  --private-parent EXISTING_OWNER_0700_PARENT \
  --folder NEW-PRIVATE-LAB-HUMAN-CONTINUATION \
  --human-confirm 'CONTINUE PRIVATE LAB HUMAN BATCH'
```

Repeat `--team-return TEAM=PRIVATE_CSV` for at most four separate original teams.
Optional repeatable `--withhold-team 'Security'` excludes selected sources
after admitting them, instead of silently omitting source validation. The
console asks per team and defaults to NO.

For later HUMAN rounds, pass 1–6 prior PRIVATE continuation rooms *in exact
operator-declared order* with `--prior-continuation PRIOR_0700_ROOM`. The entire
unchanged original root batch and complete ordered prior chain are re-admitted;
the newest admitted candidate becomes the starting point. Maximum chain depth
is intentionally bounded. **Operator order is not verified calendar time**.

## Reopen chained HUMAN Lab decisions read-only (console 66)

```bash
python3 assessment-integrated-suite/lab_review_team_continue_reopen.py \
  --packet ORIGINAL_PRIVATE_LAUNCHPAD_0700 \
  --final-room ORIGINAL_FINAL_HUMAN_0700 \
  --handoff-room ORIGINAL_TEAM_HANDOFF_0700 \
  --prior-batch ORIGINAL_PRIVATE_TEAM_BATCH_0700 \
  --prior-continuation OPTIONAL_EARLIER_CONTINUATION_0700 \
  --continued-room CURRENT_CONTINUATION_0700 \
  --human-confirm 'REOPEN PRIVATE LAB HUMAN CONTINUATION'
```

The `--prior-continuation` parameter is omitted for the first round.
For later rounds repeat it for all earlier saved private continuation rooms,
oldest first. The read-only native reopener checks every original source,
team assignment and 0600 original/private descriptor; re-admits the entire
ordered previous chain and candidate; verifies original source-bound HUMAN
stage/ordinal/team continuity, complete candidate and accepted change CSV,
withheld conflict ordinals, every file's unsigned exact-byte digest and the
previous candidate/receipt SHA. Existing files remain unchanged; any missing
or different source returns **HOLD** rather than creating a new report.

These tools handle only **original offline HUMAN Lab proposals**, not real
assessments, verified incident remediation, authenticated recipient consent,
security approvals, scanning, grants, scheduling, network transfer or releases.
Notion LightUp is **INCUBATE M3/M7 PLAN/LAB ONLY, DRAFT/HOLD**. Original
hosted + permanently named VPS exact-head CI, source-owner, independent
security/privacy/browser review, #177/#182/#829, separately authenticated
current client+operator consent with at-use revocation and explicit HUMAN GO
remain prerequisites for any `main` merge or live deployment. No QA suites
were added or run.

## NEW: original HUMAN Lab continuity dashboard (console 67)

[Native source-bound continuation history](lab_review_team_continuation_history.py)
combines **one original saved HUMAN batch plus 1–7 later PRIVATE original
continuations** in operator-supplied order. Each previous 0700/0600 source,
original Lab packet, original FINAL HUMAN review, assigned team receipt,
complete candidate/diff and entire unsigned previous lineage must pass the
existing native source re-openers; no source history may be skipped, repeated
or nested into a new output.

```bash
python3 assessment-integrated-suite/lab_review_team_continuation_history.py \
  --packet ORIGINAL_PRIVATE_LAB_LAUNCHPAD_0700 \
  --final-room ORIGINAL_FINAL_HUMAN_0700 \
  --handoff-room ORIGINAL_TEAM_HANDOFF_0700 \
  --root-batch ORIGINAL_MULTI_TEAM_BATCH_0700 \
  --continuation-room FIRST_SAVED_CONTINUATION_0700 \
  --continuation-room NEXT_SAVED_CONTINUATION_0700 \
  --private-parent OWNER_PRIVATE_0700_PARENT \
  --folder NEW-PRIVATE-HUMAN-CONTINUITY-HISTORY \
  --human-confirm 'BUILD ORIGINAL PRIVATE HUMAN CONTINUATION HISTORY'
```

The separately created 0700 PRIVATE result includes 0600 scriptless
`OPEN-PRIVATE.html` grouped by original HUMAN stage and team, original
ordinal-by-ordinal stage and private-question-*changed* Booleans, and
adopted/withheld/conflict/not-returned team disposition transitions. Three
additional 0600 files provide original source-minimal JSON, stage-change CSV
and team-transition CSV for deliberate HUMAN local handoff. Earlier
unanswered teams are explicitly preserved with the correct original assigned
workload. **No question text, original lab URLs, source paths, source hashes,
credentials or client source contents are in these summary artifacts.**

The operator-provided order is not verified chronology; stage changes are
not verified fixes. No original review is overwritten; this historical
companion cannot authorize, contact, scan, finalize, release or infer current
consent. The original M3/M7 DRAFT/HOLD, named permanent VPS + hosted exact-head
CI, source-owner and independent security/privacy/browser reviews,
#177/#182/#829, separately authenticated current client/operator consent
with at-use revocation and explicit HUMAN GO remain mandatory.

## NEW: source-bound PRIVATE per-original-ordinal HUMAN conflict Studio (console 68–71)

When the existing source-bound HUMAN Lab continuation (option 65) withholds an
entire team's new reply because any HUMAN stage or question conflicts with an
earlier stored HUMAN decision, the owner can now **deliberately select individual
original ordinal changes**. Nothing silently replaces a previous HUMAN choice.
This is a local follow-up proposal, **not** a consent, source authentication,
privileged security activity, approval or PASS.

**68 — Prepare exact-original conflict choices.** Select 3–8 ORIGINAL
owner-0700 Launchpad packets, the unchanged original FINAL HUMAN review,
the original team handoff, one original PRIVATE batch, optionally up to six
previous saved PRIVATE continuation rooms in order, and 1–4 complete
owner-0600 returned team CSVs. Every original source, earlier HUMAN candidate,
each assigned-team handoff and complete returned HUMAN CSV is freshly
re-admitted before a new 0700 room is created. The room contains original
owner-0600 `OPEN-PRIVATE.html` (scriptless overview),
**`EDIT-PRIVATE.html` (a real keyboard-accessible source-bound browser
choice editor)**, `PRIVATE-HUMAN-CHOICES.csv` and an unsigned
`PRIVATE-HUMAN-DECISIONS-RECEIPT.json` with 0600 exact artifact digests.
Every original ordinal defaults to **KEEP_PREVIOUS**.

Open `EDIT-PRIVATE.html` locally on a trusted offline device. It provides
independent per-ordinal checkboxes, previous/returned HUMAN stage, assigned
team and whether the confidential HUMAN question differs. It now includes
source-minimal original team/stage/changed-question/ordinal filters,
bounded in-memory undo/redo (25 snapshots) and deliberate KEEP/APPLY actions
limited to CURRENTLY VISIBLE filtered rows; bulk APPLY explicitly confirms.
**The complete CSV still includes all original source-bound positions**,
even if filtered out of view, so hidden rows cannot be dropped or rewritten
by a filtered export. No source
findings, client identities, original target URLs or private question text
are embedded. **The PRIVATE HTML itself does include unsigned source and
previous candidate SHA bindings within its data-only rows**, necessary
to export the complete original-native source-bound CSV: keep the page
confidential. The browser JavaScript is SHA-256 CSP-pinned, with
`connect-src 'none'`; no remote calls, cookies, localStorage, IndexedDB,
service workers, scanners, models or network action. The editor never
automatically downloads or exports by merely opening the page: only
an explicit operator click exports the *entire* original row set.
Do not assume browser downloads are PRIVATE: deliberately save the completed
CSV into an **existing trusted owner-only 0700 directory with exact 0600 file
mode** before continuing. No other CSV column may be edited.

**69 — Publish only explicitly selected HUMAN choices.** Supply the EXACT
same original packet/FINAL/handoff/batch/continuation/team return sources,
the 0700 original choice preparation room, the completed owner-0600 HUMAN
choices CSV, and a NEW unused PRIVATE 0700 destination. The native producer
recomputes original source/previous candidate SHA, requires the unchanged
full original choice rows and strict duplicate-key-rejecting receipt with
all authority flags false, rechecks source-bound original editor/CSV/HTML
file hashes, exact original ordinal/team/previous/proposed stage and
HUMAN question-changed Boolean, and accepts only
`KEEP_PREVIOUS` or `APPLY_RETURN`. At least one deliberate APPLY is required.
It creates a separate owner-0600 `OPEN-PRIVATE.html`,
`PRIVATE-HUMAN-RESOLVED-CANDIDATE.csv` (complete original five-column
HUMAN Lab Review rows, **not** a grant),
`PRIVATE-HUMAN-FINAL-CHOICES.csv` and unsigned
`PRIVATE-HUMAN-RESOLUTION-RECEIPT.json`. Original source and earlier
PRIVATE HUMAN candidate bytes are untouched. No automatic FINALIZE.

**70 — Reopen the published original-human resolution READ ONLY.**
Reconstruct the complete result from unchanged original packets, original
human FINAL, team handoff, previous HUMAN batches and full returned team CSVs,
the original choice preparation room, and the separately saved resolution.
It checks the complete exact-byte receipt inventory and recomputes
the original source-bound full HUMAN result from only deliberate APPLY rows.
Missing/modified source/receipt/CSV or ordinal decisions means **HOLD**, not
PASS, not release, and does not modify any prior room.

**71 — Open the resolved HUMAN draft in the unchanged ORIGINAL native Lab
Review Studio.** After #70's full exact-source admission, explicitly supply
the original owner-0700 Lab Review Studio source room (created by original
option 56), and a new PRIVATE 0700 output parent/unused name. Native
`lab_plan_review.prepare(..., prior_room=original_review,
prior_csv=PRIVATE-HUMAN-RESOLVED-CANDIDATE.csv)` re-admits the ORIGINAL
source-owned HUMAN Studio receipt and selected original-complete CSV.
This creates a new editable source-bound HUMAN Studio, with original
manual FINALIZE as a **separate later decision**. No original source owner
files or security/authorization/CI contracts are modified.

All four stages are discoverable in the foreground
`python3 assessment-integrated-suite/console.py` via actions **68–71**
and `?conflict` / `ALL`; the standalone native CLIs
`lab_review_conflict_resolution.py prepare`,
`lab_review_conflict_resolution.py publish`,
`lab_review_conflict_reopen.py` and
`lab_review_conflict_studio.py` remain available for an owner-operated
offline machine. They return REVIEW_ONLY (code 2) and HOLD (code 3),
never verified authority.

**Release state remains INCUBATE M3/M7 PLAN/LAB ONLY DRAFT/HOLD**:
real independently current authenticated client/operator consent and
revocation-at-use, original source-owner and independent privacy/security/
browser review, #177/#182/#829, original exact-head hosted + permanently
registered named VPS CI, explicit HUMAN GO remain mandatory for any main
merge/deploy/real activity. No QA/regression/testsuites, real scans,
grants, recipient transmission or customer evidence performed by this work.

## Local-only HUMAN Lab round comparison (21 October 2026)

The source-only [HUMAN Lab Route Desk](human-lab-route.html) and adjacent
[script](human-lab-route.js) can now display **two to eight independently
exported, operator-ordered local HUMAN discussion self-report JSON files** in
one screen. No installation, backend, login, network, cookies or browser
storage is involved. This comparison is independent of the native 72–75
original PRIVATE HUMAN receipt/reopen/history flows; it does NOT replace
original source admission or validate native receipts.

1. Open `human-lab-route.html` **locally**, with its adjacent original
   `human-lab-route.js`. Export self-report JSON after manual discussion
   rounds, retaining only the fixed original 20 action/status pairs.
2. In **Compare 2–8 separate HUMAN discussion rounds**, choose two through
   eight previously exported self-reports in the intended display order.
   The chooser ordering is **not evidence of actual chronology** or actor
   identity. Each file is admitted against the same bounded original schema:
   24 KiB per report; all original twenty action slots in exact order;
   only four named HUMAN statuses; every authority/source flag exactly false;
   duplicate JSON keys, invalid content and identical repeated reports HOLD.
3. Review the source-free twenty-action matrix and five stage summary rows.
   It shows self-declared status transitions and last-round NEEDS_INPUT counts,
   **never security quality, remediation, verified actions or authority**.
4. Optionally export the minimal status-only CSV for **private local HUMAN
   discussion**; export contains only literal action numbers, four known
   status tokens, proposed chooser order, transition counts and REVIEW_ONLY.
   It contains no original source/target/evidence, identities, file paths,
   timestamps or private notes. Select **Clear compared reports** to remove
   the entire browser-held comparison from memory.

Loading these rounds never edits the active twenty-marker discussion plan.
Invalid replacement selections clear stale comparisons and do not partially
load data. Changing current markers never endorses or imports a prior round.
All data remains self-reported, unsigned and non-authorizing. The original
release controls and explicit HUMAN GO remain separate and mandatory.

## Current HUMAN Route plan: follow-up queue and scriptless brief

The local HUMAN Lab Route Desk now offers two additional source-free exports:

- **Export pending HUMAN follow-up queue (CSV)** lists only current markers that are NEEDS_INPUT, IN_PROGRESS or NOT_REVIEWED, sorted by marker category and then original stage/action order. The order is a discussion aid, not a risk or urgency score.
- **Save scriptless current-plan brief (HTML)** produces a portable no-script/no-network report with five stage counts, the pending discussion queue, and every one of the original twenty action rows.

Both outputs contain only fixed action captions, the four allowed self-reported marker labels and fixed HUMAN next-step prompts. They contain no source findings, targets, private notes, identity, filenames, timestamps or consent. DISCUSSED still means only that a discussion marker was selected; it never means executed, verified, remediated, authorized or released. The HTML is scriptless and CSP-restricted. Keep both exports private; they are unsigned and non-authorizing.

## Explicit all-action HUMAN continuation proposal

The same browser-only local [HUMAN Lab Route Desk](human-lab-route.html)
can turn its 2–8 **self-reported** comparison into a brand-new, complete,
**non-authorizing** HUMAN discussion proposal, without silently selecting
"latest", accepting the file chooser's order as authentic chronology, or
changing a saved review round.

- After admitting 2–8 exact original self-report JSON files, open
  **Compose a NEW human-only discussion proposal from these rounds**.
- Explicitly choose a prior locally selected report for **each** of the
  twenty original action ordinals (52–71). The same marker may occur in
  multiple rounds; choices retain the locally selected slot only while the
  composer is open, not as an authenticated origin or timestamp.
- Incomplete selection disables export. The operator must confirm before
  the browser requests a private local JSON download. The output retains the
  original v1 20-step self-report shape and false authority/source claims;
  no original source, reviewer, target, finding, client data, private text,
  filenames or timestamps are included.
- This output is a **NEW untrusted HUMAN proposal**, not a reviewed round.
  It does not update the active local status checklist or any earlier source
  or receipt, cannot finalize original native sources or dispatch anything.
  Original native option 72 must separately receive a manually moved
  private file before options 73–75 can provide their own source-bound
  checks. A source-bound checksum does not verify who made a selection.
- The **Discard all draft selections** action clears only this local
  unsaved editor and leaves all selected original reports unchanged.

Never interpret the round-specific status selection as verified remediation,
execution, identity, client/operator approval, grant, release or HUMAN GO.

## Source-free scriptless printable HUMAN round brief

In the **2–8 separate HUMAN discussion rounds** panel, the operator can
save **PRIVATE HUMAN Lab Round Brief (HTML)**. The browser produces a portable
self-contained **scriptless**, CSP-pinned HTML file with the five fixed
original stage summaries, all twenty original action/status histories and
per-action count of self-reported marker transitions. It can be opened from
disk or printed without JavaScript, network, external assets, browser
storage or any native assessment service.

The downloaded file is **unsigned, source-free and private**. It includes
only fixed original action captions, four allowed local self-report status
labels and the manually selected round positions; it never includes imported
file names, paths, hashes, credentials, original customer evidence, targets,
reviewer notes, actors, actual tasks or consent. The visible table filters
do not drop any of the twenty actions from this full briefing. Operator
file-picker order is not proof of a real time series. It is neither a client
report nor a remediation/authorization receipt. No sending/assignment,
scan, grant, source approval, release or verification occurs.
