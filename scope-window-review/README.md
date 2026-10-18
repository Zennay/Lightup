# LightUp · Private grant-window human review (DRAFT/HOLD)

**INCUBATE M3/M7 · PLAN/LAB ONLY. No authority, scan, grant, consent, worker dispatch or production release.**

This feature fills a human-operations gap alongside the **original authenticated Authorization Casebook** and the separate **emergency STOP/Incident Room**. Existing Casebook shows retrospective grant windows but does not provide a ready-to-open *private scheduled human review board* and an *identity-free calendar reminder*. This independent child branch changes **only** new files in `scope-window-review/`, based on the held integrated PR #1624 pinned at `8e14d9389699e6bf9b912042e40f17eff2fd95f4`. No original source-owner, CLI authorization, web portal, scan, CI, QA, STOP or existing test paths are modified.

## Complete one-command private review workspace

Generate the interactive board, machine-readable private agenda, generic .ics reminders
and an artifact integrity manifest **from one original Casebook snapshot**.
Use an existing owner-only 0700 parent directory and a **new** workspace path:

```sh
umask 077
PYTHONPATH=src python3 scope-window-review/window_review.py \
  --database /private/domain.sqlite --email ORIGINAL_OPERATOR_EMAIL \
  --client EXACT_ORIGINAL_TENANT_ID \
  --workspace /private/NEW-lightup-human-window-room \
  --lead-days 7 --future-days 45 --daily-capacity 8
```

Or replace `--database /private/domain.sqlite --email ... --client ...` with
`--casebook /private/ORIGINAL-exported-casebook.json` when using an offline
source snapshot. Only the original persisted account login path can authenticate
at the time it is called; neither a subsequently opened HTML report nor a
file hash becomes client consent, scan permission, or proof of live STOP.

The new directory contains:
- `human-review-board.html`: responsive, entirely offline private human case desk.
- `human-review-agenda.json`: original-ID-bearing planning data for human review only.
- `human-review-calendar.ics`: generic, redacted and non-authorizing reminders.
- `human-review-manifest.json`: exact SHA-256 + byte length of the other three
  generated artifacts, original-source byte digest, prepared-at timestamp and
  literal false authority flags. A checksum does **not** authenticate its author.

**On the trusted receiving machine**, use the separate read-only workspace
inspector without connecting to the original SQLite database or any target:

```sh
python3 scope-window-review/workspace_inspect.py \
  --workspace /private/NEW-lightup-human-window-room
```

This inspects the **entire exact four-file collection**, requires owner-controlled
0700 directory and regular 0600 non-symlink single-link files, validates bounded
canonical manifest fields and all SHA-256/size declarations, and returns
`2 REVIEW_ONLY` or `3 HOLD`. Only aggregate counts are printed. It
never elevates a snapshot to a verified grant; a modified manifest could
be re-created by an attacker because **SHA-256 is not an issuer signature**.
Explicit client/operator authentication and the real action-time gates are
unchanged, and a recipient must independently verify who supplied the private
room and its tenant. Never distribute this private workspace on public hosting.

Directory is newly created mode 0700, individual files 0600 and exclusive
non-overwriting. On ordinary partial failure only newly created files/directories
are cleaned; an incomplete private workspace must never be construed as an
approved source or a completed handoff. The final manifest is published last.
No network traffic, shared host, scheduler, scan, model call, consent or
original SQLite grant/STOP mutation is performed by this workspace composer.

## Human follow-up after a genuine original-source refresh

A new original persisted-domain Casebook changes its source fingerprint: **do not
blindly load the old human note into the new dashboard**. An offline
human-only carryover tool can instead propose preservation only for grant
identities whose **entire original grant row, linked engagement and caseboard,
all related grants, risk decisions and linked request records are unchanged**.
Disappeared, edited or newly out-of-horizon rows are explicitly withheld.
No account authentication, approval, grant, STOP or original SQLite write
occurs in this separate retrospective handoff utility.

Before running, an operator must independently verify both original Casebook
sources, tenant, note issuer and exact review policy. Use the earlier
`human-review-agenda.json` file's `prepared_at` as `--old-review-at`
if the original review was not made immediately after source export:

```sh
python3 scope-window-review/rebase_handoff.py \
  --old-casebook /private/ORIGINAL-OLD-casebook.json \
  --new-casebook /private/ORIGINAL-NEW-casebook.json \
  --previous-note /private/ORIGINAL-human-followup-v2.json \
  --old-review-at 2026-10-18T18:00:00+00:00 \
  --acknowledge-same-tenant \
  --output /private/NEW-human-followup-proposal.json \
  --private-diff /private/NEW-source-differences.html
```

This creates a new 0600 **candidate-only** v2 note in a 0700 owner-only
directory and reports anonymous counts of preserved/changed/missing/out-of-view
entries, always with exit status **3 HOLD**. With `--private-diff`, a second
separate 0600 **scriptless/private HTML human differences desk** lists each
original withheld grant and engagement, source-change reason and next human
action. These original IDs must NEVER be published or treated as consent.
Both destinations are checked before writing and newly written candidate data
is rolled back if second publication fails; neither existing operator file
may be overwritten. Open a **new** private board
generated from the exact new Casebook with identical lead/horizon/capacity
settings; use its local handoff-import preview, verify the source and sender
again, tick the independent confirmation and apply **human stages/aliases/
notes only in the browser tab**. No automatic import or grants are executed.
When no entries are safe to carry, the private proposal is empty; an
operator must review the new source manually. Previously issued v1 notes
have no old-source carried-over path here; use the original stage-only import
only against the exact original board when compatible.

## One-step original authenticated operator workflow (preferred)

From the held LightUp source checkout and on a trusted local machine, use the **original stored account, actual tenant, existing DomainStore authentication/lockout**, with no intermediate plaintext Casebook export:

```sh
umask 077
PYTHONPATH=src python3 scope-window-review/window_review.py \
  --database /private/domain.sqlite \
  --email EXISTING_OPERATOR_EMAIL --client EXACT_EXISTING_TENANT_ID \
  --board /private/NEW-private-window-board.html \
  --lead-days 7 --future-days 45 --daily-capacity 8
```

The original account password is requested interactively through `getpass`, never passed as an argument or placed into the generated HTML. Existing client accounts may omit `--client`, but an operator must choose an exact original tenant ID. Original login can update ordinary stored login/lockout counters. All Casebook source queries continue in the existing read-only original SQLite snapshot and no grant, target, real execution, STOP, consent or risk decision is changed. Original Casebook business logic is called directly, not copied or rewritten.

The mutually exclusive `--database` and `--casebook` modes expose the same private outputs; account selector flags are rejected in offline-file mode. The private source digest in authenticated mode is taken from the original Casebook exporter canonical bytes (unsigned, never consent authentication).

## Workflow

1. On a trusted private LightUp operator machine, use the original **persisted** DomainStore account to export an original single-tenant Casebook through the owner module. No copied/synthetic consent is accepted:

```sh
umask 077
PYTHONPATH=src python3 -m lightup.auth_casebook \
  --database /private/domain.sqlite --email EXISTING_OPERATOR_EMAIL \
  --client EXACT_EXISTING_TENANT_ID --output /private/NEW-casebook.json
```

2. In a local directory **owned by your OS account with mode 0700**, create a private, self-contained operator dashboard; no HTTP server is needed:

```sh
python3 scope-window-review/window_review.py \
  --casebook /private/NEW-casebook.json \
  --board /private/NEW-window-board.html --lead-days 7 --future-days 45 --daily-capacity 8
```

Open the resulting HTML on the same trusted machine, filter by original case/source observations and **assigned versus unassigned human follow-up**, see a private per-alias workload overview, choose temporary human review stages, **human owner alias and up to 280-character next action**, then export the **unsigned private follow-up v2 packet**. The packet includes original private grant/engagement identities; it is NOT an authenticated instruction. The board can later import v1 stage-only or v2 full-follow-up notes ONLY when the original Casebook content-bound digest is exactly unchanged. The complete packet is checked against allowed schema, canonical byte serialization (including duplicate-key rejection), exact grant+engagement membership, bounded text and false authority flags. Import first displays a local human before/after preview, then requires explicit confirmation that the person has independently verified the sender, exact tenant and proposed changes. Changes to local state between preview and apply cancel the entire import. Only in-tab human planning fields change, atomically; original stored grants and cases are never written. Refreshing the page deliberately loses stages and owner/next-action fields until a private note is re-imported. Do not upload the private HTML or packet to public hosting.

3. Alternatively request a private machine-readable source-linked agenda, or a much smaller **calendar with generic titles and without original tenant/engagement/grant/request IDs**:

```sh
python3 scope-window-review/window_review.py \
  --casebook /private/NEW-casebook.json \
  --agenda-json /private/NEW-window-agenda.json

python3 scope-window-review/window_review.py \
  --casebook /private/NEW-casebook.json \
  --calendar /private/NEW-human-review.ics
```

Calendar UIDs are stable generic day/attention identifiers, so repeated imports do not create fresh random IDs; importing unrelated tenants into the *same* calendar may intentionally coalesce identically named generic reminders. Use separate local calendars to keep unrelated client planning distinct. The calendar uses **09:00–09:15 UTC** on capacity-adjusted candidate human follow-up dates, grouped into a generic entry per day and source-attention category. Dates can still correlate with confidential customer work: handle even redacted calendars privately. The dates are proposed *human follow-up reminders*, **never authorization expiry enforcement or a substitute for checking original live stored data**.

Exit status is **2 = REVIEW_ONLY**, **3 = HOLD** or invalid input; never 0 as an execution approval. Tool output displays anonymous counts, not private IDs. Outputs must not exist already. Each single output is created as a new, owner-only 0600 file with same-directory fsync, exclusive non-overwriting link, and no intermediate exposure of a partially written final path.

## What is actually derived

- The original Casebook single-tenant `lightup.auth_casebook.v1` grants, engagement links, original recorded `valid_from` / `valid_until`, the source-declared original `validity_observation` and original request-link observation. **Source data is retrospective, not a trusted runtime fact**.
- Bounded strict JSON with duplicate-key/nonfinite rejection, six false-only authority fields, source identity, grants/engagement declared count and identity consistency, and source-stated observation against original snapshot time. Input is an ordinary no-follow regular file, max 512 KiB. 200 source grants / engagements max. Limits: `--lead-days 0..30`, `--future-days 1..366`, and `--daily-capacity 1..64` (default 8).
- Historical observation older than 24 hours, invalid recorded grant windows, detached original engagements, original `HOLD_` request bindings, and passed recorded windows all yield HUMAN HOLD attention. **Even a non-HOLD entry is REVIEW_ONLY and does not validate a grant, its original consent, the selected target, or live revocation.**
- Next review = the start date for a future source window or end date for a source-in-progress window, minus user-supplied planning lead; overdue/invalid follow-ups are queued for the next UTC day. Human daily-capacity scheduling then distributes reminders from earlier to later dates without changing original source timestamps or windows. Original-source HOLD items (including mismatched request links, invalid records or stale Casebooks) are scheduled for human attention no later than the next UTC day even if the recorded grant window starts much later; HOLD is never deferred just because the original grant has a distant date. Any item delayed by capacity is explicitly HUMAN HOLD with both its target day and proposed human day visible; it never extends a grant or changes actual runtime policy. Each output is a local human planning suggestion. The unrelated original runtime authorization/STOP/consent code is never called.
- Private HTML shows precise original IDs and timestamps for local coordination and supports local human stages, local human owner aliases and local next actions; identity-free aggregate CSV export only contains date/attention/assigned-versus-unassigned/count summaries, NEVER reviewer identities. Private human handoff contains IDs for operator routing, original derived agenda digest and **false** authority flags, not permissions. Neither hashed source nor human declarations authenticate who produced the underlying export.
- The `.ics` output includes no original IDs, targets, risk, evidence, mailboxes or URLs, and never emits an alarm that could be mistaken for an active control.

## Separation and release gates

This feature **is not a real-time revocation monitor** and cannot prove an actual STOP took effect, that a previous grant remained valid, or that a security assessment may proceed. No network, browser persistence, target discovery, scanner, LLM, handler, grant issuance, STOP mutation, live credentials in the board, real domain table writes or automation. The original Casebook export operation itself invokes original authenticated login, which may update ordinary original login/lockout counters.

**Required to release any LightUp code:** exact-head original hosted and registered permanent named VPS CI, original source-owner and independent security/privacy approval, actual separately authenticated client and operator consent and revocation on use (including retry and resume), and explicit HUMAN GO. Known original scope #301/source-contract CI issue is not fixed or waived here. This is a **DRAFT/HOLD child PR**, not a main merge or deploy. No QA/regression/test suites were written, expanded or manually run.

Original source reference: https://github.com/Zennay/Lightup/pull/1620 and integrated separate candidate https://github.com/Zennay/Lightup/pull/1624 .
