# LightUp PRIVATE HUMAN Coordination — offline workroom product

**Status:** Incubate · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD. This is a working *source-bound local human coordination interface*, **not** a LightUp authenticated assessment, client authorization, verified remediation, genuine retest or security release. It operates only on the original independently admitted **source-free** inbox from existing PR #1662, and does not edit the original evidence/cockpit source owner, casework, authorization, grants, scans or deployment.

## What it delivers

A local operator can assign the *received source-free inbox slots* to pseudonymous human operators, set local stages (`unassigned`, `assigned`, `waiting_human`, `locally_answered`), choose local attention (`normal`, `attention`, `urgent_review`), set an ISO review date, and enter a short PRIVATE note. **A slot is a locally received source-free workroom, not a distinct client, finding, verified fix, consent, real status in the original request desk or proven chronology.**

Every plan is encrypted using AES-256-GCM with a key separated by HMAC domain from the team's out-of-band secret used for the source-free HMAC/inbox. Each publication produces a **fresh exclusive 0600 encrypted `.ltplan` file**, and every revision contains the SHA-256 digest of the previous encrypted plan, preserving local voluntary HUMAN continuity **without suggesting cryptographic signatory identity**. Original source-free inbox manifests and per-slot manifests are pinned and independently reread for every material operation. Old plan and original inbox remain unchanged. Private notes/aliases are not included in anonymous exports.

### Prerequisites

Use an already independently admitted PRIVATE HUMAN Inbox from [INBOX.md](INBOX.md), prepared from the original source-owner cockpit with its separate HMAC receipts. All source/inbox/secret/output paths must be **absolute** in existing, locally owner-only 0700 directories; keys, plan snapshots and exports are fresh 0600 private files. The secret remains separately human-distributed and must never be appended to encrypted handoffs. These optional standalone tools require Python 3.11+, Linux for original native exclusive directory publication, and an already reviewed local `cryptography` installation. They do not install packages, contact network services or add core LightUp dependencies.

## 1. Start a private encrypted HUMAN plan

```sh
python3 remediation-cockpit-attestation/coordination.py start \
  --inbox "$HOME/private-incoming/lightup-human-inbox-EXACT-ID" \
  --key-file "$HOME/private-secrets/team-secret.key" \
  --output "$HOME/private-incoming/plan-v1.ltplan"
```

The new plan starts every source-free slot as **unassigned**, with no reviewer alias, due date or free-text note. Everything is locally self-declared.

## 2. Revise one source-free inbox slot (immutable snapshot)

```sh
python3 remediation-cockpit-attestation/coordination.py revise \
  --inbox "$HOME/private-incoming/lightup-human-inbox-EXACT-ID" \
  --key-file "$HOME/private-secrets/team-secret.key" \
  --plan "$HOME/private-incoming/plan-v1.ltplan" \
  --slot 1 --assignee "team-alpha" --stage assigned \
  --priority urgent_review --due-date "2026-10-24" \
  --note "Contact source owner for the next HUMAN review." \
  --output "$HOME/private-incoming/plan-v2.ltplan"
```

To remove a due date, use `--clear-due`; to clear the local PRIVATE note, `--clear-note`. Each revision must actually change one field. `unassigned` requires an empty assignee; all other local stages require a nonempty pseudonymous owner. Text is length-bounded; control, bidi/invisible-format or malformed date text fails closed. The old encrypted plan is never overwritten or deleted. To read counts without writing:

```sh
python3 remediation-cockpit-attestation/coordination.py overview \
  --inbox "$HOME/private-incoming/lightup-human-inbox-EXACT-ID" \
  --key-file "$HOME/private-secrets/team-secret.key" \
  --plan "$HOME/private-incoming/plan-v2.ltplan"
```

## 3. Create a real offline PRIVATE HTML coordination board

```sh
python3 remediation-cockpit-attestation/coordination.py publish \
  --inbox "$HOME/private-incoming/lightup-human-inbox-EXACT-ID" \
  --key-file "$HOME/private-secrets/team-secret.key" \
  --plan "$HOME/private-incoming/plan-v2.ltplan" \
  --output-dir "$HOME/private-incoming/coordination-v2"
```

The command publishes a **new owner-private 0700** browser directory containing a scriptless CSP-pinned `index.html` with local operator aliases, stages, priorities, due dates and escaped PRIVATE notes, plus an anonymous `anonymous-counts.json` that **excludes** aliases, dates, source hashes and note contents. This HTML is PRIVATE; never publish it to a public web server. Local `locally_answered` never means the original vulnerability is actually fixed.

## 4. Export a private anonymous HUMAN calendar

```sh
python3 remediation-cockpit-attestation/agenda.py \
  --inbox "$HOME/private-incoming/lightup-human-inbox-EXACT-ID" \
  --key-file "$HOME/private-secrets/team-secret.key" \
  --plan "$HOME/private-incoming/plan-v2.ltplan" \
  --output "$HOME/private-incoming/human-review.ics" --format ics
```

This creates a fresh owner-private **0600 iCalendar** with all-day `TENTATIVE` reminders for local pending HUMAN review dates, grouped by date and count. Events have **no slot IDs, clients, original findings, names, notes, source fingerprints or grant facts**. No automatic calendar sync occurs. For a machine-readable **anonymous counts-only JSON**, use `--format json` and a fresh private output filename. Manually import into an appropriate trusted calendar only after assessing your own privacy requirements.

## 5. Preserve local HUMAN plans when new encrypted inbox packets arrive

When the team has used `extend.py` to publish a **new** complete private inbox, the former plan is pinned to its original inbox manifest, so it deliberately does not open against a different inbox until explicitly carried:

```sh
python3 remediation-cockpit-attestation/carry.py \
  --old-inbox "$HOME/private-incoming/lightup-human-inbox-OLD-ID" \
  --new-inbox "$HOME/private-incoming/lightup-human-inbox-NEW-ID" \
  --old-plan "$HOME/private-incoming/plan-v2.ltplan" \
  --key-file "$HOME/private-secrets/team-secret.key" \
  --output "$HOME/private-incoming/plan-v3.ltplan"
```

This reads **both** independently admitted original inboxes, and requires the new inbox to contain an **exact, in-order prefix of the old source-free slot manifest identities and local anonymous counts** plus at least one new slot, with total maximum 12. It carries existing encrypted PRIVATE HUMAN owner/due/note labels unchanged, appends new slots as unassigned, and creates a **new** source-bound plan revision. Different sources, reordered prior slots, revised source-free bytes or fake growth = HOLD. This proves only local original slot byte continuity, not historical client evidence or human chronology.

## 6. One file for an entire workroom including the HUMAN plan

```sh
python3 remediation-cockpit-attestation/workroom.py send \
  --inbox "$HOME/private-incoming/lightup-human-inbox-EXACT-ID" \
  --plan "$HOME/private-incoming/plan-v2.ltplan" \
  --key-file "$HOME/private-secrets/team-secret.key" \
  --output "$HOME/private-incoming/private-team-workroom.ltworkroom"
```

The module admits the original native source-free inbox **and** encrypted plan, independently binds the plan to exact source-free inbox SHA identities, and creates one new owner-only encrypted workroom envelope. The plan's pseudonymous assignees and notes stay **inside encrypted ciphertext** in transport.

The separately trusted receiver uses the same team key supplied through an independent private channel:

```sh
python3 remediation-cockpit-attestation/workroom.py receive \
  --input "$HOME/private-incoming/private-team-workroom.ltworkroom" \
  --key-file "$HOME/private-secrets/team-secret.key" \
  --output-parent "$HOME/private-incoming"
```

After bounded authenticated decryption, it independently reconstructs each original native source-free cockpit + HMAC receipt, admits the encrypted plan against the rebuilt inbox, and reconstructs the full private browser board under `board/index.html` plus the original anonymized `inbox/index.html`. The complete **new 0700 workroom** is published atomically with the original Linux no-overwrite publisher. Open the printed folder's `index.html` locally. The previous source, private plan and received encrypted package stay unchanged.

To independently re-admit **every** member and deterministic browser artifact later:

```sh
python3 remediation-cockpit-attestation/workroom_control.py inspect \
  --workroom "$HOME/private-incoming/lightup-human-workroom-EXACT-ID" \
  --key-file "$HOME/private-secrets/team-secret.key"
```

To publish a **new complete workroom version** after changing an assigned local HUMAN slot, without manually handling individual `.ltplan` and recipient files:

```sh
python3 remediation-cockpit-attestation/workroom_control.py revise \
  --workroom "$HOME/private-incoming/lightup-human-workroom-EXACT-ID" \
  --key-file "$HOME/private-secrets/team-secret.key" \
  --output-parent "$HOME/private-incoming" \
  --slot 1 --assignee "team-beta" --stage waiting_human \
  --priority attention --due-date "2026-10-27"
```

This creates a new encrypted HUMAN plan revision, rewraps the unchanged original source-free inbox and plan, reconstructs and independently re-admits all original members, and publishes a completely separate owner-private browser-ready workroom. It does not delete or overwrite the earlier workroom.

## Bulk update or whole-workroom key changeover

For a group of independent local HUMAN slot changes, use [**BULK.md**](BULK.md): create a pinned 0600 JSON assignment template from the complete original workroom, privately edit multiple slots, preview aggregate changes, and atomically publish one new entire workroom without touching the old one. For new out-of-band team keys, use [**REKEY.md**](REKEY.md): `workroom_control.py rekey` (or `rekey_workroom.py`) re-signs every independently verified original source-free cockpit with a new team key, re-encrypts the PRIVATE HUMAN plan, reconstructs the complete browser workroom and publishes it separately. Neither action authorizes remediation or revokes previously copied old keys.

## Privacy-minimal whole-workroom counts export

The original inbox's internal `summary.json` has **source-free manifest SHA-256 identifiers** for local native consistency and deduplication. Do not share that internal private inventory as an anonymous report. Instead, admit the complete workroom and export a separate **new 0600 counts-only JSON**:

```sh
python3 remediation-cockpit-attestation/workroom_control.py export-counts \
  --workroom "$HOME/private-incoming/lightup-human-workroom-EXACT-ID" \
  --key-file "$HOME/private-secrets/team-secret.key" \
  --output "$HOME/private-incoming/workroom-counts-only.json"
```

This contains *only aggregated counts* from the original source-free HUMAN inbox and local encrypted slot plan (stages, pending slots, number with locally entered due dates). It deliberately omits source-free manifesto digests, individual slot rows, dates, operator aliases and notes, and never asserts actual client identity, verified fixes, original consent or authorization. Any release or onward sharing is still a separate authorized HUMAN decision.

## One-command start from freshly received encrypted source-free cockpits

For a first-time LOCAL PRIVATE HUMAN operator, it is no longer necessary to separately run `inbox.py receive-many`, `coordination.py start`, `workroom.py send`, and `workroom.py receive`. Use one source-bound original native workflow:

```sh
python3 remediation-cockpit-attestation/workroom_control.py create \
  --package "$HOME/private-incoming/operator-01.ltpack" \
  --package "$HOME/private-incoming/operator-02.ltpack" \
  --key-file "$HOME/private-secrets/team-secret.key" \
  --output-parent "$HOME/private-incoming"
```

All original encrypted packets must already be under the same **separately human-approved key** and contain only source-free native cockpits. The operation authenticates and admits every original signed manifest and HTML/JSON, creates a new encrypted owner-private **unassigned HUMAN coordination plan**, seals/reopens the complete package, and publishes **one fully constructed 0700 PRIVATE workroom** with the v2 local workload dashboard and clickable original source-free cockpit links. The original ciphertexts and source remain untouched. It cannot authenticate the actual human sender, original case evidence, client consent or a verified fix. No network upload, grant, Apply, scan or CI change occurs.

## Faster offline workroom: prioritized review queue and one-step encrypted intake

**New complete PRIVATE HUMAN workrooms** open to a source-bound, scriptless local dashboard with local workload totals, pending HUMAN questions, and two navigation links. The HUMAN review board sorts not-locally-answered items by self-declared urgency and local date, with a direct **one-click link to each original native source-free cockpit**. Those links point only into `../inbox/slot-NN/cockpit/index.html` within the same 0700 workroom; there are no network calls. Older workrooms retain and re-admit their original v1 pages unchanged. Standalone PRIVATE coordination HTML exports also retain their original link-free layout, because they do not include the sibling inbox. The new v2 navigation is declared explicitly in the workroom's private board manifest and independently rebuilt during admission.

To **extend an already received complete workroom** without four manual intermediate commands, run:

```sh
python3 remediation-cockpit-attestation/workroom_control.py extend \
  --workroom "$HOME/private-incoming/lightup-human-workroom-OLD-ID" \
  --key-file "$HOME/private-secrets/team-secret.key" \
  --package "$HOME/private-incoming/arrived-03.ltpack" \
  --package "$HOME/private-incoming/arrived-04.ltpack" \
  --output-parent "$HOME/private-incoming"
```

This composes the existing native `extend.py` encrypted cockpit admission, `carry.py` **exact preserved original source-free slot prefix** and encrypted local HUMAN plan continuation, `workroom.py` complete source-free handoff and independent receive/admission, and exclusive atomic 0700 workroom publication into **one HUMAN operator action**. Existing notes, review dates, local priority, operator labels and statuses are retained only against identical admitted original slots; new slots start unassigned. Original workrooms, previous plan and incoming ciphertext remain unchanged. There is still no original client identity, client consent, authority, verified remediation, security verdict or real retest, and the original DRAFT/HOLD release gates remain in force.

## Security and release boundaries

These modules handle **local HUMAN scheduling**, not authenticated original customer findings, remediation execution, vulnerability proof, consent, security decision or regulator-approved retention. Shared-key HMAC and AES-GCM prove possession of the separately distributed key, not verified human sender identity. A compromised shared key enables forging alternative locally admitted anonymous cockpit summaries, plan files and portable workrooms. The system provides no network upload, remote revoke, automatic key expiry, identity verification, source validation of real underlying evidence, active test, grant or native Apply action.

All original gates remain mandatory: exact-head hosted and permanent named VPS CI, original source-owner and independent security/privacy/browser/crypto approval, existing #177/#182/#829, separately genuine current client and operator consent with action-time revocation, and explicit HUMAN GO. **Do not merge to main or deploy based on this local product.** No QA/regression suites are included in this work.
