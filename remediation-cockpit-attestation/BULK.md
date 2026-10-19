# Atomic PRIVATE HUMAN batch coordination

**LightUp Incubate · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD.** This source-free operator companion lives only in our private attestation add-on. It never changes original findings, evidence, client consent, authorization, grants, verified remediations, native Apply or scanning. A "locally answered" slot is merely a human bookkeeping state, not proof of a fixed vulnerability.

Previously, a reviewer changed one HUMAN workroom slot per `coordination.py revise` invocation. This workflow accepts **one private batch containing 1–12 distinct slot edits**, verifies their exact current encrypted plan and original source-free inbox binding, and creates **one atomic new encrypted plan or complete new workroom**. Invalid input, mismatched source bytes, stale plan version, duplicate slots, partial HUMAN edits, invalid dates or invalid aliases fail before publishing the new version.

## One private operator batch against an existing workroom

Prerequisites: original source-free owner cockpit source, an already admitted complete workroom under `workroom_control.py inspect`, approved local Python `cryptography`, Linux native no-replace directory publisher, and the genuine locally shared 32-byte key in an existing 0700 owner-only parent and 0600 regular file. The secret must be transferred through a separately approved private channel; a shared key does not authenticate a sender's real identity.

Generate a new **0600 local JSON template pinned to the exact workroom version**:

```sh
python3 remediation-cockpit-attestation/workroom_control.py bulk-template \
  --workroom "$HOME/private-lightup/lightup-human-workroom-EXACT-ID" \
  --key-file "$HOME/private-lightup/team.key" \
  --output "$HOME/private-lightup/operator-edits.json"
```

This template contains `kind`, `schema_version`, current source-free inbox manifest SHA, current **encrypted** plan SHA, current plan revision and an empty `edits` array. Use a trusted **local editor** to fill the array. JSON indentation is accepted, but duplicate fields, extra metadata, bad slot identifiers, duplicate edits or noncanonical stages/priority/dates will HOLD.

For example, replace `"edits":[]` with:

```json
"edits": [
  {
    "slot": 1,
    "set": {
      "assignee": "team-alpha",
      "stage": "assigned",
      "priority": "urgent_review",
      "due_date": "2026-10-24",
      "private_note": "Ask HUMAN operator for an update"
    }
  },
  {
    "slot": 2,
    "set": {
      "assignee": "team-beta",
      "stage": "waiting_human",
      "due_date": null,
      "private_note": ""
    }
  }
]
```

The example is only the value replacing the original `edits` property; **retain all exact root fields from your template**. The edits file is **plaintext PRIVATE operator input** and may contain aliases or notes. It must remain a 0600 file in a 0700 owner-only directory; do not publish, upload or send it to other operators. This file is not encrypted; the resulting plan is encrypted. Setting a due date to `null` clears it; setting note to `""` clears it. An `unassigned` slot must have a blank assignee, and other stages require a nonempty assignee. The one 0600 JSON source is never rewritten by LightUp.

Preview **only the number of changed slots and planned revision** (not real source/notes):

```sh
python3 remediation-cockpit-attestation/workroom_control.py bulk-preview \
  --workroom "$HOME/private-lightup/lightup-human-workroom-EXACT-ID" \
  --key-file "$HOME/private-lightup/team.key" \
  --edits "$HOME/private-lightup/operator-edits.json"
```

Then create **one entirely new atomically published full workroom**, with its original native source-free inbox and all updated private HUMAN notes encrypted at rest:

```sh
python3 remediation-cockpit-attestation/workroom_control.py bulk-revise \
  --workroom "$HOME/private-lightup/lightup-human-workroom-EXACT-ID" \
  --key-file "$HOME/private-lightup/team.key" \
  --edits "$HOME/private-lightup/operator-edits.json" \
  --output-parent "$HOME/private-lightup"
```

The printed result contains `index.html`, `inbox/`, `board/` and `plan.ltplan`. Open the root HTML **locally**, not via an externally accessible web server. The original source inbox, old workroom, old plan and draft input JSON remain unchanged. The new workroom is independently source/receipt/HTML admitted, then exclusively atomically published via the existing original Linux no-replace directory writer.

## Optional plan-only workflow

You can alternatively use `bulk.py template`, `bulk.py preview`, `bulk.py apply` or `bulk.py publish-workroom` with explicit `--inbox`, `--plan`, `--key-file` and `--edits` paths. `apply` produces **one new encrypted 0600 `.ltplan`**, not a full workroom. `publish-workroom` produces the complete new PRIVATE workroom. All require the original exact source-free inbox SHA and **current encrypted plan ciphertext SHA**; this is local stale-plan protection and does not authenticate human intent or source truth.

This process cannot create or authorize a real customer action, scanner, retest or security verdict. Original exact-head hosted + named permanent VPS CI, independent source-owner, security, privacy, browser/crypto review, genuine separate current client/operator consent including action-time revocation, original #177/#182/#829 and explicit HUMAN GO remain indispensable before any merge or production deployment.
