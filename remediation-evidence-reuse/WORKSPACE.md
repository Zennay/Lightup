# LightUp · PRIVATE offline Evidence Relationship Workspace

This is an integrated offline product inside existing held [PR #1660](https://github.com/Zennay/Lightup/pull/1660), layered on the original PRIVATE Evidence Artifact Ledger [PR #1642](https://github.com/Zennay/Lightup/pull/1642). It does not take ownership of the Ledger, the first-party assessment engine, authorization, consent, scans or external evidence.

## Create a usable standalone PRIVATE work folder in one command

The complete `desk.py workspace` operation reads an original owner-private Evidence Artifact Ledger v1 or unified HUMAN v2 export, optionally an earlier PRIVATE snapshot of the **exact same original source**, and optionally an existing source-byte-bound HUMAN review session. You do **not** need to start a separate HUMAN inbox first: an empty local one is created automatically if `--session` is omitted.

Run from the repository root, with original PRIVATE JSON files already owned by you as `0600` inside an owner-only `0700` directory:

    python3 remediation-evidence-reuse/desk.py workspace \
      --current "$HOME/lightup-private-review/original-ledger.json" \
      --output-dir "$HOME/lightup-private-review/workdesk-01"

To reuse existing local HUMAN review statuses and notes:

    python3 remediation-evidence-reuse/desk.py workspace \
      --current "$HOME/lightup-private-review/original-ledger.json" \
      --session "$HOME/lightup-private-review/my-inbox.json" \
      --output-dir "$HOME/lightup-private-review/workdesk-02"

If you originally created the HUMAN inbox with `--previous`, specify the **identical exact previous source packet** again. A different client, original source SHA, finding count or source contract HOLDs. Existing HUMAN statuses and source metadata are never silently carried between different original sources.

### What gets created

One **NEW** owner-private `0700` folder containing complete owner-private `0600` files:

| Private file | Product behavior |
| --- | --- |
| `index.html` | Start here in an offline browser; links to all snapshots and operator explanations. |
| `fingerprints.html` | Local SHA/finding reuse, conflicting local length/HUMAN stage and optional same-source drift. |
| `attention.html` | HUMAN source-owner priority board; local stages and follow-up explanations but **no free-text HUMAN notes**. |
| `inbox.html` | PRIVATELY shows the exact local HUMAN status, proposed question, and note content. |
| `counts.json` | Aggregate anonymous original-local counts and HUMAN status summaries, no individual IDs, SHA or note text. |
| `questions.json` | Sensitive original finding/fingerprint advisory HUMAN questions, never native execution or Apply. |
| `current.json` | A PRIVATE exact copy of the admitted original ledger/unified HUMAN metadata; **not underlying attachment file bytes**. |
| `previous.json` | Only when supplied: a PRIVATE exact previous same-source original packet. |
| `session.json` | Source-byte-bound local HUMAN inbox; initially all open if no existing session was supplied. |
| `manifest.json` | Input/derived SHA-256 and lengths for all shipped files; integrity hints, **not signatures or authenticated provenance**. |

Open `/absolute/path/to/workdesk-01/index.html` **only in your trusted local browser**. All HTML is scriptless, CSP-restricted, and has no background service, external resources, uploads, cookies, remote fonts, APIs, scans or state-changing links.

To continue HUMAN-only work, use this bundle's PRIVATE copies (and the exact optional `--previous` if present):

    python3 remediation-evidence-reuse/desk.py inbox list \
      --current "$HOME/lightup-private-review/workdesk-01/current.json" \
      --session "$HOME/lightup-private-review/workdesk-01/session.json"

    python3 remediation-evidence-reuse/desk.py inbox mark \
      --current "$HOME/lightup-private-review/workdesk-01/current.json" \
      --session "$HOME/lightup-private-review/workdesk-01/session.json" \
      --ordinal 1 --stage in_human_review --note-prompt

No real client material is created or read by this documentation. The old HTML and manifest reflect **the session at the moment the bundle was created**; after the local inbox changes, generate a **different unused workdesk folder** instead of expecting HTML to update itself. `session.json` is a local mutable HUMAN state; it is never authoritative LightUp casework or a grant.

### Security, privacy and failure behavior

The bundle publisher builds **every** file under a random owner-private staging directory, flushes files and directory metadata, rereads exact PRIVATE input bytes and the optional HUMAN session, and publishes the complete prepared directory using **Linux `renameat2(RENAME_NOREPLACE)`**. If the target folder exists, the move is refused without replacing anything. Unsupported platforms HOLD rather than using unsafe fallback. If a source or session changes during the operation, the bundle is not published.

This is intentionally a **PRIVATE metadata + HUMAN notes folder**, not encrypted evidence material. Any attached filename, finding, reviewer alias, source/context label, digest and HUMAN note is confidential even without underlying binary attachments. Keep access at 0700/0600, do not share by public URL, do not upload to GitHub, Notion public pages, CI logs/artifacts, or uncontrolled syncing. If actual signed provenance or encrypted-at-rest collaboration is required, those capabilities belong to their independently reviewed and gated original owner PRs, not this offline operator report.

Project remains **INCUBATE, M3/M7 PLAN/LAB ONLY, DRAFT/HOLD**. Original exact-head hosted and permanently registered named VPS CI, original source owner and independent security/privacy/browser/crypto approval, #177/#182/#829, separately authenticated current client and operator consent with action-time revocation, plus explicit HUMAN GO are release gates. This bundle does not satisfy them and does not execute anything against a real target.
