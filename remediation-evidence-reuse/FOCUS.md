# LightUp PRIVATE HUMAN Attention Board

This is an optional source-bound local companion of the existing [PRIVATE HUMAN Evidence Relationship Desk](README.md) in draft [PR #1660](https://github.com/Zennay/Lightup/pull/1660). **Incubate M3/M7 PLAN/LAB ONLY · DRAFT/HOLD.** No original LightUp owner source, scanner, authorization, client consent, native HUMAN Apply, CI or release gate changes.

## Operator workflow

The new [focus.py](focus.py) allows you to see which *locally proposed HUMAN follow-up* needs attention first. It opens the exact original PRIVATE Ledger v1/unified v2 export and a separately maintained exact-byte-bound HUMAN `triage.py` inbox and groups each question by:

1. **Original owner follow-up needed** (local HUMAN state).
2. **Inconsistent reported evidence-file byte length** for the same local SHA.
3. **Different HUMAN stages** on shared local SHA.
4. **Added / absent local reference** between same-source private exports.
5. Other **open** or **in human review** questions.
6. Locally **answered HUMAN** (never automatically a verified repair).

The generated standalone HTML uses built-in browser `<details>` sections, no script, no cookies, no browser storage and a no-network Content Security Policy. It gives the exact original finding ID and SHA-256 **inside a private HTML only**, original HUMAN stage and plain-language human follow-up suggestions, but **never free-text private notes** (only a note-presence indicator). Nothing is executed by clicking or opening it. The original source, evidence files, source-owner review and local human journal remain unchanged.

Only use an original PRIVATE 0600 JSON export in an actual 0700 private directory and a matching independently admitted PRIVATE HUMAN inbox:

    python3 remediation-evidence-reuse/desk.py focus --current "$HOME/lightup-private-review/current.json" --session "$HOME/lightup-private-review/reuse-inbox.json"
    python3 remediation-evidence-reuse/desk.py focus --current "$HOME/lightup-private-review/current.json" --session "$HOME/lightup-private-review/reuse-inbox.json" --format html --output "$HOME/lightup-private-review/PRIVATE-human-focus.html"
    python3 remediation-evidence-reuse/desk.py focus --current "$HOME/lightup-private-review/current.json" --session "$HOME/lightup-private-review/reuse-inbox.json" --format counts --output "$HOME/lightup-private-review/anonymous-human-focus.json"

When your original session was created with `--previous`, supply the **same exact previously imported source** on every command. `inspect` (the default) prints counts only. `counts` writes separate owner-private 0600 anonymous JSON without target/source labels, IDs, file hashes, notes or reviewer names. `html` writes only to a previously unused owner-private 0600 output path and shows exact private question identities. Source bytes and HUMAN session bytes are reopened before publication; drift blocks export.

A local stage, source SHA label, note or artifact fingerprint is not independently authenticated evidence. In particular an `answered_human` record does **not** prove vulnerability remediation, signed owner acceptance, grant, legal custody, assessment permission or a completed retest. Keep HTML inside original applicable retention controls and never upload it to public GitHub/Notion, CI artifacts or third-party document services.

**Unchanged release HOLD:** original exact-head hosted and permanent named VPS CI, independent source owner/privacy/security/browser/crypto reviews, #177/#182/#829, separate client/operator revocable action-time consent, explicit HUMAN GO. No production merge/deploy.
