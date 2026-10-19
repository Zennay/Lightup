# LightUp — PRIVATE HUMAN action handoff (DRAFT/HOLD)

This standalone, **offline** companion turns **an existing exact-matched saved anonymous numeric browser session and local HUMAN routing board** from the unchanged [remediation-portfolio](../remediation-portfolio/README.md) into *separate, human-readable follow-up packets grouped by selected HUMAN next action*.

It solves a practical operator gap: routing choices in a combined private board are not yet individual, reviewable, least-disclosure human handoffs. A human can now prepare just the follow-up needed for a manually chosen original authorized reviewer instead of sharing an entire local numerical dashboard. This feature **does not send anything**, grant authority or update the original source.

## Use (offline Linux, stdlib Python)

Open the original `remediation-portfolio/studio.html` in an offline browser. Import the original native anonymized counts-only exports, save the numeric private session, make HUMAN-only next-action choices and export the matching action board. Save **both** downloads inside one folder owned by the same local account, with mode 0700 for the parent and 0600 for both files.

```bash
mkdir -m 700 -p "$HOME/lightup-private-human"
install -m 600 ~/Downloads/PRIVATE_SESSION.json "$HOME/lightup-private-human/session.json"
install -m 600 ~/Downloads/PRIVATE_BOARD.json "$HOME/lightup-private-human/board.json"

python3 remediation-human-handoff/handoff.py \
  --session "$HOME/lightup-private-human/session.json" \
  --board "$HOME/lightup-private-human/board.json" \
  --output-dir "$HOME/lightup-private-human/all-actions"

# Least-disclosure packet for one HUMAN action:
python3 remediation-human-handoff/handoff.py \
  --session "$HOME/lightup-private-human/session.json" \
  --board "$HOME/lightup-private-human/board.json" \
  --only request_original_human_review \
  --output-dir "$HOME/lightup-private-human/original-owner-review"

# Disclose only one human-selected ordinal in one exact action group:
python3 remediation-human-handoff/handoff.py \
  --session "$HOME/lightup-private-human/session.json" \
  --board "$HOME/lightup-private-human/board.json" \
  --only request_original_human_review \
  --ordinal 1 \
  --output-dir "$HOME/lightup-private-human/one-local-row"
```

Open `all-actions/index.html` **locally**; follow the action-group links. Each non-empty selected group has matching `handoff-ACTION.html`, `.csv`, and `.txt`. The source-free `handoff-summary.json` records the exact requested action scope, action/state appearances and literal false authority flags. Empty groups receive no handoff files. No-action choices are excluded, **never silently considered resolved**. An explicit `--only` hides other groups but does not assert that missing groups are zero. `--ordinal N` requires a matching `--only ACTION`, validates that the exact selected row actually has that action, and publishes just that one locally declared ordinal. This is not a client/case identifier. Filtered exports omit unselected original packet counts rather than disclosing them. The browser reports are print-friendly, keyboard-link navigable and scriptless with network-blocking CSP.

## Offline HUMAN status return to original Studio

The original Studio allows importing a local source-free HUMAN routing board, but an operator who receives an action packet could not apply an individual local state change through the CLI without manually reconstructing the entire board. The independent `return_to_studio.py` closes this loop **without touching original evidence**.

```bash
python3 remediation-human-handoff/return_to_studio.py \
  --session "$HOME/lightup-private-human/session.json" \
  --board "$HOME/lightup-private-human/board.json" \
  --ordinal 1 \
  --expect-action request_original_human_review \
  --new-state waiting_original_owner \
  --output-dir "$HOME/lightup-private-human/local-return-01"
```

A fresh private 0700 folder contains `board.json` (native Studio-compatible v1), `change-summary.json` (one self-declared local state transition; 12 authority flags all false), and scriptless `index.html`. Each file is 0600. It requires the **exact current session** and the full matching prior board, refuses unknown ordinals/actions, rejects a no-op state transition, and strictly re-admits the produced board through the original owner parser before exclusive publication. The prior board remains unchanged. In the **same offline Studio session**, restore the new `board.json` manually; Studio itself independently checks all packet ordinals and numeric shapes.

The local return does not prove that an authentic original HUMAN reviewer replied. In particular, `locally_discussed` is **never** a verified fix or original-source decision; no native evidence or ticket workflow is modified. A new file is not a delivery receipt or consent.

## Hard boundaries

- The existing owner-controlled `remediation-portfolio/action_board.py` is the **sole** import contract: original producer format, bounded/private no-follow file admission, duplicate-key rejection, **exact** numeric packet shape and ordinal matching, all literal false authority flags. A mismatching board or input rejects the whole operation before any final publication. We do not rewrite, fork or relax the original parser.
- Output appears only in a **fresh** folder under an existing owner-only 0700 parent; the staging directory is private and only 0600 files are written. Publication is exclusive Linux `renameat2(RENAME_NOREPLACE)`, with fsync; existing destinations remain untouched.
- Nothing is sent, imported to other systems, uploaded, cached in browser storage, mapped to a real client/finding, scheduled, scanned or marked remediated. The local packet ordinal is **not** an original case ID. Sort is purely HUMAN waiting/follow-up state and local question volume, never risk severity or authentic prioritization.
- Private numeric exports may still disclose sensitive small-cell information and **are not encrypted at rest**. An actual human must decide disclosure and independently authenticate current original records and both parties' authority through the genuine source workflow.
- LightUp remains **INCUBATE · M3/M7 PLAN-LAB ONLY · DRAFT/HOLD**. Original source-owner and independent security/privacy review, original hosted plus permanent named VPS exact-head CI, #177/#182/#829, separate authentic client/operator consent with action-time revocation and explicit HUMAN GO remain required before any main merge, real-client operation or deployment. This local companion itself supplies none of those approvals.

## Isolation

Only new `remediation-human-handoff/` files. Built on pinned existing independent `remediation-portfolio/` companion; does not mutate original owner branch, source evidence, QA/tests, auth/scan/grant paths, CI or deployment. If original native source format evolves, update via a separate owner-reviewed source contract rather than guessing.
