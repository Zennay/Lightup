# LightUp PRIVATE HUMAN multi-room inbox board

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** All operations below are
strictly local HUMAN review. No scanner, network requests, external target,
AI model, client authorization, new grant, revocation broker, release or deploy.

## Existing problem and finished operator flow

The original offline [PRIVATE HUMAN browser intake](./PRIVATE-BROWSER-INBOX.md)
receives one complete six-part source-bound reconciliation at a time into a
new owner-only 0700 room. Operators coordinating up to twelve already received
PRIVATE rooms need a **single readable work board** without reopening and
disclosing every original confidential HUMAN note or passing room paths onward.

`private_inbox_board.py` creates three exclusive 0600 artifacts in an
**existing PRIVATE owner-only 0700 output directory**:

- `PRIVATE-inbox-portfolio.html`: self-contained scriptless printable
  board with a strict no-network CSP and source-free slot/choice counts.
- `PRIVATE-inbox-portfolio.csv`: the identical fields for offline local
  HUMAN follow-up discussion. Fields are predetermined non-formula tokens
  and integers; no original notes or downloaded names.
- `PRIVATE-inbox-portfolio.json`: the same source-free slot counts and
  exact false authority flags, **unsigned** and non-authenticating.

No original browser names, original room names, customer/source identifiers,
source SHA hashes, HUMAN reasons/questions or vulnerable asset addresses are
placed in the board. The board *can* reveal sensitive small-cohort aggregate
HUMAN counts: it remains PRIVATE and cannot be forwarded automatically.

## Example

First create owner-only PRIVATE source rooms using the original
`private_intake.py` or interactive `private_intake_wizard.py`, then:

~~~sh
mkdir -m 700 ./owner-private-board
python3 assessment-disclosure-preflight/private_inbox_board.py \
  --private-parent ./owner-private-inbox \
  --room review-001 --room review-002 --room review-003 \
  --private-output-dir ./owner-private-board
~~~

Open only the generated `PRIVATE-inbox-portfolio.html` locally from trusted
owner-only storage. Room **slot 1, 2, 3** is the exact user-selected CLI
order, not a durable ID, timestamp, source age, or verified chronology.
The tool never uses an implicit global folder scan. A missing room is not a
fixed or resolved vulnerability: only explicitly selected rooms appear.
Outputs never overwrite existing names. Create a different empty PRIVATE
output directory for each newly ordered board.

The command performs a bounded read-only full local byte check of every
supplied existing owner-only room through the original `private_reopen`
inventory admission, then admits the full original source-free receipt and
seven-column HUMAN decision layout to derive A/B/HOLD choice counts.
Unknown source role, altered byte identity, unexpected directory content,
wrong file mode, invalid HUMAN choice/ordinal/receipt binding or invalid
source-declaration membership causes **HOLD (3)** without publishing a
partial board. **REVIEW_ONLY (2)** means only that this snapshot of local
unsigned files was admitted. Encrypted result passwords are NOT requested;
the board makes NO claim to decrypt or revalidate encrypted original HUMAN
content. Even identical source-free declarations are not ground truth.

## Optional full original HUMAN reopening before the board is produced

By default, the board checks only existing locally stored unsigned source
identities and original decision counts. If a HUMAN operator deliberately wants
every selected room to undergo the **unchanged native original
`private_reopen.reopen`** before publishing the same source-free overview,
append `--full-reopen` to the example above. This requires an interactive
trusted terminal and typing exactly `REOPEN` before any source is reopened.
Encrypted reviewers and results use the original trusted local no-echo
passphrase flow; no passphrases are included in output or CLI flags. Any native
refusal causes the ENTIRE board to HOLD without publishing partial output.
All rooms are locally byte-checked again after re-admission. A board row
marked `ORIGINAL_NATIVE_REVIEW_ONLY` means only local original HUMAN content
reopening returned REVIEW_ONLY, **never genuine client consent, trusted
provenance, approval or verified remediation**.

The `--full-reopen` mode is deliberately optional so generating a simple
source-free overview cannot silently cause decryption or prompting.

## Full original reopening remains separate

For every slot being considered for real follow-up, manually run:

~~~sh
python3 assessment-disclosure-preflight/private_reopen.py \
  --private-parent ./owner-private-inbox --room review-001
~~~

This is the full original native source-bound HUMAN reopener and, where
necessary, performs encrypted receipt decryption through trusted no-echo
local password prompts. The board **does not** replace it.

Zero HOLD choices, matching unsigned hashes or identical HUMAN notes can
never prove security, remediation, independent reviewer identity, original
lab evidence integrity, action-time consent, permission to contact clients
or approval to activate a scanner. Existing exact-head hosted+named VPS CI,
original owner and independent privacy/security/browser/crypto review,
issues #177/#182/#829, genuine separately authenticated client and operator
consent with action-time revocation, and explicit HUMAN GO remain mandatory.
