# LightUp PRIVATE original HUMAN browser inbox

**DRAFT/HOLD · INCUBATE M3/M7 PLAN/LAB ONLY.** This is an offline, owner-controlled
local receiving utility for *already exported* PRIVATE LightUp source-free lab
review artifacts. It neither authenticates clients/reviewers, nor verifies
findings, confers consent, executes scans, sends data, approves external disclosure,
or changes grants. REVIEW_ONLY is not an authorization verdict.

## Product workflow

The original portable [two-reviewer reconciliation desk](./reconcile-standalone.html)
produces the *full* seven-column A/B/HOLD HUMAN decision CSV, an original six-column
PRIVATE result either as plaintext CSV or password-encrypted original `.luhb`,
and a separate small-cohort-suppressed PRIVATE counts CSV. It reads the original
source-free PRIVATE receipt and both independently saved reviewer submissions.

Browser downloads may land with unsafe default file permissions in a public
Downloads directory. `private_intake.py` copies the **complete six-part handoff**
to a new owner-only `0700` room using exclusively-created `0600` regular
files, without touching the original downloads. Files are renamed to private
fixed roles, so their original browser filenames are never copied into the
receiving inventory. No unsupported, symlinked, hardlinked, changing, oversized,
non-user-owned or repeated source input is admitted.

It then invokes **the unchanged original `reconcile.py reopen`** over all
original receipt, two reviewer sources, complete A/B/HOLD decisions, chosen
full result and suppressed counts. No summary-only shortcut is sufficient.
Encrypted original `.luhd` reviewer vaults, original reviewer `.luhb` bundles
and final result `.luhb` are accepted and decrypted only in memory using
the native original no-echo passphrase flow where required. The optional
`cryptography` dependency must already be installed for encrypted files.
Invalid source/reviewer binding, malformed result, counts mismatch or failed
decryption causes HOLD; on ordinary failure newly created room files are removed,
without modifying the original browser downloads.

Only if complete original reopening returns REVIEW_ONLY, the new room gains a
private, **unsigned, non-anonymous** `PRIVATE-intake-inventory.json` of fixed
local role filenames, per-file byte length and SHA-256, with literal false
authentication, consent, signature, grant and release flags. No actual source
targets, client IDs, original download basenames, reviewer note content or
external destinations are written into the inventory. Hashes are correlatable
and never constitute a trusted signature or evidence authenticity.

## Faster interactive PRIVATE terminal receiving (no long command)

On a trusted offline owner workstation open the **native PRIVATE operator
wizard**. It gathers the exact source roles and explicit input-format choices
one at a time, obtains file paths through terminal prompts with disabled echo,
and requires an explicit `RECEIVE` confirmation before creating a room.
The wizard invokes the SAME `private_intake.stage` and the original unchanged
`reconcile.py reopen`; no alternate weaker validator, external service,
scan, upload or unapproved approval exists. It refuses non-interactive sessions.

~~~sh
python3 assessment-disclosure-preflight/private_intake_wizard.py
~~~

The original encrypted reviewer/final bundle passphrases, if needed, remain
handled by the genuine native original cryptography receiver in memory; do not
enter them as file paths or shell arguments. A cancelled/invalid wizard produces
HOLD (3), never an automatic consent or a grant.

## Receiving an already downloaded plaintext handoff

Use a trusted local terminal. Create an **existing private parent** before the
operation, and use a **new room name** each time. Never use real customer inputs
on a shared terminal. Examples use placeholders; they do not run assessments.

~~~sh
mkdir -m 700 ./owner-private-inbox
python3 assessment-disclosure-preflight/private_intake.py \
  --private-parent ./owner-private-inbox \
  --room review-001 \
  --receipt ~/Downloads/PRIVATE-receipt.json \
  --a-csv ~/Downloads/PRIVATE-reviewer-A.csv \
  --b-csv ~/Downloads/PRIVATE-reviewer-B.csv \
  --decisions ~/Downloads/PRIVATE-reconcile-browser-decisions.csv \
  --result-csv ~/Downloads/PRIVATE-reconciled-human.csv \
  --counts ~/Downloads/PRIVATE-browser-reconciled-counts.csv
~~~

For an encrypted final result, substitute
`--result-bundle ~/Downloads/PRIVATE-reconciled-human.luhb` for
`--result-csv`. Each reviewer independently accepts exactly ONE of
`--a-csv`, `--a-vault`, `--a-bundle`, and the analogous `--b-*` options.
The original native decryption prompts for passphrases; secrets are not
placed on a command line. The independent original `--minimum-cohort`
defaults to 5 and is limited to 5–12 for this PRIVATE receipt flow.

On complete admission exit **2 / REVIEW_ONLY** returns a ready owner-only
local receiving room. Any refused input or existing room yields **3 / HOLD**.
There is no successful authentication/consent/release exit status.

## Reopen the exact original received HUMAN room later (read-only)

The bundled `private_reopen.py` independently checks the owner-only room,
the *entire exact* private unsigned file inventory, every original SHA-256/length,
all six required original private roles, and uses the unchanged native original
`reconcile.py reopen` again to read the receipt/reviewers/decisions/full
HUMAN result/suppressed counts. This action never modifies, extracts or
publishes a prior receiving room. A corrupt/missing/extra file, changed source,
duplicate manifest key, unsafe mode or original admission mismatch causes
**HOLD (3)**. Exact matching plus original reopening returns **REVIEW_ONLY (2)**,
never evidence/consent/authorization.

~~~sh
python3 assessment-disclosure-preflight/private_reopen.py \
  --private-parent ./owner-private-inbox \
  --room review-001
~~~

Encrypted inputs use the original secure native no-echo password prompts when
opened again. This does not prove that someone else did not copy/replace
unsigned bytes and manifest together, or that any reviewer/customer identity
or source was verified.

**Important:** Original files in Downloads remain exactly where they were,
potentially readable by other users or backup software. Inspect and arrange
their cleanup yourself under your organization’s retention/privacy policy.
Do not assume merely copying bytes revoked any previous access. The local
source-free packet must still undergo original owner and independent
security/privacy/browser/crypto review, exact-head hosted and permanently named
VPS CI, original issues #177/#182/#829, separately authenticated current
client/operator consent including revocation at action time and explicit HUMAN GO
before any contemplated release. Never equate a browser download, inventory
hash or source match with verified finding or remedied vulnerability.
