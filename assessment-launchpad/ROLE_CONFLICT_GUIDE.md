# Explicit HUMAN conflict decisions for overlapping role returns

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · REVIEW_ONLY.**
No identity/consent/authorization/HUMAN GO is authenticated or granted.

The existing native `advance.py --role-return-dir` deliberately HOLDS if
two independently admitted role returns claim the same original local slot.
Never silently pick the first, last, or newest response; original HUMAN round
order and the role strings are self-reported, not trustworthy timestamps or
credentials.

The offline `role_return_conflicts.py` enables the **owner** to explicitly
choose one original return packet per overlapping ordinal while preserving
every original packet unchanged. All inputs pass the same original-source
five-file + 2–8 exact HUMAN rounds + original two-file return admission gates.

## 1. Prepare a PRIVATE conflict desk

Create a fresh owned mode-0700 folder, then:

```sh
mkdir -m 700 ~/private-role-conflicts
python3 assessment-launchpad/role_return_conflicts.py \
  --bundle-dir ~/private-lab-launchpad \
  --round-dir ~/private-human-round-01 \
  --round-dir ~/private-human-round-02 \
  --role-return-dir ~/private-owner-return-first \
  --role-return-dir ~/private-owner-return-second \
  --output-dir ~/private-role-conflicts
```

The result contains exactly four 0600 files. The **PRIVATE HTML** displays
every conflicting ordinal, the 1-based input packet number in the order of
`--role-return-dir`, the suggested role, the old/proposed non-authorizing
HUMAN stage, and whether a private note changed. It deliberately omits
endpoint URLs, private note text, paths and authenticated identities.

A second, locally generated **PRIVATE browser editor** provides one-choice-per-
conflicting-slot dropdowns, a progress indicator and a one-click source-bound
CSV download. All input suggestions are fixed to exact original return packet
numbers and the original stage/role, never arbitrary filenames or approval.
The browser can resume an earlier PRIVATE choice CSV in memory. Every original slot, source-set fingerprint, eligible source packet and explicit decision must match before any edit is restored. An invalid file leaves all in-memory choices untouched.
It has no network access, browser storage, original endpoint URL or previous
PRIVATE note text. Its inline script/style CSP hashes are generated from the
exact local producer. The browser download may lack 0600 permissions: move it
to an owned 0700 folder, chmod 600 and use the original native input gate.

The **PRIVATE choice CSV** includes a source-set SHA-256 fingerprint, an
ordinal, the eligible packet numbers, and a blank `chosen_packet_number`.
It contains exactly one row per conflicting original slot. Keep the first
three columns and every row in the original order. Fill the last column
with **one permitted original packet number**, not a role, filename, date,
or unverified human name. An empty choice fails closed. This is an explicit
operator decision only, not a grant or a claim that either recipient was
authenticated.

## 2. Apply the complete manual choices

Put the completed CSV in another owned mode-0700 folder as a single-link
mode-0600 file. Choose a separate *new* empty 0700 output folder.

```sh
mkdir -m 700 ~/private-conflict-result
python3 assessment-launchpad/role_return_conflicts.py \
  --bundle-dir ~/private-lab-launchpad \
  --round-dir ~/private-human-round-01 \
  --round-dir ~/private-human-round-02 \
  --role-return-dir ~/private-owner-return-first \
  --role-return-dir ~/private-owner-return-second \
  --decision-file ~/private-decisions/manual-choices.csv \
  --output-dir ~/private-conflict-result
```

Every overlapping ordinal must be selected explicitly. All non-overlapping
slots use their unique original packet. Unselected slots and other roles'
notes remain unchanged. No original response files are modified.

The result contains a full **OWNER-PRIVATE** canonical next HUMAN worksheet,
`lightup-lab-human-conflict-resolved-private.json`, a separate source-bound
unsigned context file, and a private guide. The *full* worksheet includes all
original roles' notes: **never send it back to a selected-role recipient**.
The source-set fingerprint and context are not cryptographic signatures of
a human, identity, consent or trust in a sender.

Use the resulting worksheet with the established HUMAN next-round command:

```sh
mkdir -m 700 ~/private-conflict-followup
python3 assessment-launchpad/advance.py \
  --bundle-dir ~/private-lab-launchpad \
  --earlier-round-dir ~/private-human-round-01 \
  --previous-round-dir ~/private-human-round-02 \
  --responses ~/private-conflict-result/lightup-lab-human-conflict-resolved-private.json \
  --output-dir ~/private-conflict-followup
```

**Note:** the `advance.py --responses` path is an ordinary owner-private
HUMAN worksheet import and does not automatically carry the conflict context
into the new workroom. Keep the exact original packets, completed choice CSV,
and source context private if a later review needs to replay the operator
decision. Do not claim stronger provenance than was actually checked.

## 3. Reopen exactly against the original inputs

Replace `--output-dir DIR` with `--verify-output-dir DIR` while preserving
the original flag order and, for a resolved packet, the exact same
`--decision-file`. Source or recipient drift, incomplete files, altered
source fingerprints, reordered slot rows and changed choice data HOLD.

No target interaction, network call, scanner, model, grant, authorization,
remediation verification or deployment occurs. Original separate real client
and operator consent, action-time revocation, independent privacy/security
review, permanent CI, source-owner and HUMAN GO remain release requirements.

## Permanent PRIVATE HUMAN decision ledger

A fully resolved conflict result now includes exactly four owner-private 0600
files: the full canonical HUMAN worksheet, source-bound context JSON, a new
lightup-lab-human-conflict-decisions-private.csv ledger, and the owner guide.
The ledger shows the local ordinal, manually chosen original packet number,
all eligible original packet numbers, chosen self-reported HUMAN stage, and
whether the PRIVATE note changed. No original URL, note text, recipient
identity or source path is present in the ledger. The context stores its
SHA-256 fingerprint, and read-only reopen regenerates and compares the
complete four-file packet against the unchanged original source and manually
selected reply CSV. These are local UNSIGNED provenance facts, not consent,
authentication, a remediation verdict or HUMAN GO.
