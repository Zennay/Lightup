# PRIVATE team-key changeover for a complete HUMAN workroom

**LightUp Incubate / M3–M7 PLAN/LAB ONLY / DRAFT/HOLD**. This workflow solves an operational source-free handoff gap: a complete existing encrypted team workroom contains multiple individually keyed original HUMAN cockpit receipts **and** an encrypted local owner/priority/date plan. Rotating only one `attest.py` receipt would leave other team members and the plan bound to the old key.

The native tool `rekey_workroom.py` builds a **complete new browser-ready PRIVATE team workroom** with every original source-free cockpit/manifest preserved byte-for-byte, **all** attached HMAC receipts newly bound to another independently generated 32-byte shared secret, and the same locally self-declared HUMAN coordination details re-encrypted under the new secret. It creates one new encrypted plan revision and links the old encrypted plan SHA for local continuity. No old files are deleted, overwritten or modified. No client authorization, original evidence, original finding IDs, real active targets, verified fixes or real customer consent are created.

## 1. Prepare a new key privately

On the operator's already trusted Linux device, use an existing owner-only `0700` folder. Keep original and new keys in separate **0600 regular files**; all command paths must be canonical absolute.

```sh
python3 remediation-cockpit-attestation/attest.py new-key \
  --key-file "$HOME/private-lightup/team-key-v2.key"
```

The new secret must be transferred through a **separate human-approved secure channel** to an authorized receiver. Do not include it in the workroom, receipts, notes, encrypted package, email body, shared folder or public repository. A shared key only establishes possession; it is **not a verified person, legal authorization or original provenance**.

## 2. Re-sign all source-free dossiers and re-encrypt the coordination plan

```sh
python3 remediation-cockpit-attestation/rekey_workroom.py \
  --workroom "$HOME/private-lightup/lightup-human-workroom-OLD-ID" \
  --old-key-file "$HOME/private-lightup/team-key-v1.key" \
  --new-key-file "$HOME/private-lightup/team-key-v2.key" \
  --output-parent "$HOME/private-lightup"
```

The importer requires two genuinely distinct 32-byte secrets. It independently admits the **whole old native workroom**, every original source-free cockpit, source-free manifest, attached original HMAC receipt and current encrypted HUMAN plan against the previous key.

It then publishes **only a fresh workroom** under an exclusive new randomly named folder, with private directory permissions, exact unchanged original source-free HTML/JSON and newly signed detached HMAC receipts under the new key. Existing locally chosen reviewer aliases, stages, review dates, priorities and private HUMAN notes are retained **inside newly encrypted `plan.ltplan`**, with a higher local revision and a backlink digest to the previous encrypted plan bytes. It regenerates the entire PRIVATE offline coordination browser board and root index. Before atomic publication, every new original signed cockpit and root workroom is read through the same native admission under the new key. Failure leaves the old workroom and both key files unchanged.

This operator operation is **not** replacing a key in place, changing original source/provenance or silently updating existing recipients. Every previous archived encrypted copy and original key/receipt remains a valid copied artifact until separately handled under authorized human key-compromise/revocation processes. Rotation **cannot erase or revoke a previously copied shared key**, prevent old recipients from viewing old copies, or make compromised-key source assertions trustworthy.

### Alternative: use the unified PRIVATE workroom control interface

The already existing human operator console now exposes the **same complete rekey procedure** without extracting any source-free inbox/plan files yourself:

```sh
python3 remediation-cockpit-attestation/workroom_control.py rekey \
  --workroom "$HOME/private-lightup/lightup-human-workroom-OLD-ID" \
  --old-key-file "$HOME/private-lightup/team-key-v1.key" \
  --new-key-file "$HOME/private-lightup/team-key-v2.key" \
  --output-parent "$HOME/private-lightup"
```

It calls the exact same native `rekey_workroom.py` implementation, requires the original and new private team keys, publishes **only** a new entire workroom, and does not claim that old keys or already copied ciphertext have been revoked.

## 3. Use new workroom and key for future distribution

The tool prints the exact new `lightup-rekeyed-human-workroom-<random>` directory. Verify/read it with:

```sh
python3 remediation-cockpit-attestation/workroom_control.py inspect \
  --workroom "$HOME/private-lightup/lightup-rekeyed-human-workroom-NEW-ID" \
  --key-file "$HOME/private-lightup/team-key-v2.key"
```

Open its root `index.html` **locally only**. For a later encrypted multi-cockpit and private-plan handoff, use the existing `workroom.py send` with `--inbox "$NEW_WORKROOM/inbox"`, `--plan "$NEW_WORKROOM/plan.ltplan"` and `--key-file "$HOME/private-lightup/team-key-v2.key"`. From that moment the human team must explicitly coordinate use of the new key and retention/revocation of any earlier copies.

The procedure uses the already-approved local offline `cryptography` installation with Python 3.11+ on Linux. It performs no network transfer, package install, real-source export, scan, grant, native Apply, verified retest or deployment.

**Original held release gates unchanged:** exact-head hosted and permanent named VPS CI, original source-owner + independent security/privacy/browser/crypto review, open #177/#182/#829, separate genuine current client/operator consent with revocation-at-action, explicit HUMAN GO. This product remains **DRAFT/HOLD; do not merge or deploy**.
