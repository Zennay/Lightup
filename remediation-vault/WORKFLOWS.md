# LightUp · Complete offline human remediation workspace

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This is a local coordination preview, not a release, scope approval, real security finding, scan, retest, execution permission, or assertion that a finding is repaired. Every source, recipient, person, grant and engagement needs independent authentication and authorisation outside these offline apps.

## Getting started without a server

Unzip **LightUp-Private-Handoff-Vault.zip** onto a trusted, local device. Open **START-HERE.html** directly. Use the seven independent links for these separate, original human-only workflows:

| Screen | Original source and use | What you may export |
| --- | --- | --- |
| Evidence Review | Original held PR #1623; import separately authenticated five-column findings CSV and, if authorised, original Casework draft for same client and exact engagement | Human reviewer notes, local evidence references, source-bound drafts and anonymous aggregate only; never verified findings |
| Casework Calendar | Original held PR #1635; import original Casework v1 bound to exact current CSV | Tentative ICS, human follow-up drafts, owner-specific private packets and anonymous human workload |
| Owner Reply Desk | Original held PR #1635; import exact source-bound *single-owner* handoff from Calendar | PRIVATE original-owner human reply, not a grant or application |
| Dependency Board | Original held PR #1638; import original Casework v1 bound to same confirmed engagement | Tentative human dependencies and work estimates; does not issue actual remediation |
| Remediation Capacity Studio | Original held PR #1583; import separately authorized original findings and original Casework source | Hypothetical priority staffing, available hours, effort/backlog, anonymous weekly summaries |
| Remediation Funding Studio | Original held PR #1586; import original Capacity Studio aggregate export ONLY | Hypothetical budget/cash release timing and priority-based finance risk, never binding commitments |
| Encrypted Handoff Vault | Own isolated PR #1640; select already approved human-only local text exports | AES-256-GCM encrypted .vault.json; later separate local restore, re-encryption or minimal-files handoff |

### Recommended single-engagement operator workflow

1. Obtain genuine original source files through an independently authenticated client/operator channel, not through these apps. Check the actual legal scope, engagement, active consent and private channel outside the browser. Keep files on a trusted local machine.
2. Open **Evidence Review**. Load the exact original authorised findings CSV and, optionally, the matching original human Casework draft. Produce or update human-only evidence notes; never infer that a source finding was repaired simply because it disappeared later.
3. Open **Casework Calendar** separately. Re-open the original Casework v1 for that exact original finding set; plan only tentative human deadlines and prepare original private owner-scoped handoffs. Sending files must use a separate real authorised channel.
4. On the recipient device, open **Owner Reply Desk**. Import exactly the matching owner-specific packet. Produce a private reply. The original Calendar operator must independently re-open the same exact source and review the proposed before/after human fields before accepting changes.
5. Open **Dependency Board** to coordinate work prerequisites and illustrative critical-path dates using original Casework v1. Graph or dates never change the original verified finding, retest, grant or source-of-truth case status.
6. Open **Encrypted Handoff Vault** and import only the minimum exact original human coordination outputs the already-authorised recipient requires. Reconfirm actual recipient and exact engagement; use 12+ character passphrase and an *independent approved* password exchange. After receiving a vault, the recipient separately validates sender/client/engagement and only then chooses manual source downloads.
7. When preparing a subsequent recipient handoff, check off only the minimal restored files, create a second encrypted vault with fresh unique cryptographic parameters and private recipient confirmation. Old vaults remain decryptable if a recipient retains them; this is **not** revocation.

### Invariants & boundaries

- Each original app is **copied without edits** from an immutable original source-owner commit. `package_kit.py` pins the SHA-256 of every original HTML, refusing packaging if any original copied bytes change. The manifest includes source commit, path, PR number and file fingerprint.
- Apps are independent. The launcher cannot auto-transfer content, impersonate operators, access client databases, or turn file names/hash receipts into permission. All transfers use user-chosen local files and independent private human approval.
- A source SHA-256 or password only proves data has not been changed under the relevant scheme; it does not attest genuine issuer identity, current consent, scope, effectiveness of fixes or a passed retest.
- All apps and the launcher need **no network, server, password store, external resources or browser persistence** to function. Manual private file downloads remain sensitive plain text unless routed through the Vault.
- ZIP includes no findings, target details, private notes, passwords, authentic client identity, access tokens or user records. Do not commit user-created packet files.
- Original owner PRs #1623, #1635 and #1638 stay in DRAFT/HOLD and are not automatically promoted. This composition PR does not supersede original owners or their CI, privacy/security or human release approvals.
- Main merge/production deploy require original exact-head hosted and permanently registered named VPS CI, independent original source-owner/security/privacy signoff, genuinely separate authenticated client/operator consent with action-time revocation, #177/#182/#829, and explicit HUMAN GO.

## Offline distribution

`python3 remediation-vault/package.py` creates a SHA-CSP-pinned encrypted vault browser standalone. `python3 remediation-vault/package_kit.py` builds the complete pinned seven-app ZIP. Neither command runs tests, networks or deployment. Files remain available individually under `remediation-vault/partner-apps/` for original owner review.

To inspect the generated kit, open its **MANIFEST.json**: it lists every packaged file's SHA-256, size, original PR and exact immutable source commit. Never treat these fingerprints as permission or authentic client approval.
