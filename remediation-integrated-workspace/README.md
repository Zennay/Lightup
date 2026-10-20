# LightUp — Integrated PRIVATE offline remediation suite

**INCUBATE M3/M7 — PLAN/LAB ONLY — DRAFT/HOLD.** This is source-only offline software, not a released scanner, grant, authenticated evidence or verified remediation.

## Integrated original products

This branch includes existing original product assets unchanged from:
- [PR #1670](https://github.com/Zennay/Lightup/pull/1670): source-free recipient workload, comparison, HUMAN recipient journal, revision history and offline recipient browser.
- [PR #1661](https://github.com/Zennay/Lightup/pull/1661): complete original PRIVATE evidence relationship workrooms and independent source admission.
- [PR #1665](https://github.com/Zennay/Lightup/pull/1665): HUMAN Portfolio Studio and selective password-encrypted offline HUMAN action handoffs.
- Their pinned independent Casework and Evidence Artifact Ledger sources.

All **79 original software assets** are pinned by source-lock.json against the exact upstream source HEADs 6246550821039b829dc10ded95a1432c0653786f and 264bf15929e1f36699ea4114b91c5c313e55eea7. Original branch files are not rewritten. Their owners retain review authority.

## One-command offline installation

On an authorized trusted Linux machine with Python 3, inside a copy of this branch create a private parent directory first:

    mkdir -p "$HOME/lightup-private"
    chmod 700 "$HOME/lightup-private"
    python3 remediation-integrated-workspace/install.py build --output-dir "$HOME/lightup-private/integrated-workspace-v1"

The installer returns 2 = REVIEW_ONLY after local success, or 3 = HOLD on failure. Use an unused directory name. Open integrated-workspace-v1/index.html locally.

The new **private, 0700** folder contains the original 79 software-only files, a CSP/scriptless index linking four complete offline original application screens, source-lock.json, software-only.zip, and a SHA-256 manifest. The ZIP is ordered reproducibly and contains software, the installer, operator guide and landing page, but **no tenant data, evidence, login, credentials, private source workrooms or HUMAN notes**. All installed files are 0600. Never unpack or share this package outside a separately approved private environment. Optional original CLI cryptography functionality retains its documented local optional dependencies.

To check the installed folder's exact native file inventory and the locally generated software archive, without contacting any service:

    python3 remediation-integrated-workspace/install.py inspect --workspace "$HOME/lightup-private/integrated-workspace-v1"

Inspection enforces private file ownership/modes, regular nofollow one-link files, canonical warning and non-authority flags, exact installed SHA-256 file contents, ZIP-member byte identity, original source inventory and local scriptless portal renderer. It only establishes local consistency.

## Operator flow: maintain privacy boundaries

1. ORIGINAL SOURCE OWNER: open the offline index and use original Casework and Evidence Ledger. Review and prepare PRIVATE source-ledger workspaces using remediation-evidence-bundle-integrity/prepare.py per original operator guide. Original private records stay with the authenticated and separately authorized source owner. The human-only source-free PRIVATE Cockpit is an **explicitly separate** disclosure surface.
2. AUTHORIZED SOURCE-FREE RECIPIENT: on a trusted private destination re-admit a complete received source-free Cockpit with remediation-evidence-bundle-integrity/read_cockpit.py. Use remediation-recipient-trend/receiver_desk.py for anonymous workload series, locally human-ordered review and editable follow-up journals; use the standalone HUMAN Portfolio Studio to route anonymous follow-ups.
3. PRIVATE SELECTIVE HUMAN HANDOFF: use remediation-human-handoff/browser.html only for chosen recipient-appropriate source-free HUMAN action subset and, where required, local password encryption. The encrypted file does not authenticate the sender or authorize any action. Do not forward a full private owner workspace when only selected HUMAN questions are needed.

Native exact CLI commands and encrypted file/password handling are in the original adjacent README documents. Neither the launcher nor installer automatically executes scan, retest, remediation, grant, uploads, API calls or a consent decision.

## Actual non-authorization and release contract

Local SHA-256 source pins, manifests and zip checks are **unsigned and unkeyed**. They do not prove who authored source files, customer identity, legitimate consent, real evidence, fix, time order, security risk, verified retest or authority to act. Local encrypted browser files authenticate only their own ciphertext against the chosen passphrase and documented format; they do not authenticate real client/operator identity.

This is a DRAFT/HOLD composition branch, not a production merge. Required original gates remain: **exact-head hosted and permanent named VPS CI, original source-owner and independent security/privacy/browser/crypto review, original issues #177/#182/#829, genuine separately authenticated current client and operator consent with action-time revocation, and explicit HUMAN GO**. Until then: no merge to main, no production deploy, no active targets or native Apply. No QA, regression or test suite is created or run by this change; direct build/package inspection is not CI or security proof.
