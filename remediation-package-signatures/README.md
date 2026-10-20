# LightUp offline software custody signatures — DRAFT/HOLD

An independent **new-only** signing and recipient workflow for the original PRIVATE
software-only.zip produced by the **held** remediation-integrated-workspace/ source
branch. This folder changes no original receiver, evidence, scanner, grant, CI,
tenant or worker-owned source file. It is not included in the original portable
ZIP and does not require the original product to adopt the signer.

## What is actually authenticated?

Ed25519 verifies that **these exact ZIP bytes** were signed by a holder of the
private signing key corresponding to a **separately trusted public-key fingerprint**.
The signer produces a small canonical JSON sidecar containing the exact ZIP SHA-256,
byte length, purpose, schema and domain-separated 64-byte signature.

The receiver must obtain the public key **and its SHA-256 DER/SPKI fingerprint through
a trustworthy, separate channel**; a fingerprint supplied inside an untrusted
handoff is not trust. SHA-256 here identifies exact bytes; the digital signature,
not the unsigned digest, is the authenticity check.

This does NOT authenticate the original GitHub/source owner, ensure actual client
or operator identity, verify consent, confer permission to scan/apply, or satisfy
security review, exact-head CI, remediation or release gates. A signer could sign
an unsafe or unapproved ZIP. The original source-lock receiver is a **second**
independent gate and still yields REVIEW_ONLY / DRAFT/HOLD.

## Dependencies

Requires Python 3.11+ and an independently installed cryptography package.
For a disposable, local offline venv install from a previously approved and
available package source using requirements.txt. This tool **never installs**
packages, contacts a package index or accesses targets by itself.

## Owner: create an encrypted keypair locally

    python3 remediation-package-signatures/offline_signatures.py keygen \
      --directory /ABSOLUTE/PRIVATE/PATH/new-signing-keys

The key directory must be fresh; private and public files are created without
overwrite at mode 0600 inside a new mode 0700 directory. The private key is
encrypted with the interactively entered passphrase (at least 12 characters);
it is never accepted in command arguments, logs or ENV. Preserve it securely
and share **only the public key and a separately verified fingerprint**.

## Owner: sign an existing original software-only ZIP

First run the original offline build in a separate owner-only area.
Never bundle customer evidence/credentials in the software archive.

    python3 remediation-package-signatures/offline_signatures.py sign \
      --archive /ABSOLUTE/PRIVATE/PATH/software-only.zip \
      --private-key /ABSOLUTE/PRIVATE/PATH/new-signing-keys/signing-private.pem \
      --receipt /ABSOLUTE/PRIVATE/PATH/software-only.lusig.json

The receipt is published as a **new** 0600 file; overwrite, existing path and
symbolic-link input are refused. Only previously built regular local ZIP bytes
up to 32 MiB are admitted. Signing makes no release assertion.

## Recipient: verify signature (without extracting)

    python3 remediation-package-signatures/offline_signatures.py verify \
      --archive /ABSOLUTE/PRIVATE/PATH/software-only.zip \
      --receipt /ABSOLUTE/PRIVATE/PATH/software-only.lusig.json \
      --trusted-public-key /ABSOLUTE/PRIVATE/PATH/signing-public.pem \
      --trusted-fingerprint 64-lowercase-hex-trusted-out-of-band

A successful verification prints VERIFIED for the exact signed ZIP **only** and
exits **2 = REVIEW_ONLY**, intentionally not a release-success 0. Every HOLD
(including changed ZIP, malformed receipt, changed key, forged signature or
unexpected digest) exits **3** and produces no extracted files.

## Recipient: one command verify → original atomic source-only receive

Use an **already-present original, unchanged repository source checkout** and
a fresh output directory under an owner-private parent. The original native
receiver enforces its own pinned source inventory, owner-only ZIP inputs, 0700
directory / 0600 files, atomic no-overwrite publication, and local inspection.

    python3 remediation-package-signatures/verified_receive.py \
      --archive /ABSOLUTE/PRIVATE/PATH/software-only.zip \
      --receipt /ABSOLUTE/PRIVATE/PATH/software-only.lusig.json \
      --trusted-public-key /ABSOLUTE/PRIVATE/PATH/signing-public.pem \
      --trusted-fingerprint 64-lowercase-hex-trusted-out-of-band \
      --output-dir /ABSOLUTE/PRIVATE/PATH/fresh-received-suite

This invokes signature verification **before** original receiver ZIP parsing
and publication, captures the exact cryptographically verified bytes in a
fresh private 0600 temporary file for native admission (no re-open race against
the original user-supplied ZIP), removes this temporary snapshot, and invokes
original installed source-lock inspection.
The two verifiers are independent; neither authenticates contemporary customer
identity or consent. No private key crosses to the recipient. No network.

## Optional two-key co-signing: stronger offline custody, not authorization

For deployments where two separately held, independently trusted Ed25519 keys
are available, a second human signer can sign the **same exact ZIP** separately
with the regular sign command and their own encrypted private key, producing a
second receipt. The recipient can require **both** signatures to verify on the
same bytes and on two **distinct independently trusted fingerprints** BEFORE
running the original source-lock receiver:

    python3 remediation-package-signatures/verified_receive.py \
      --archive /ABSOLUTE/PRIVATE/PATH/software-only.zip \
      --receipt /ABSOLUTE/PRIVATE/PATH/first.lusig.json \
      --trusted-public-key /ABSOLUTE/PRIVATE/PATH/first-public.pem \
      --trusted-fingerprint FIRST-TRUSTED-64-HEX \
      --second-receipt /ABSOLUTE/PRIVATE/PATH/second.lusig.json \
      --second-trusted-public-key /ABSOLUTE/PRIVATE/PATH/second-public.pem \
      --second-trusted-fingerprint SECOND-TRUSTED-64-HEX \
      --output-dir /ABSOLUTE/PRIVATE/PATH/fresh-cosigned-suite

All three second-key flags are required together; a second signature made by
the SAME key is refused. A second signer does **not** grant independent
security approval, customer authorization or HUMAN GO. It only provides two
cryptographic possession proofs over matching bytes.

## Portable single-file handoff (original software bytes ONLY)

When the recipient should not juggle three separate untrusted files, wrap the
already signed software ZIP, sidecar receipt and public key in one bounded
software-only transport ZIP. The package **cannot carry client evidence, notes,
credentials or authority** under this exact three-member format.

First, the sender independently verifies the original signature and creates a
new 0600 archive without overwrite:

    python3 remediation-package-signatures/portable_handoff.py pack \
      --archive /ABSOLUTE/PRIVATE/PATH/software-only.zip \
      --receipt /ABSOLUTE/PRIVATE/PATH/software-only.lusig.json \
      --trusted-public-key /ABSOLUTE/PRIVATE/PATH/signing-public.pem \
      --trusted-fingerprint 64-lowercase-hex-trusted-out-of-band \
      --output-bundle /ABSOLUTE/PRIVATE/PATH/software-only.portable.zip

The receiver provides the expected public-key fingerprint **from a separate
trusted channel**, NEVER from the portable ZIP itself, and admits the original
source-only suite into a fresh owner-private directory:

    python3 remediation-package-signatures/portable_handoff.py receive \
      --bundle /ABSOLUTE/PRIVATE/PATH/software-only.portable.zip \
      --trusted-fingerprint 64-lowercase-hex-trusted-out-of-band \
      --output-dir /ABSOLUTE/PRIVATE/PATH/new-portable-receiver

Portable admission allows exactly three named regular ZIP_STORED files, one ZIP
and one small receipt and Ed25519 public key, with strict member/type/size/mode
and duplicate-member constraints. The transport is read into bounded memory;
contained files are written only into a fresh private temporary directory.
The existing signature verifier, race-free private byte snapshot, original native
receiver and source-lock inspector then run; the temporary directory is cleaned
up. Untrusted embedded public-key bytes are never treated as self-authorizing:
they must match the out-of-band trusted fingerprint and prove the signature.

### Portable two-key custody — no silent quorum downgrade

For a portable bundle that must preserve the previously required two distinct
signatures, add the following three arguments to portable_handoff.py pack:

    --second-receipt /ABSOLUTE/PRIVATE/PATH/second.lusig.json
    --second-trusted-public-key /ABSOLUTE/PRIVATE/PATH/second-public.pem
    --second-trusted-fingerprint SECOND-64-HEX-TRUSTED-INDEPENDENTLY

The outer ZIP then has exactly five fixed members: original source-only ZIP,
two small signed receipts and two public keys, with neither private key inside.
The receiving operator MUST pass --second-trusted-fingerprint with a value
received independently out of band. Supplying a second-key fingerprint for
a one-signature package, or omitting it for a co-signed package, is a HOLD,
not a fallback to one signer. The two keys must differ and their receipts must
verify over the same exact software bytes.

This provides byte-custody quorum, NOT source identity, approval, release
authorization or any client consent. The original native source inventory,
security, consent and HUMAN gates remain unchanged.

All CLI successes intentionally exit 2 (**REVIEW_ONLY**), not 0. Run the pack
and receive commands separately; a shell chain with && will stop at the pack's
2 even though the handoff file was created. Failures HOLD with exit 3.

## Complete HUMAN operator desk: trusted keys → PRIVATE software inbox

The previous workflows can now be operated through one foreground, offline
menu. This is **review-only** and has no scanner, model, HTTP, login, consent,
grant, remediation or deploy capability.

First prepare your own *new* 0700 directory (private, not inside Git). Any
keys used in the earlier synthetic VPS example are disposable and do not
establish trustworthy real-world identity.

    mkdir -m 700 /ABSOLUTE/OWNER/PRIVATE/custody-workroom

Then launch the local operator console:

    python3 remediation-package-signatures/operator_desk.py \
      --workdir /ABSOLUTE/OWNER/PRIVATE/custody-workroom

The six menu actions create an owner-only local trust registry, register an
Ed25519 public key ONLY after manual out-of-band fingerprint confirmation,
list local trust with revoked markers, admit 1–12 selected source-only
portable ZIPs, reopen an existing inbox against **current** key state and the
original LightUp source-lock inspector, and permanently revoke a registered
signer. Everything runs in the **foreground**; the menu never automatically
browses, executes software or sends a file.

Equivalent direct commands are available for scripting an explicitly human
approved **offline** workflow. Success always exits 2 REVIEW_ONLY:

    python3 remediation-package-signatures/trust_registry.py init \
      --directory /ABSOLUTE/OWNER/PRIVATE/custody-workroom/local-trust-registry

    python3 remediation-package-signatures/trust_registry.py register \
      --directory /ABSOLUTE/OWNER/PRIVATE/custody-workroom/local-trust-registry \
      --public-key /ABSOLUTE/OWNER/PRIVATE/signer-public.pem \
      --trusted-fingerprint 64-lowercase-hex-verified-out-of-band \
      --label "Source-only custody key A"

    python3 remediation-package-signatures/trust_registry.py list \
      --directory /ABSOLUTE/OWNER/PRIVATE/custody-workroom/local-trust-registry

    python3 remediation-package-signatures/inbox.py \
      --keyring /ABSOLUTE/OWNER/PRIVATE/custody-workroom/local-trust-registry \
      --bundle /ABSOLUTE/OWNER/PRIVATE/first.portable.zip \
      --bundle /ABSOLUTE/OWNER/PRIVATE/second.portable.zip \
      --require-two-signers \
      --output-dir /ABSOLUTE/OWNER/PRIVATE/custody-workroom/fresh-inbox

Each accepted original source-only software ZIP is received with the existing
native receiver into a separate private suite folder. **Only after all
original source-lock admissions** succeed is the entire inbox published
atomically without replacing existing output. The resulting scriptless
private index.html links to each original installed offline suite and displays
only signer label, truncated fingerprint, package byte digest and REVIEW_ONLY.
Input order is NEVER represented as validated release chronology.

To re-admit an earlier inbox using the latest locally registered and
non-revoked keys and current ORIGINAL pinned software:

    python3 remediation-package-signatures/inbox_reopen.py \
      --keyring /ABSOLUTE/OWNER/PRIVATE/custody-workroom/local-trust-registry \
      --workspace /ABSOLUTE/OWNER/PRIVATE/custody-workroom/fresh-inbox \
      --require-two-signers

To permanently revoke a local key (no automatic previously downloaded file
retraction, no unilateral return to trusted state):

    python3 remediation-package-signatures/trust_registry.py revoke \
      --directory /ABSOLUTE/OWNER/PRIVATE/custody-workroom/local-trust-registry \
      --trusted-fingerprint 64-lowercase-hex-fingerprint-to-revoke

### Persistent minimum signing policy: no accidental two-to-one downgrade

Once TWO distinct public keys have been independently validated and registered,
the operator can permanently require two **currently trusted** Ed25519 signers
for all future inbox imports and reopens. Use operator desk menu option 7 or:

    python3 remediation-package-signatures/trust_registry.py require-two \
      --directory /ABSOLUTE/OWNER/PRIVATE/custody-workroom/local-trust-registry

This creates a private immutable local two-signer minimum marker (0600,
durable directory fsync). The listing command shows the current minimum.
The CLI's single-signature option cannot weaken this rule; higher persistent
local policy is applied even when the two-signer flag was omitted. New inboxes
also record their enforced original minimum. Reopen uses the stricter of
that recorded minimum, the current registry minimum, and the caller choice.
Old inboxes using the original schema remain readable under the current
registry floor, but can never silently lower it. Revoked keys do not qualify.

The marker is only a local owner-controlled custody policy. It is **not** an
authenticated organisational approval, remotely enforced permission or
tamper-proof policy against an attacker controlling the same local account.
It cannot make any archived software safe to deploy. The original exact-head
CI, source-owner review, independent crypto/security/privacy review, genuine
separate client/operator consent, revocation at use and HUMAN GO still govern
all release and active actions.

**Security and privacy limits of this HUMAN workflow:**
- Registration relies on the HUMAN already having independently authenticated
  the *correct* out-of-band fingerprint. A signature does not establish the
  signer is a given customer, source author, approver or other person.
- This is a **LOCAL** trust list, not a PKI, certificate authority, client
  consent database, authentication login or remote revocation service.
- The local static HTML viewer cannot query current revocation state.
  Foreground **inbox_reopen.py** is required for a fresh local decision.
  Even this cannot retract copies or prevent a user opening old local HTML.
- Only original source-only software ZIP archives are admitted; not arbitrary
  private evidence bundles, client files, remediation claims or HUMAN notes.
- An invalid current key/receipt/source or duplicate original archive identity
  refuses the entire fresh inbox before publication. No partial product is
  described as admitted.
- Merely having two local signatures does not mean two separately authenticated
  people approved the package; independent external identity verification and
  release reviews remain outside this tool.

## Compare 2–12 independently admitted ORIGINAL software inboxes

This is a separate user-facing offline source-difference desk. It helps the
operator understand **what software bytes and local signer fingerprints
differ**, without claiming that a new package is approved, fixes a
vulnerability, is chronologically newer or carries current consent.

Choose 2–12 existing PRIVATE inbox folders, each containing exactly one
previously received, source-locked original LightUp software-only ZIP. Each
input is independently re-admitted using the **current** local non-revoked
keyring, its original native receipt, both signers where required, the
byte-identical scriptless HTML, and the original native source inspector.
Only then is an independent PRIVATE, scriptless source-change report
published atomically with a bounded locally derived JSON receipt:

    python3 remediation-package-signatures/software_revision_desk.py \
      --keyring /ABSOLUTE/PRIVATE/PATH/local-trust-registry \
      --inbox /ABSOLUTE/PRIVATE/PATH/first-admitted-inbox \
      --inbox /ABSOLUTE/PRIVATE/PATH/second-admitted-inbox \
      --output-dir /ABSOLUTE/PRIVATE/PATH/new-software-difference-desk

The HUMAN operator may provide more --inbox arguments, up to twelve, or choose
**option 8** in operator_desk.py. The input order means ONLY the order the
operator selected; it is NOT verified chronology or proof that any proposed
package supersedes a prior one. The report shows exact software ZIP digests,
file counts, the source inventory digest, each original source file path whose
signed-installed bytes are added/removed/changed, and selected old/new local
signing-key fingerprints. It neither copies private evidence/credentials nor
compares customer vulnerabilities. New human decisions remain external.

An existing native software source-lock version must be available to inspect
each selected original inbox. A historical package that the CURRENT installed
original source owner cannot re-admit is HOLD; this desk will NOT bypass the
original pin and will NOT invent a diff. An existing diff is a static private
snapshot. Generate a new diff after key revocation or input change; a saved
HTML file cannot enforce current trust or remote revocation by itself.
Original CI, independent reviews, client/operator consent, and HUMAN GO
remain mandatory for any actual release.

## Private historic software impact desk after LOCAL signer revocation

Revoking a local trust record stops normal **fresh admission/reopen**, but it
cannot pull back software already downloaded by another operator. The
independent offline impact desk permits a **read-only inventory** of old
original signed software, *including packages signed by now-revoked keys*,
WITHOUT upgrading such packages to trusted status.

The user explicitly selects 1–12 previous, owner-private original software
inboxes, up to 24 total original source-only packages. Each original ZIP
byte digest, all original Ed25519 signatures and original native installed
source inventory are checked before the tool derives the local status for
each original key. The output is a fresh PRIVATE scriptless HTML and
source-bound JSON report showing signed original software digests, locally
REVOKED signers, and clear HUMAN follow-up, with no client data, permissions
or remediation verification.

    python3 remediation-package-signatures/revocation_impact.py \
      --keyring /ABSOLUTE/OWNER/PRIVATE/custody-workroom/local-trust-registry \
      --inbox /ABSOLUTE/OWNER/PRIVATE/custody-workroom/earlier-inbox \
      --output-dir /ABSOLUTE/OWNER/PRIVATE/custody-workroom/new-impact-desk

Use **operator desk menu option 9** for the same private, foreground flow.
Even when the archived original signature is cryptographically valid, a
currently REVOKED signer is shown as **LOCAL_REVOKED_HOLD**. This never
restores trust, never issues an authorization or pretends prior distribution
can be erased. The key's old human label and the current HUMAN label may
differ between two independently curated local registries; the actual
Ed25519 public key fingerprint, not a human label, defines byte identity.

Local revocation records can be managed only by the owner-controlled local
registry; they are not remotely authenticated client consent or a distributed
PKI. The impact report is a static private snapshot and must be regenerated
when key state changes. The original source-owner, security/privacy reviews,
mandatory exact-head CI, explicit separate current consent, action-time
revocation and HUMAN GO remain outside these tools.

## Complete twelve-action foreground custody console

The single operator_desk.py integrates the entire offline HUMAN journey:

1. Create new private local trust registry.
2. Register trusted public Ed25519 key after independent fingerprint review.
3. List registered and revoked keys with permanent local signer minimum.
4. Atomically receive 1–12 original signed source-only software archives.
5. Reopen private software inbox with currently registered keys and ORIGINAL source pins.
6. Permanently revoke local trust in a signer.
7. Permanently require two distinct currently trusted signers.
8. Review exact source file and signing-key byte differences across 2–12 original inboxes.
9. Review LOCAL revoked key impact across existing original signed software.
10. Generate a NEW encrypted Ed25519 private/public keypair in fresh private folder.
11. Sign an original software-only archive with interactive hidden private-key passphrase.
12. Package signed original source-only software ZIP into one private portable file,
    optionally requiring a second distinct independently verified signing key.

No original source owner code, grant, scanner, model, active execution path or
production entrypoint is modified. Signing passphrases are never accepted as
CLI flags and no private PEM is automatically registered or included in ZIP.
New files are exclusive owner-private outputs, not overwrites. Operator source
files are not included in the original locked installed suite without separate
original owner review. Success exits 2 REVIEW_ONLY, never a release PASS.

## Limits and operational risks

- Password/key loss cannot be recovered; do not store the private PEM in Git.
- A passphrase protects keys at rest but not a compromised host or memory.
- The locally verified public key requires **out-of-band origin validation**.
- Self-signed receipts, even if cryptographically valid, do not imply independent
  code review or security approval.
- The ZIP signature binds complete compressed bytes, not semantic correctness;
  original receiver checks original member inventory and pinned source bytes.
- A modified upstream integrated studio needs its **own** original receiver
  review, lock and compatible signer/recipient composition. Do not silently
  restack or absorb currently claimed upstream source.
- Only use on source-only offline software. Do not include real client evidence,
  secret material or private HUMAN notes in this signature receipt workflow.
- No QA/regression/test suites are shipped or run here.

**Posture:** Notion INCUBATE, M3/M7 PLAN/LAB ONLY, DRAFT/HOLD. Hosted
and permanently registered exact-head VPS CI, independent privacy/security/crypto
review, original source-owner sign-off, #177/#182/#829 where applicable,
separately authenticated current client and operator consent with use-time
revocation, and explicit HUMAN GO remain unchanged release requirements.
