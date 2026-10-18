# Client assessment request desk (draft / non-authorizing)

This is a **real client-origin request workflow**, not an execution console. It is
proposed **on top of** the persisted client/operator request-source and grant
binding repair in [draft PR #1570](https://github.com/Zennay/Lightup/pull/1570).
The source of truth remains the existing SQLite `DomainStore` and its
persisted-user, active-client and transaction-level checks. This CLI cannot
approve a request, make a grant, launch a scan, contact a target or accept a
fictional client/operator identity.

## Operator prerequisites

Only use with your **existing**, privately held LightUp database that already
contains your actual client login; never give this tool an uninitialized database,
public path, production deployment, or a shared terminal. The CLI refuses a
missing database and path symlinks, prompts for the account password on a
terminal, calls the existing `DomainStore.authenticate` and resolves the
persisted user role/tenant through `context_for_user`. No operator login can
impersonate a client, including by supplying client IDs. Account lockout remains
owned by the existing domain. Do not put passwords, secrets, or customer proof
material in `--notes`.

From an installed LightUp source tree:

```sh
# Offline preview; no database, network, grant or target interaction.
python -m lightup.client_request_cli preview \
  --asset example.org --asset 192.0.2.0/24 --risk 2 \
  --notes "Proposed scope for discussion"

# One intentional client-origin submission (interactive terminal password).
python -m lightup.client_request_cli submit \
  --db /private/lightup.sqlite --email client@example.org \
  --asset example.org --risk 2 \
  --notes "Request independent operator review" --confirm-submit

# Return only your own stored request states, without asset inventory.
python -m lightup.client_request_cli list \
  --db /private/lightup.sqlite --email client@example.org

# Inspect one of your own submitted requests.
python -m lightup.client_request_cli show \
  --db /private/lightup.sqlite --email client@example.org \
  --request-id 'request-uuid-from-submission'
```

## Private browser timeline

After authenticating on a local terminal, a client may save a read-only browser snapshot:

```sh
python -m lightup.client_request_cli export \
  --db /private/lightup.sqlite --email client@example.org \
  --output /private/client-requests.html
```

This creates a **new exclusive 0600 HTML file** with the client's stored
request status history (up to 200 entries). Original text is HTML-escaped.
It requires no scripts, external styles, network connections or browser login,
and the original SQLite records are never changed. A saved HTML copy is
**unsigned, potentially sensitive and stale**; it is not proof of current
identity, consent, grant or retest status. Do not share it publicly.
Existing destination files cannot be overwritten.

## Direct intake from the existing Scope Planning Studio (#1567)

Create a proposal in the existing [Scope Planning Studio](../studio/scope-proposal.html)
and export its `lightup.scope_proposal_draft` v1 JSON. That offline studio is
a separate owner-held draft PR and does not submit or authenticate anything.

```sh
# No login or database; read the untrusted browser export and revalidate.
python -m lightup.client_request_cli preview \
  --proposal ~/Downloads/lightup-scope-draft.json

# Explicit client-authenticated submission of the *same* validated proposal.
python -m lightup.client_request_cli submit \
  --db /private/lightup.sqlite --email client@example.org \
  --proposal ~/Downloads/lightup-scope-draft.json \
  --expect-proposal-sha256 "<64 lowercase hexadecimal characters from preview>" \
  --confirm-submit
```

The `preview` response includes a locally computed `proposal_file_sha256` over
**the exact input bytes**. Copy this digest to `submit --expect-proposal-sha256`.
Submission refuses a missing or changed digest before prompting for account
credentials. This unsigned checksum is a version-continuity guard, **not**
a signature, authenticated identity, client consent or permission. The digest
is copied to request notes as a clearly untrusted operator handoff hint.

The importer never trusts a draft's unsigned SHA-256, self-declared client
label or `authorization` flags. It requires an exact bounded v1 format,
literal `false` authority/consent/grant/execution flags and unique JSON keys,
then runs the same canonical domain-bound asset parser as raw CLI input.
Unrecognized fields and malformed UTF-8 fail closed.

**No silent scope widening:** native `DomainStore.submit_assessment_request`
currently stores requested assets, mode, risk and notes, but does *not* store
the Studio's exclusions, local/UTC schedule or private-lab activity settings.
Consequently proposals containing **any exclusions, time windows or lab
activities are held**, not submitted. Resolve these constraints through
actual source-owner work and independent operator review; never erase them
solely to force acceptance. `analysis_only` Studio proposals also cannot be
submitted as `authorized_assessment` by implicit conversion. Ordinary
passive/configuration activity labels remain clearly marked as
*requested planning activities (NOT permissions)* in notes.
A browser fingerprint is at most an unsigned version hint, never consent or
identity verification. Clients authenticate separately at submission time.

The assets use the **same strict literal parser** as the draft domain request
binding: canonical lower-case DNS names, canonical IP literals, or strict CIDRs.
No wildcards, URLs, port suffixes, whitespace, Unicode aliases, DNS lookups or
host-bit CIDRs. Repeats are rejected, rather than silently expanding a scope.
The preview is not a proof of ownership or consent, nor is it equivalent to
an approval. Clients can propose risk levels **1–4** only. Submission requires
an explicit `--confirm-submit` flag; it writes exactly one native request using
the existing client-authenticated domain method, without issuing a grant.

`list` shows the most recent 100 requests and intentionally omits scope and
notes; `show` exposes one record after the same tenant checks. All output
clearly states that request state is not execution authorization. JSON output
is intended for a **private** local terminal and should not be published:
request IDs, assets, notes, and other fields can still be sensitive.

## Release posture

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This child PR is a
source-owner-isolated implementation proposal, not a live service or consent
mechanism. It must not be merged/deployed/used for real assessments until its
upstream domain fixes, original hosted and registered VPS CI, separate real
client/operator consent including at-use revocation, independent security and
privacy review, and explicit human GO are complete. Even an approved request
is *not* an active grant. Offline preview has no external calls; commands that
use a database operate on the selected local database only.

No new QA tests, QA workflow or synthetic release gate are added.
