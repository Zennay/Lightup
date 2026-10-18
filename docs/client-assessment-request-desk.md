# Client assessment request desk (draft / non-authorizing)

This is a **real client-origin request workflow**, not an execution console. It is
proposed **on top of** the persisted client/operator request-source and grant
binding repair in [draft PR #1570](https://github.com/Zennay/Lightup/pull/1570).
The source of truth remains the existing SQLite `DomainStore` and its
persisted-user, active-client and transaction-level checks. This CLI cannot
approve a request, make a grant, launch a scan, contact a target or accept a
fictional client/operator identity.

## Interactive client request desk (full workflow)

The original CLI now has a real interactive local terminal workspace.
Clients do not need to manually assemble every separate preview and submit
command or copy a SHA-256 for ordinary menu-based submissions.

```sh
python -m lightup.client_request_cli desk \
  --db /private/lightup.sqlite --email client@example.org
# Direct installed module entry is also available:
python -m lightup.client_request_desk \
  --db /private/lightup.sqlite --email client@example.org
```

Manual intake in the desk accepts up to 80 canonical asset entries and
multiline safety notes: finish notes with a single period (`.`) on its own
line, within the 4000-character limit. After seeing the normalized request,
the client can optionally create a private 0600 HTML preview, then either
decline or type the explicit submission phrase. During rejected-request
revision, a separate private 0600 before/after comparison can likewise be
saved **before** deciding whether to create the new request. These saved
documents are not network-published or considered current consent.

The desk requires a **private interactive TTY** and authenticates with
`DomainStore.authenticate` using a hidden password prompt. It then offers:

1. **Own request inbox:** latest 30 current tenant-owned request statuses,
   preserving the independent operator review meaning.
2. **Manual request creation:** guided exact hostname/IP/CIDR entry,
   risk 1–4, and explanation; canonicalizes with the native domain binding
   parser. Shows the full normalized request before submission.
3. **Existing Studio v1 import:** reads the exported JSON locally using the
   same strict Studio importer as `preview --proposal`. Exclusions,
   scheduled windows and private lab activities still HOLD rather than
   silently disappearing.
4. **Revision after rejection:** choose a genuinely rejected own request,
   then manual or Studio replacement. Shows changes and requires a separate
   typed expansion acknowledgement if assets or risk widen. Never edits the
   original rejected record.
5. **Inspect own stored request** by ID, including originally requested assets,
   risk and notes; no operator impersonation or cross-tenant access.
6. **Export private HTML inbox:** at most the most recent 200 stored requests
   into a new exclusive permission-`0600` file, without scripts or network.
   Earlier requests remain in SQLite and are **not** claimed to be exported
   if the client has more than 200.

Every submission requires explicitly typing `SUBMIT NEW REQUEST`.
An existing submitted/under-review request with **the same asset identities
(regardless of ordering) and requested risk**, even when its explanation
differs, causes a warning and requires typing `REPEAT REQUEST` as well.
This helps avoid parallel duplicate reviews; it is an advisory pre-submit
read, not atomic server-side deduplication. No request is submitted merely by importing
a Studio draft or viewing an inbox. For rejected revision expansion,
the client must additionally type `ACKNOWLEDGE EXPANSION`.
Even an approved assessment request is **not** a grant or scan permit.

The multi-action desk checks persisted user role/tenant, active-client state
and credential-update generation before each menu action, then checks again
**immediately before** writing a request or exporting a sensitive HTML file.
A changed password, deactivated client or tenant/role change terminates
the session. The native `DomainStore.submit_assessment_request` still
enforces actual client provenance inside its own write transaction; the
desk's freshness check is not a replacement for that security boundary.

This is strictly a **local request-accounting CLI**. It does not connect to
targets, create sessions for the browser, issue grants, approve requests,
dispatch handlers, verify target ownership, or turn a planning document into
client/operator consent. The original explicit noninteractive CLI remains
supported for reproducible use.

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
  --notes "Request independent operator review" \
  --expect-intake-sha256 "<exact intake_sha256 from preview>" \
  --confirm-submit

# Return only your own stored request states, without asset inventory.
python -m lightup.client_request_cli list \
  --db /private/lightup.sqlite --email client@example.org

# Inspect one of your own submitted requests.
python -m lightup.client_request_cli show \
  --db /private/lightup.sqlite --email client@example.org \
  --request-id 'request-uuid-from-submission'
```

## Review the exact client proposal visually before submission

Both the manual input path and the existing Studio JSON intake support a
private, browser-readable **no-script local preview**. No authentication or
database access occurs in this preview step; a signed-in client must submit
separately.

```sh
python -m lightup.client_request_cli preview \
  --asset app.example.org --risk 2 \
  --notes "Proposed scope and safety limits for operator discussion" \
  --output /private/assessment-proposal-preview.html

python -m lightup.client_request_cli preview \
  --proposal ~/Downloads/lightup-scope-draft.json \
  --output /private/studio-intake-preview.html
```

Every ordinary `submit` additionally requires the `intake_sha256` shown by `preview` via\n`--expect-intake-sha256`, even for manually entered assets. Any change to the\nnormalized assets, risk or notes requires a new preview, not just the same\n`--confirm-submit` flag. This is an unsigned review continuity guard only.\n\nThe output is an exclusive mode-`0600` HTML file containing the **exact
normalized assets and risk**, a readable safety notice and (when present) the
source Studio proposal's SHA-256 file-continuity hint. The document contains
no JavaScript, network requests, forms or remote resources. It is *not* a
verified ownership claim, operator decision, consent signature, executable
grant or completed submission. It is sensitive and should stay private.

## Private browser timeline

After authenticating on a local terminal, a client may save a read-only browser snapshot:

```sh
python -m lightup.client_request_cli export \
  --db /private/lightup.sqlite --email client@example.org \
  --output /private/client-requests.html
```

The snapshot now includes an **accessible, no-script status dashboard** linking to\nclient requests by submitted, under-review, administratively-approved and\nrejected status. Statuses and next-step copy do not imply a permission, grant\nor scan right.\n\nThis creates a **new exclusive 0600 HTML file** with the client's stored
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
  --expect-intake-sha256 "<exact intake_sha256 from preview>" \
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

## Exact review-before-resubmission continuity

A rejected client's `revise-preview` now produces **two unsigned digests**:
`previous_record_sha256` for the original stored request and
`revision_sha256` for the complete proposed replacement (assets, risk, notes,
scope expansion facts and source version). Both must be passed to
`revise-submit`: `--expect-original-sha256` and
`--expect-revision-sha256`. Changing either the original or ANY part of the
replacement requires a new preview. The private before/after browser report
shows both digests.

A replacement may alternatively be imported from the **existing** offline
Studio v1 export:

```sh
python -m lightup.client_request_cli revise-preview \
  --db /private/lightup.sqlite --email client@example.org \
  --request-id 'rejected-request-uuid' \
  --proposal ~/Downloads/updated-studio-scope.json \
  --output /private/request-revision-review.html

python -m lightup.client_request_cli revise-submit \
  --db /private/lightup.sqlite --email client@example.org \
  --request-id 'rejected-request-uuid' \
  --proposal ~/Downloads/updated-studio-scope.json \
  --expect-original-sha256 '<previous_record_sha256 from preview>' \
  --expect-revision-sha256 '<revision_sha256 from preview>' \
  --expect-proposal-sha256 '<proposal_file_sha256 from preview>' \
  --confirm-new-request
```

An expanded proposed asset range or risk still requires
`--confirm-scope-expansion`. The Studio import **refuses** exclusions,
scheduled windows and lab-active activities that the current durable request
schema cannot enforce, even for revisions. The SHA values are local
version-continuity hints, **never** verified client consent or grants.

## Revise an independently rejected client request

A rejected request remains part of the original review history. Client members
can **create a new proposal** based on an earlier rejected request, but cannot
rewrite that rejection, change the operator's decision, inherit authorization or
change a grant. Authentication and tenant isolation use the existing persisted
`DomainStore` client checks; the previously rejected record must belong to the
current authenticated client.

```sh
# Login; compare existing rejected request with revised inputs.
# All unchanged values (except fields explicitly replaced) are proposed again.
python -m lightup.client_request_cli revise-preview \
  --db /private/lightup.sqlite --email client@example.org \
  --request-id 'original-rejected-request-uuid' \
  --asset app.example.org --risk 2 \
  --notes "Updated assessment rationale and client safety constraints" \
  --output /private/request-revision-review.html

# Carefully read the printed source SHA-256 and the optional private HTML report.
# Submit a completely NEW request with independent operator review.
python -m lightup.client_request_cli revise-submit \
  --db /private/lightup.sqlite --email client@example.org \
  --request-id 'original-rejected-request-uuid' \
  --asset app.example.org --risk 2 \
  --notes "Updated assessment rationale and client safety constraints" \
  --expect-original-sha256 '<original 64-character digest from revise-preview>' \
  --expect-revision-sha256 '<complete replacement digest from revise-preview>' \
  --confirm-new-request

# If the new assets include additional CIDR/hostname coverage or risk rises,
# add the deliberate acknowledgement --confirm-scope-expansion.
```

**No live authority:** The CLI reads only an already **REJECTED**
`authorized_assessment` request, refuses identical/no-op submissions, computes
the changed literal hostname/CIDR coverage and risks, and requires the original
stored request's exact version SHA-256 to match before a fresh submission.
An increased risk or expanded scope requires explicit
`--confirm-scope-expansion`; that acknowledgement is **NOT operator approval**.
The newly submitted record starts at `SUBMITTED`, under a new UUID, with a
clearly client-supplied predecessor reference in its *notes only*.
The existing database has no authoritative revision-lineage relation: the
note/reference and SHA-256 are **untrusted hints**, not signatures or bindings.

Scope difference comparisons now use the **effective same-family CIDR union**.
For example, two adjacent IPv4 `/25` blocks representing precisely the same
range as one `/24` do not trigger an artificial expansion warning. IPv4
and IPv6 are evaluated independently; DNS hostnames remain literal and are
never resolved to IP addresses. Any genuinely newly covered asset or elevated
risk still requires `--confirm-scope-expansion`. These are review hints only,
not authorization-policy decisions.

The optional **private visual comparison** is an escaped, no-script/no-network
HTML snapshot saved to a *new* file with mode `0600`; it shows before/after
assets, added/widened and removed/narrowed declarations, risks and next steps.
It cannot submit requests, contact targets, confer approval or prove current
status. Source history remains unchanged and a separate real operator
assessment decision must be made for each new request.

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
