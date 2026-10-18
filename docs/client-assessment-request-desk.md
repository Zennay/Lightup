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
