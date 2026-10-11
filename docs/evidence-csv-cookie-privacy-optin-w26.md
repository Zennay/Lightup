# W26 — opt-in session-cookie CSV privacy HOLD gate

**DRAFT / HOLD / M3-M7 PLAN/LAB ONLY / NO MERGE / NO DEPLOY.**

This independent add-only follow-up to W23 #1201 and issue #1197
protects against a **specific presentation privacy disclosure** in the
synthetic checked-CSV route. It is *not installed* and is not a general
sensitive-data scanner or production privacy guarantee.

## Narrow implementation

`src/lightup/webapp/finding_exports_cookie_privacy_optin_w26.py`
defines an additional **explicitly opted-in** WSGI application factory
`create_app_with_checked_cookie_privacy(store, security)`. Its class
inherits the W23 opt-in tenant-selected renderer, trusted WSGI
session/portal admission and post-render durable revalidation. Only a
successful bounded CSV is inspected **before WSGI returns its bytes**.

The gate rejects a concrete `lightup_session=VALUE` cookie fragment,
including case and Unicode-NFKC-compatibility disguises, with an
all-or-nothing generic 400 response. It inspects a private normalized
copy; existing persisted finding text is not altered. Ordinary CSV
remains unchanged and retains legacy recognized-pattern redaction,
security headers and `no-store`. All other errors, 403 decisions and
anonymous redirects are delegated unchanged to the inherited guard.

The W26 helper **does not** run from existing `create_app`,
`create_app_with_exports`, `create_app_with_checked_exports`, CLI,
or any installed Nginx/Gunicorn service. It cannot certify arbitrary
credentials, free-text privacy, evidence authenticity, or authorization.

## Real disposable-SQLite WSGI tests

`tests/test_finding_export_checked_wsgi_cookie_privacy_w26.py`
contains actual authenticated WSGI/DomainStore tests, never real
cookies or customer values:

- authorized clean request returns redacted, read-only CSV with no-store;
- synthetic session cookie in title and remediation rejects entire CSV;
- NFKC-compatible fullwidth label rejects without source mutation;
- a late problematic finding blocks even earlier valid rows;
- foreign-tenant access refuses before `list_findings`;
- original W23 factory intentionally still permits the synthetic
  canary while new W26 factory rejects it;
- explicit construction only, no default-factory modification.

Run full offline suites on **this exact head**:

```sh
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_finding_export_checked_wsgi_cookie_privacy_w26.py' -v
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_*.py'
```

Run status belongs to its GitHub exact-head Actions logs; do not
count previous W23 hosted green as proof of this add-on.

## Release HOLD

Original CSV/render/tenant/auth/redaction owners must decide whether to
apply denial, privacy-by-design export field restrictions or other
reviewed secret classification in the canonical producer. Independent
security/privacy review and free-text redaction coverage are mandatory.
The installed ingress/session/revocation/Firefox review, registered
permanent exact-SHA self-hosted VPS CI, safe latest-main composition
and explicit release approval remain outstanding. No real targets,
scans, grants, client databases, credentials, remediation or retest.
