# W23 — deny-only post-render session integrity for opt-in checked CSV

**Scope:** synthetic offline WSGI / disposable SQLite only. M3/M7 PLAN/LAB.
**Status:** DRAFT/HOLD — not a production feature, not an authorization grant,
not a claim of actual exploitability, and not approved for merge/deploy.

## Observed opt-in seam and narrow contract

The optional checked CSV handler in draft #1198 re-resolves its persisted
session **after** bounded tenant record selection and CSV serialization. The
original branch compared only `live[0]` with the first session identity.
Malformed non-sequence/empty responses can cause an uncaught exception rather
than deny; a retained principal paired with a changed CSRF value could
still release CSV. This is a defensive synthetic trust-boundary hardening
opportunity, **not evidence of an installed service vulnerability**.

On this child branch:
- Require an exact built-in two-item tuple from the second
  `DomainStore.session_context` lookup.
- Require a canonical `AccessContext` identity matching the dispatch-time
  principal; require an exact nonempty CSRF string matching dispatch time.
- Reject malformed/rotated session state with generic **403**, before returning
  any CSV bytes; preserve `no-store`, `nosniff`, tenant boundaries and
  unchanged durable findings.
- Keep original login/route, default export/CLI, ingress, source-owner
  branches and canonical `main` untouched.

## Offline regression

`tests/test_finding_export_checked_wsgi_postrender_integrity_w23.py` uses
the existing W11 **real WSGI** application and disposable persisted-domain
fixtures. It permits a canonical unchanged persisted session and denies 13
malformed/replaced session shapes, including missing container/CSRF, wrong
types, forged list/mapping, and a rotated CSRF token. Each request
demonstrates unchanged finding rows, non-CSV denial and no finding/secret
release. The second session return is synthetically replaced **after** genuine
first-pass authentication; it does not claim that such malformed outputs
can be caused by remote users. A separate real durable-SQLite WSGI test
rotates the session's stored CSRF value during checked rendering and asserts
the in-flight export is denied with no CSV or finding mutation. This proves
the narrow CSRF revalidation behavior using a real persisted session.

Run against this stacked branch with:

```sh
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_finding_export_checked_wsgi_postrender_integrity_w23.py' -v
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_*.py'
```

The test commands are instructions for the registered CI/test owner; do not
count unexecuted commands as proof. Review exact branch HEAD and completed
runner job logs before changing any acceptance status.

## Remaining gates (not waived)

Original export/domain/web/session owner review; independent privacy and
security review; installed Nginx → Gunicorn/Firefox ingress and concurrency
review; exact-final-head **permanent self-hosted VPS CI** (hosted preflight
alone is insufficient); safe composition on latest main; release authorization.
No real clients, targets, scans, external models, live evidence, remediation,
verification, merge or deploy.
