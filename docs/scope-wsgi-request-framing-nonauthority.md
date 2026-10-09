# WSGI request-framing non-authority — offline acceptance

**Status:** isolated test-only acceptance; **DRAFT/HOLD** for any deployment or real-target activation.  
**Base:** LightUp `main` `dd4072cdd1a2bc44a752ccbb7b1d0b6d56559da1` (2026-10-09).  
**Scope:** in-process WSGI request framing for privileged `POST /clients`; NOT an ingress, HTTP parser, TLS, authorization-token, or real-target proof.

## Threat boundary

A client-supplied `HTTP_CONTENT_LENGTH`, an ambiguous WSGI `CONTENT_LENGTH`, or a
`Transfer-Encoding` request hint must never promote a request to an approved
operator mutation. Bad framing must be rejected **before** reading the body and
before resolving the session. The platform already has a constrained form
parser; these tests pin its behavior **through the real web application and
temporary SQLite**, not just through a stand-alone helper.

A valid framing token is **necessary but insufficient**. A valid operator
session, CSRF, correct route and role still decide a write. Transport metadata
does not create consent or an authorization grant.

## Synthetic tests

Run with no socket, DNS, network, grants, or real targets:

```sh
PYTHONPATH=src python -m unittest discover -s tests \
  -p 'test_scope_wsgi_framing_nonauthority_20261009.py' -v
```

The suite runs in development and simulated-production HTTPS/trusted-loopback
contexts with temporary SQLite and checks:

1. Bad, missing, signed, padded, Unicode, oversized, and non-string WSGI
   lengths produce 400/413 before session lookup and stream reads.
2. Four nonempty `HTTP_TRANSFER_ENCODING` values with otherwise valid framing
   cannot reach authentication or mutation.
3. A contradictory client `HTTP_CONTENT_LENGTH: 0` cannot override a valid
   canonical WSGI body length, and cannot rescue an invalid WSGI length.
4. Correct framing without CSRF is denied; approved framing+session+CSRF can
   create a synthetic client in each environment.
5. Truncated body and duplicate/percent-aliased CSRF fields are denied before
   session lookup; neither the client database nor the existing operator
   session is mutated.
6. Valid canonical framing plus a real **client-admin** session/CSRF cannot
   access the operator-only creation route, even with synthetic forwarded
   user/role/length headers. Both operator and client sessions survive.
7. Denied framing leaves both the authenticated session and the client count
   unchanged. Security response headers retain `Cache-Control: no-store`.

## Out-of-scope / limits

- **No installed Gunicorn/Nginx parsing proof.** Real proxy behavior for
  duplicate/conflicting `Content-Length` / `Transfer-Encoding` must be
  separately exercised with **isolated, synthetic, owned ingress fixtures**,
  not production targets or a production proxy reload.
- `CONTENT_LENGTH` is a WSGI server-provided value; `HTTP_CONTENT_LENGTH`
  is only a synthetic untrusted hint in this test. No claim is made that every
  ingress exposes or forwards that synthetic field.
- The suite does not change `src/lightup/webapp/app.py`, `forms.py`,
  `security.py`, the proxy, the tool executor, policy, or any live grants.
  It does not replace concurrent owners #182, #202, #107, #1155, #1156,
  #1157, or #1159.

## Promotion gate

Require exact-current-head hosted Python 3.11/3.14 and **canonical permanent
VPS** checks to succeed, plus independent review of paths and owner
coordination. A passing offline suite is *not* evidence that a deployed ingress
is safe from HTTP request smuggling, nor that real-target authorization is live.
Keep all active target interactions disabled.
