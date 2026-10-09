# WSGI HTTP method token case sensitivity — RED acceptance contract

**Status:** production defect candidate; intentionally unresolved. **Activation:** plan/lab-only, no real targets.

HTTP request methods are case-sensitive tokens (RFC 9110 §9.1). The actual WSGI method, after trusted server parsing, must be matched *exactly* against LightUp's supported route methods. Untrusted or noncanonical `post`, `PoSt` or `get` must not be made into `POST` or `GET` by an application-level `.upper()` call. The current `LightUpWebApp.__call__` uses `environ.get("REQUEST_METHOD", "GET").upper()` and therefore collapses different method tokens.

## Direct production evidence from source

- `src/lightup/webapp/app.py` computes `method = ... .upper()`, passes this value to `read_form`, then to `_dispatch`, whose GET/POST routes are otherwise exact.
- `src/lightup/webapp/security.py` similarly checks `environ.get("REQUEST_METHOD", "GET").upper() == "POST"` for origin checks. Correcting one layer must not make another layer accept a token that route admission should reject.
- A valid operator session plus a valid CSRF token is an intentionally positive fixture. It demonstrates that wrong-case methods may reach authenticated mutation or session revocation even though no canonical method was sent.
- This does **not** assert that a real proxy accepts such a wire method; real end-to-end ingress testing is separate.

## Real-WSGI regression matrix

| Input | Path | Expected after source fix | Current canary |
| --- | --- | --- | --- |
| `post` | `/clients` | no mutation; non-success | expectedFailure |
| `PoSt` | `/clients` | no mutation; non-success | expectedFailure |
| `post` | `/logout` | original session remains valid | expectedFailure |
| `get` | `/` | no dashboard disclosure | expectedFailure |
| `POST` | `/clients` | 303 and one fixture client created | positive |
| `GET` | `/` | 200 | positive |
| `PATCH` | `/clients` | 404, no client created | negative |

A source-owner correction may return 403/404/405 for unsupported case variants; acceptance requires **no effects** and **no sensitive reads**, not a specific denial status. The `expectedFailure` canaries currently pin 404 to detect the existing defect; after a fix, the owner should replace those assertions with an explicit accepted denial-status set and remove `expectedFailure`. Tests are standard-library unittest, run with:

`PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_wsgi_method_case_sensitivity_20261009.py' -v`

## Ownership and release hold

Changes in this PR are **only** new tests and this note. Do not edit existing `src/lightup/webapp/app.py` (authorization web-input owner PR #182), `src/lightup/webapp/security.py` (development peer-trust owner PR #202), or method-override regression owner PR #1153. Handoff production correction to the existing webapp owners, rather than racing their branch.

Offline passing tests with expected failures are **not proof** of a hardened production boundary. Promote only after real-source fix, real WSGI regressions that all truly pass without expectedFailure, same-head hosted AND permanent VPS CI success, and independent review. No HTTP listeners, grants, external targets, scans, deployment or new active capabilities in this branch.
