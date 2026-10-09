# Scope authorization: WebSocket subprotocol is non-authoritative

**Status:** offline reference / HOLD. No production gate, network calls, upgrade handshake, grant issuance or target activity.

The client-controlled `Sec-WebSocket-Protocol` handshake header selects an application wire protocol; it is never an issuer signature, operator approval, capability lease, risk authorization, tenant identity, asset identity, grant revision, or revocation state. Header casing and arbitrary token contents must not change grant decisions. Even strings such as `approved`, `admin`, or `scope:all` confer no authority.

The standalone `tests/test_scope_ws_subprotocol_nonauthority_reference.py` uses an intentionally small frozen grant model and a mock call counter. It covers unapproved/revoked grants, identity/capability/revision mismatches, malformed persisted grant field types, exact grant class identity (including subclass rejection), stale revision replay, immutable presentation input, benign valid-grant controls, and no handler calls on denial. Thirteen offline unittest methods total. A dedicated fixture-integrity regression asserts that newline, NUL, zero-width, line-separator and surrogate test values are actual single Unicode codepoints with expected categories, preventing false confidence from accidental double-escaped string literals. The new identity hardening rejects leading/trailing whitespace, Unicode control/format/surrogate/line-separator characters in matching stored and request identities, and string subclasses; benign Unicode exact matches remain valid while composed/decomposed variants remain distinct. This is an offline reference contract, not production enforcement.

Production acceptance belongs to the WebSocket gateway / trusted scope executor source owners: use live authenticated authorization from server-side storage, enforce revocation and exact capability/asset/tenant binding immediately before side effects, reject invalid scope with zero handler/evidence side effects, and run exact-head hosted plus permanent VPS CI and review. This reference deliberately does **not** assert those production guarantees.

No overlapping production paths have been modified. No target I/O, scanning, deployment, or merge permitted by this artifact.

## CI regression and exact fixture repair (2026-10-09)

Hosted preflight `37914098987` failed (Python 3.11 and 3.14 `Compile and unit suite`, 20 assertions) because literal double-backslash fixture strings did not represent Unicode control characters. The self-checking fixture test exposed this failure; importantly, the preceding green-looking deny assertions were not trustworthy. Commit `4a08402fe529c52b18cd7bee7158048f397ef980` replaces double escapes with Python single escape sequences; GitHub source re-fetch confirms single-escape spelling. Exact-head hosted preflight `37914223989` and permanent VPS `37914223974` must pass before marking fixed. The reference does not establish production enforcement.
