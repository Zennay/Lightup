# Scope authorization: WebSocket subprotocol is non-authoritative

**Status:** offline reference / HOLD. No production gate, network calls, upgrade handshake, grant issuance or target activity.

The client-controlled `Sec-WebSocket-Protocol` handshake header selects an application wire protocol; it is never an issuer signature, operator approval, capability lease, risk authorization, tenant identity, asset identity, grant revision, or revocation state. Header casing and arbitrary token contents must not change grant decisions. Even strings such as `approved`, `admin`, or `scope:all` confer no authority.

The standalone `tests/test_scope_ws_subprotocol_nonauthority_reference.py` uses an intentionally small frozen grant model and a mock call counter. It covers unapproved/revoked grants, identity/capability/revision mismatches, benign valid-grant controls, and no handler calls on denial.

Production acceptance belongs to the WebSocket gateway / trusted scope executor source owners: use live authenticated authorization from server-side storage, enforce revocation and exact capability/asset/tenant binding immediately before side effects, reject invalid scope with zero handler/evidence side effects, and run exact-head hosted plus permanent VPS CI and review. This reference deliberately does **not** assert those production guarantees.

No overlapping production paths have been modified. No target I/O, scanning, deployment, or merge permitted by this artifact.
